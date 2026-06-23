//go:build linux

// In-process netlink-based replacement for the iptables-restore
// shellouts. Background:
//
// Empirically, iptables-nft v1.8.11 on Linux 6.17 returns EPERM on
// NFT_MSG_GETGEN when called from a cap_net_admin file-cap'd
// non-root process more than once in close temporal proximity from
// SEPARATE processes. The first invocation succeeds; subsequent
// ones fail until something resets (kernel state? per-uid resource
// counter?). The kernel returns EPERM, iptables surfaces it as the
// misleading "you must be root".
//
// We sidestep the issue by holding a single netlink connection in
// the veil-bridge process and sending all rule changes through
// that one socket. nft transactions inside one connection don't
// trigger the cross-process EPERM behavior.
//
// Operations supported (matches what add-nat / remove-nat used to
// shell to iptables for):
//
//	filter / FORWARD: -I 1 -s SUBNET -j ACCEPT
//	filter / FORWARD: -I 1 -d SUBNET -j ACCEPT
//	nat    / POSTROUTING: -A -s SUBNET -o IFACE -j MASQUERADE
//	  + corresponding -D variants for cleanup.
//
// Tables (filter, nat) and chains (FORWARD, POSTROUTING) are
// expected to already exist — they're created at boot by Linux's
// nftables init or by the first iptables call. We never CREATE the
// table/chain ourselves; we only append/insert/delete rules.

package main

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// nftAddNAT installs the FORWARD ACCEPT pair + POSTROUTING MASQUERADE
// rule for the given subnet/iface. Idempotent: deletes any existing
// matching rules first so re-runs collapse cleanly.
func nftAddNAT(subnet *net.IPNet, iface string) error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("netlink connect: %w", err)
	}
	defer c.CloseLasting()

	// Delete pass: drain stale rules. We list every rule in the
	// target chains and delete the ones that match our spec.
	if err := nftDeleteMatching(c, subnet, iface); err != nil {
		return fmt.Errorf("delete pass: %w", err)
	}

	// Insert + append the fresh rules. All happens in one
	// transaction (one Flush call commits everything).
	filterTable := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: "filter"}
	natTable := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: "nat"}
	forward := &nftables.Chain{Name: "FORWARD", Table: filterTable}
	postrouting := &nftables.Chain{Name: "POSTROUTING", Table: natTable}

	c.InsertRule(&nftables.Rule{
		Table: filterTable,
		Chain: forward,
		Exprs: append(matchSourceCIDR(subnet),
			&expr.Verdict{Kind: expr.VerdictAccept},
		),
	})
	c.InsertRule(&nftables.Rule{
		Table: filterTable,
		Chain: forward,
		Exprs: append(matchDestCIDR(subnet),
			&expr.Verdict{Kind: expr.VerdictAccept},
		),
	})
	c.AddRule(&nftables.Rule{
		Table: natTable,
		Chain: postrouting,
		Exprs: append(matchSourceCIDR(subnet),
			matchOutIface(iface),
			&expr.Masq{},
		),
	})
	if err := c.Flush(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// nftRemoveNAT removes any rules matching the subnet/iface.
// Idempotent: succeeds even when no rules exist.
func nftRemoveNAT(subnet *net.IPNet, iface string) error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("netlink connect: %w", err)
	}
	defer c.CloseLasting()
	return nftDeleteMatching(c, subnet, iface)
}

func nftDeleteMatching(c *nftables.Conn, subnet *net.IPNet, iface string) error {
	filterTable := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: "filter"}
	natTable := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: "nat"}
	forward := &nftables.Chain{Name: "FORWARD", Table: filterTable}
	postrouting := &nftables.Chain{Name: "POSTROUTING", Table: natTable}

	wantSrc := matchSourceCIDR(subnet)
	wantDst := matchDestCIDR(subnet)
	wantSrcOut := append(matchSourceCIDR(subnet), matchOutIface(iface))

	if rules, err := c.GetRules(filterTable, forward); err == nil {
		for _, r := range rules {
			if rulePrefixMatches(r.Exprs, wantSrc) && hasAccept(r.Exprs) {
				_ = c.DelRule(r)
				continue
			}
			if rulePrefixMatches(r.Exprs, wantDst) && hasAccept(r.Exprs) {
				_ = c.DelRule(r)
			}
		}
	}
	if rules, err := c.GetRules(natTable, postrouting); err == nil {
		for _, r := range rules {
			if rulePrefixMatches(r.Exprs, wantSrcOut) && hasMasq(r.Exprs) {
				_ = c.DelRule(r)
			}
		}
	}
	return c.Flush()
}

// matchSourceCIDR builds the expression sequence for `-s CIDR`.
// Loads bytes from the IP source address field of the packet,
// AND-masks them with the subnet mask, and compares to the network
// address.
func matchSourceCIDR(n *net.IPNet) []expr.Any {
	return cidrMatchExprs(n, /*offset*/ 12)
}

// matchDestCIDR builds the expression sequence for `-d CIDR`.
func matchDestCIDR(n *net.IPNet) []expr.Any {
	return cidrMatchExprs(n, /*offset*/ 16)
}

func cidrMatchExprs(n *net.IPNet, ipHeaderOffset uint32) []expr.Any {
	ip := n.IP.To4()
	mask := net.IP(n.Mask).To4()
	xored := make([]byte, 4)
	for i := range xored {
		xored[i] = ip[i] & mask[i]
	}
	return []expr.Any{
		// payload load 4b @ network header + offset (saddr/daddr)
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       ipHeaderOffset,
			Len:          4,
		},
		// AND with mask
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           mask,
			Xor:            []byte{0, 0, 0, 0},
		},
		// CMP eq subnet network address
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     xored,
		},
	}
}

// matchOutIface builds the expression for `-o IFACE`. It compares
// the meta oifname against the literal interface name.
func matchOutIface(iface string) expr.Any {
	return &expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1}
}

// rulePrefixMatches checks whether r's expression list starts with
// the same expressions as want. We walk both lists and compare
// "shape + key bytes", which is enough to distinguish our rules
// from unrelated ones (Docker's, for instance).
func rulePrefixMatches(have []expr.Any, want []expr.Any) bool {
	if len(have) < len(want) {
		return false
	}
	for i, w := range want {
		if !exprEqual(have[i], w) {
			return false
		}
	}
	return true
}

// exprEqual compares two expression entries by type and the most
// distinctive field (mask/data/key). Approximate but good enough
// for our specific rules: payload offset+len, bitwise mask, cmp
// data, meta key.
func exprEqual(a, b expr.Any) bool {
	switch ax := a.(type) {
	case *expr.Payload:
		bx, ok := b.(*expr.Payload)
		return ok && ax.Base == bx.Base && ax.Offset == bx.Offset && ax.Len == bx.Len
	case *expr.Bitwise:
		bx, ok := b.(*expr.Bitwise)
		return ok && byteSliceEq(ax.Mask, bx.Mask)
	case *expr.Cmp:
		bx, ok := b.(*expr.Cmp)
		return ok && ax.Op == bx.Op && byteSliceEq(ax.Data, bx.Data)
	case *expr.Meta:
		bx, ok := b.(*expr.Meta)
		return ok && ax.Key == bx.Key
	}
	return false
}

func byteSliceEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func hasAccept(exprs []expr.Any) bool {
	for _, e := range exprs {
		if v, ok := e.(*expr.Verdict); ok && v.Kind == expr.VerdictAccept {
			return true
		}
	}
	return false
}

func hasMasq(exprs []expr.Any) bool {
	for _, e := range exprs {
		if _, ok := e.(*expr.Masq); ok {
			return true
		}
	}
	return false
}

// keep these imports referenced even if a future cleanup drops one;
// avoids "imported and not used" errors during refactors.
var _ = unix.AF_INET
var _ = binaryutil.BigEndian
var _ = binary.BigEndian
