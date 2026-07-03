//go:build !linux

package main

import (
	"errors"
	"net"
)

// Stubs so the package compiles under cross-builds. veil-bridge is
// Linux-only in practice; these never get called.

func nftAddNAT(_ *net.IPNet, _ string) error {
	return errors.New("nft: linux only")
}

func nftRemoveNAT(_ *net.IPNet, _ string) error {
	return errors.New("nft: linux only")
}
