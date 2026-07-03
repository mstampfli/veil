// Package direct is a no-tunnel backend: traffic leaves the namespace directly.
package direct

import (
	"context"

	"github.com/mstampfli/veil/internal/backends"
	"github.com/mstampfli/veil/internal/profile"
)

type Backend struct{}

func init() {
	backends.Register(profile.BackendDirect, func(_ profile.Backend) (backends.Backend, error) {
		return &Backend{}, nil
	})
}

func (b *Backend) Kind() profile.BackendKind { return profile.BackendDirect }

func (b *Backend) Start(_ context.Context, prev *backends.Steering) (*backends.Steering, error) {
	if prev != nil {
		return prev, nil
	}
	return &backends.Steering{}, nil
}

func (b *Backend) Stop() error    { return nil }
func (b *Backend) Status() string { return "direct" }
