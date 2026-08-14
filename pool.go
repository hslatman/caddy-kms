// Copyright 2026 Herman Slatman
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddykms

import (
	"context"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"go.step.sm/crypto/kms"
	"go.step.sm/crypto/kms/apiv1"
)

// openFunc opens a KMS. It exists so that tests can supply a fake instead of
// reaching real hardware; production always uses kms.New.
type openFunc func(context.Context, apiv1.Options) (apiv1.KeyManager, error)

// defaultPool is the process-wide KeyManager pool. Tests replace it with a
// pool over a fake; see withPool in pool_test.go.
var defaultPool = newPool(kms.New)

// pool shares KeyManager instances between everything configured against the
// same KMS, and closes each one when its last user releases it.
//
// Sharing matters for more than efficiency. Signing with a TPM opens the
// device, loads the key, signs and closes again, all serialized by a mutex
// held per TPM instance. Two instances for the same device would hold two
// different mutexes and contend at the device instead.
type pool struct {
	open  openFunc
	usage *caddy.UsagePool
}

// newPool returns a pool that opens key managers with open.
func newPool(open openFunc) *pool {
	return &pool{open: open, usage: caddy.NewUsagePool()}
}

// acquire returns the KeyManager for opts, opening it if this is the first
// use. Every successful acquire must be paired with exactly one release.
func (p *pool) acquire(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
	value, _, err := p.usage.LoadOrNew(opts, func() (caddy.Destructor, error) {
		km, err := p.open(ctx, opts)
		if err != nil {
			return nil, err
		}
		return pooledKeyManager{km}, nil
	})
	if err != nil {
		return nil, fmt.Errorf("opening kms %q: %w", opts.Type, err)
	}
	return value.(pooledKeyManager).KeyManager, nil
}

// release gives up one use of the KeyManager for opts, closing it if this was
// the last one.
func (p *pool) release(opts apiv1.Options) error {
	_, err := p.usage.Delete(opts)
	return err
}

// pooledKeyManager adapts a KeyManager to caddy.Destructor so that the usage
// pool can close it.
type pooledKeyManager struct {
	apiv1.KeyManager
}

// Destruct implements caddy.Destructor.
func (p pooledKeyManager) Destruct() error {
	return p.KeyManager.Close()
}

// Interface guard
var _ caddy.Destructor = pooledKeyManager{}
