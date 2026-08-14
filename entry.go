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
	"errors"
	"fmt"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.step.sm/crypto/kms/apiv1"
)

// errPathNeedsCertificate is returned for a key URI that identifies the key by
// path rather than by name. The TPM KMS can sign with such a key but cannot
// look up a certificate for it, so one has to be configured explicitly.
var errPathNeedsCertificate = errors.New(`a key URI using "path=" cannot supply a certificate, ` +
	`so "certificate" must be set to a PEM file path`)

// KMSOptions holds KMS backend options that are awkward to express in a key
// URI. Anything the backend accepts as a URI parameter can go in the URI
// instead.
type KMSOptions struct {
	// Pin unlocks the KMS, where the backend needs one.
	Pin string `json:"pin,omitempty"`

	// StorageDirectory is where the TPM KMS keeps its serialized objects. It
	// must match the directory used by whichever tool created the key. When
	// unset, the backend picks a default relative to the working directory,
	// which is rarely what a service wants.
	StorageDirectory string `json:"storage_directory,omitempty"`
}

// Entry describes one certificate together with the KMS-resident private key
// that belongs to it.
type Entry struct {
	// Key is a KMS URI identifying the private key. Its scheme selects the
	// backend, for example "tpmkms:name=caddy-tls" or
	// "softkms:/etc/caddy/tls.key". Backend parameters carried by the URI,
	// such as "device=" for the TPM, are honoured.
	Key string `json:"key"`

	// Certificate is the path to a PEM file holding the leaf certificate,
	// optionally followed by intermediates in issuer order. When empty, the
	// chain is loaded from the KMS, which only some backends support.
	Certificate string `json:"certificate,omitempty"`

	// KMS holds backend options that do not belong in the key URI.
	KMS *KMSOptions `json:"kms,omitempty"`

	// Tags are arbitrary values associated with the certificate, so that a
	// connection policy can select it explicitly. Only the certificate loader
	// uses them; the certificate manager ignores them.
	Tags []string `json:"tags,omitempty"`
}

// replace returns a copy of e with Caddy placeholders expanded.
func (e Entry) replace(repl *caddy.Replacer) Entry {
	out := Entry{
		Key:         repl.ReplaceKnown(e.Key, ""),
		Certificate: repl.ReplaceKnown(e.Certificate, ""),
	}
	if e.KMS != nil {
		out.KMS = &KMSOptions{
			Pin:              repl.ReplaceKnown(e.KMS.Pin, ""),
			StorageDirectory: repl.ReplaceKnown(e.KMS.StorageDirectory, ""),
		}
	}
	if e.Tags != nil {
		out.Tags = make([]string, len(e.Tags))
		for i, tag := range e.Tags {
			out.Tags[i] = repl.ReplaceKnown(tag, "")
		}
	}
	return out
}

// options derives the KMS options for e. The key URI does double duty: it
// selects the backend and carries its parameters, and it also names the key.
// Backends ignore the URI parameters they do not recognise, which is what
// makes a single field workable.
func (e Entry) options() (apiv1.Options, error) {
	if e.Key == "" {
		return apiv1.Options{}, errors.New("key is required")
	}
	typ, err := apiv1.TypeOf(e.Key)
	if err != nil {
		return apiv1.Options{}, fmt.Errorf("parsing key %q: %w", e.Key, err)
	}
	opts := apiv1.Options{Type: typ, URI: e.Key}
	if e.KMS != nil {
		opts.Pin = e.KMS.Pin
		opts.StorageDirectory = e.KMS.StorageDirectory
	}
	return opts, nil
}

// validate reports configuration errors that can be found without contacting
// the KMS.
func (e Entry) validate() error {
	if _, err := e.options(); err != nil {
		return err
	}
	if e.Certificate == "" && strings.Contains(e.Key, "path=") {
		return errPathNeedsCertificate
	}
	return nil
}

// kmsOptions returns e's KMS options, allocating them if needed.
func (e *Entry) kmsOptions() *KMSOptions {
	if e.KMS == nil {
		e.KMS = new(KMSOptions)
	}
	return e.KMS
}

// unmarshalOption consumes one option from d if it is one Entry recognises,
// and reports whether it did. Callers that accept additional options — the
// certificate manager accepts "ttl" — use this to share the common ones.
func (e *Entry) unmarshalOption(d *caddyfile.Dispenser) (bool, error) {
	switch d.Val() {
	case "certificate":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		e.Certificate = d.Val()
	case "pin":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		e.kmsOptions().Pin = d.Val()
	case "storage_directory":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		e.kmsOptions().StorageDirectory = d.Val()
	case "tags":
		tags := d.RemainingArgs()
		if len(tags) == 0 {
			return true, d.ArgErr()
		}
		e.Tags = append(e.Tags, tags...)
	default:
		return false, nil
	}
	return true, nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler, parsing:
//
//	kms_certificate <key-uri> {
//	    certificate       <path>
//	    pin               <pin>
//	    storage_directory <path>
//	    tags              <tags...>
//	}
func (e *Entry) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume the directive name
	if !d.NextArg() {
		return d.ArgErr()
	}
	e.Key = d.Val()
	if d.NextArg() {
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		known, err := e.unmarshalOption(d)
		if err != nil {
			return err
		}
		if !known {
			return d.Errf("unrecognized subdirective %q", d.Val())
		}
	}
	return nil
}

// Interface guard
var _ caddyfile.Unmarshaler = (*Entry)(nil)
