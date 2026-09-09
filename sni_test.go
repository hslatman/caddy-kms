package caddykms

import (
	"crypto/x509"
	"net"
	"testing"
)

func TestMatchesSNI(t *testing.T) {
	leaf := &x509.Certificate{
		DNSNames:    []string{"example.com", "*.apps.example.com"},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.10")},
	}

	tests := []struct {
		name       string
		serverName string
		want       bool
	}{
		{"exact match", "example.com", true},
		{"case insensitive", "EXAMPLE.COM", true},
		{"trailing dot", "example.com.", true},
		{"no sni at all", "", true},
		{"different host", "other.com", false},
		{"subdomain of a non-wildcard san", "www.example.com", false},
		{"wildcard one label", "api.apps.example.com", true},
		{"wildcard two labels", "a.b.apps.example.com", false},
		{"wildcard bare parent", "apps.example.com", false},
		{"matching ip", "192.0.2.10", true},
		{"other ip", "192.0.2.11", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesSNI(leaf, tc.serverName); got != tc.want {
				t.Errorf("matchesSNI(%q) = %v, want %v", tc.serverName, got, tc.want)
			}
		})
	}
}
