package caddykms

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"

	// The http server type must be registered for the Caddyfile adapter to
	// run, and the tls app must be registered so the loader module resolves.
	_ "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/caddytls"
)

func TestAdaptKMSCertificate(t *testing.T) {
	caddytest.AssertAdapt(t, `
		example.com

		kms_certificate tpmkms:name=caddy-tls {
			certificate       /etc/caddy/tls.crt
			storage_directory /etc/step/tpm
			tags              internal
		}
	`, "caddyfile", `{
	"apps": {
		"http": {
			"servers": {
				"srv0": {
					"listen": [
						":443"
					],
					"routes": [
						{
							"match": [
								{
									"host": [
										"example.com"
									]
								}
							],
							"terminal": true
						}
					]
				}
			}
		},
		"tls": {
			"certificates": {
				"load_kms": [
					{
						"key": "tpmkms:name=caddy-tls",
						"certificate": "/etc/caddy/tls.crt",
						"kms": {
							"storage_directory": "/etc/step/tpm"
						},
						"tags": [
							"internal"
						]
					}
				]
			}
		}
	}
}`)
}

func TestAdaptMultipleKMSCertificatesCombineIntoOneLoader(t *testing.T) {
	// Each occurrence emits its own tls.cert_loader value; buildTLSApp
	// concatenates them into a single load_kms array. If Loader were not a
	// slice type, or were passed as a pointer, the array would be missing
	// entirely and this test would catch it.
	caddytest.AssertAdapt(t, `
		example.com

		kms_certificate tpmkms:name=one
		kms_certificate tpmkms:name=two
	`, "caddyfile", `{
	"apps": {
		"http": {
			"servers": {
				"srv0": {
					"listen": [
						":443"
					],
					"routes": [
						{
							"match": [
								{
									"host": [
										"example.com"
									]
								}
							],
							"terminal": true
						}
					]
				}
			}
		},
		"tls": {
			"certificates": {
				"load_kms": [
					{
						"key": "tpmkms:name=one"
					},
					{
						"key": "tpmkms:name=two"
					}
				]
			}
		}
	}
}`)
}
