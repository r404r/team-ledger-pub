package main

import (
	"strings"
	"testing"
)

func TestGenericActivationRejectsDatabaseCoupledDomains(t *testing.T) {
	for _, domain := range []string{"staff_code_lookup", "bonus_payment_lookup", "identity_subject_lookup", "local_username_lookup", "csrf_token"} {
		t.Run(domain, func(t *testing.T) {
			err := lifecycle("activate", []string{"-socket", "/synthetic/keyd.sock", "-domain", domain, "-manifest-file", "/synthetic/manifest"})
			if err == nil || !strings.Contains(err.Error(), "requires") {
				t.Fatal("generic activation reached keyd for a database-coupled domain", err)
			}
		})
	}
}

func TestPersistentMACDomainsRejectGenericRotation(t *testing.T) {
	for _, action := range []string{"stage", "activate"} {
		for _, domain := range []string{"command_receipt", "assessment_generation", "local_password_pepper"} {
			t.Run(action+"/"+domain, func(t *testing.T) {
				args := []string{"-socket", "/synthetic/keyd.sock", "-domain", domain, "-manifest-file", "/synthetic/manifest"}
				if action == "stage" {
					args = append(args, "-target-key-id", "00000000-0000-7000-8000-000000000001", "-target-version", "2")
				}
				if err := lifecycle(action, args); err == nil {
					t.Fatal("persistent MAC domain reached generic keyd lifecycle")
				}
			})
		}
	}
}
