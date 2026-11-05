package main

import (
	"testing"

	"go.uber.org/zap"
)

func TestSetupLicenseTestBypass(t *testing.T) {
	t.Setenv("YOPASS_TEST_LICENSE_BYPASS", "true")
	t.Setenv("LICENSE_KEY", "not-a-license")
	status := setupLicense(zap.NewNop())
	if !status.CurrentlyValid() {
		t.Fatal("explicit testing bypass must enable Lambda runtime feature gates")
	}
	if status.Valid || !status.ExpiresAt.IsZero() || status.Licensee != "" {
		t.Fatalf("testing mode must not fabricate a verified license: %+v", status)
	}
}

func TestSetupLicenseBypassOff(t *testing.T) {
	t.Setenv("LICENSE_KEY", "")
	for _, value := range []string{"", "false", "TRUE", "1", "true "} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("YOPASS_TEST_LICENSE_BYPASS", value)
			if setupLicense(zap.NewNop()).CurrentlyValid() {
				t.Fatalf("Lambda testing bypass enabled for %q", value)
			}
		})
	}
}
