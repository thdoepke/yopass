package main

import (
	"testing"

	"github.com/jhaals/yopass/pkg/server"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestSetupLicenseTestBypass(t *testing.T) {
	t.Setenv("YOPASS_TEST_LICENSE_BYPASS", "true")
	for _, key := range []string{"", "invalid-key"} {
		t.Run(key, func(t *testing.T) {
			setFlag(t, "license-key", key)
			registry := prometheus.NewRegistry()
			core, logs := observer.New(zap.DebugLevel)
			status := setupLicense(zap.New(core), registry)
			require.True(t, status.CurrentlyValid(), "explicit testing bypass must enable runtime feature gates")
			assert.False(t, status.Valid)
			assert.True(t, status.ExpiresAt.IsZero())
			require.Len(t, logs.All(), 1)
			assert.Equal(t, zap.WarnLevel, logs.All()[0].Level)
			assert.Empty(t, logs.FilterMessage("license key verified").All())
			metrics, err := registry.Gather()
			require.NoError(t, err)
			for _, metric := range metrics {
				assert.NotEqual(t, "yopass_license_days_until_expiry", metric.GetName(), "test mode must not publish fictitious expiry")
			}
		})
	}
}

func TestSetupLicenseBypassOff(t *testing.T) {
	t.Setenv("YOPASS_TEST_LICENSE_BYPASS", "false")
	setFlag(t, "license-key", "")
	status := setupLicense(zap.NewNop(), prometheus.NewRegistry())
	assert.Equal(t, server.LicenseStatus{}, status)
	setFlag(t, "audit-log", true)
	require.ErrorContains(t, validateFlags(status, zap.NewNop()), "requires a valid license key")
}

func TestTestingBypassStartupFlagsAndFileSize(t *testing.T) {
	t.Setenv("YOPASS_TEST_LICENSE_BYPASS", "true")
	setFlag(t, "license-key", "")
	status := setupLicense(zap.NewNop(), prometheus.NewRegistry())
	setFlag(t, "oidc-issuer", "https://issuer.example")
	setFlag(t, "require-auth", true)
	setFlag(t, "audit-log", true)
	setFlag(t, "webhook-url", "https://hooks.example/events")
	require.NoError(t, validateFlags(status, zap.NewNop()))
	setFlag(t, "max-file-size", "8MB")
	size, err := resolveMaxFileSize(zap.NewNop(), status.CurrentlyValid())
	require.NoError(t, err)
	assert.Equal(t, int64(8*1024*1024), size)
	setFlag(t, "oidc-issuer", "")
	require.ErrorContains(t, validateFlags(status, zap.NewNop()), "OIDC is not configured")
	setFlag(t, "require-auth", false)
	setFlag(t, "oidc-session-key", "bad-key")
	require.ErrorContains(t, validateFlags(status, zap.NewNop()), "128 hex characters")
	setFlag(t, "oidc-session-key", "")
	setFlag(t, "theme-custom-light", `{"--color-primary":"red;display:none"}`)
	require.ErrorContains(t, validateFlags(status, zap.NewNop()), "invalid CSS variable")
	setFlag(t, "theme-custom-light", "")
	setFlag(t, "max-file-size", "invalid")
	_, err = resolveMaxFileSize(zap.NewNop(), status.CurrentlyValid())
	require.Error(t, err, "test bypass must not bypass size parsing")
}

func TestTestingBypassStillInitializesConfiguredOIDC(t *testing.T) {
	t.Setenv("YOPASS_TEST_LICENSE_BYPASS", "true")
	setFlag(t, "license-key", "")
	status := setupLicense(zap.NewNop(), prometheus.NewRegistry())
	setFlag(t, "oidc-issuer", "https://issuer.example")
	setFlag(t, "oidc-client-id", "")
	setFlag(t, "oidc-redirect-url", "")
	_, _, err := setupOIDC(zap.NewNop(), status)
	require.Error(t, err, "must attempt OIDC setup and reject missing required config, not silently skip auth")
}
