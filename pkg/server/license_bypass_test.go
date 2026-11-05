package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jhaals/yopass/pkg/yopass"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestResolveLicenseExactTestingOptIn(t *testing.T) {
	for _, value := range []string{"", "false", "1", "TRUE", "True", " true", "true ", "yes", "true"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("YOPASS_TEST_LICENSE_BYPASS", value)
			core, logs := observer.New(zap.DebugLevel)
			status := ResolveLicense("", zap.New(core))
			assert.Equal(t, value == "true", status.CurrentlyValid())
			assert.False(t, status.Valid, "test mode is not a verified key")
			assert.False(t, status.Expired())
			assert.True(t, status.ExpiresAt.IsZero())
			assert.Empty(t, status.Licensee)
			assert.Zero(t, status.DaysUntilExpiry())
			if value == "true" {
				require.Len(t, logs.All(), 1)
				assert.Equal(t, zap.WarnLevel, logs.All()[0].Level)
				assert.Contains(t, logs.All()[0].Message, "TESTING ONLY")
				assert.Contains(t, logs.All()[0].Message, "not a verified commercial license")
				// A testing status has no expiry to monitor; even a zero interval must
				// return before constructing a ticker or emitting expiry warnings.
				StartLicenseExpiryMonitor(context.Background(), status, 0, zap.New(core))
				assert.Len(t, logs.All(), 1)
			} else {
				assert.Empty(t, logs.All())
			}
		})
	}
	t.Setenv("YOPASS_TEST_LICENSE_BYPASS", "")
	require.NoError(t, os.Unsetenv("YOPASS_TEST_LICENSE_BYPASS"))
	assert.Equal(t, VerifyLicense("invalid", zap.NewNop()), ResolveLicense("invalid", zap.NewNop()))
	assert.False(t, ResolveLicense("", zap.NewNop()).CurrentlyValid())
}

func TestTestingOverrideIsResolvedOnlyAtSetup(t *testing.T) {
	t.Setenv("YOPASS_TEST_LICENSE_BYPASS", "true")
	status := ResolveLicense("invalid", zap.NewNop())
	assert.True(t, status.CurrentlyValid(), "test override takes precedence over a key")
	assert.False(t, VerifyLicense("invalid", zap.NewNop()).CurrentlyValid(), "raw verification must remain strict")
	assert.False(t, (LicenseStatus{}).CurrentlyValid(), "library instances must not read ambient env")
	t.Setenv("YOPASS_TEST_LICENSE_BYPASS", "false")
	assert.True(t, status.CurrentlyValid(), "resolved status is stable during this process")
	assert.False(t, ResolveLicense("", zap.NewNop()).CurrentlyValid(), "new setup follows current env")
}

func TestTestingBypassConfigAndEndpoints(t *testing.T) {
	t.Setenv("YOPASS_TEST_LICENSE_BYPASS", "true")
	y := newRequestTestServer(t, newMemoryDB(), false)
	y.License = ResolveLicense("", zap.NewNop())
	y.MaxFileSize = 4 * UnlicensedMaxFileSize
	y.AppName, y.HideAppName, y.LogoURL = "Test instance", true, "https://example.test/logo.svg"
	y.ThemeLight, y.ThemeDark = "cupcake", "night"
	y.ThemeCustomLight = `{"--color-primary":"#112233"}`
	y.ThemeCustomDark = `{"--color-primary":"#445566"}`
	handler := y.HTTPHandler()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/config", nil))
	require.Equal(t, http.StatusOK, w.Code)
	var config map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &config))
	for key, want := range map[string]interface{}{
		"APP_NAME": y.AppName, "HIDE_APP_NAME": true, "LOGO_URL": y.LogoURL,
		"THEME_LIGHT": y.ThemeLight, "THEME_DARK": y.ThemeDark,
		"SECRET_REQUESTS": true, "READ_RECEIPTS": true, "OIDC_ENABLED": false,
		"REQUIRE_AUTH": false, "MAX_FILE_SIZE": FormatSize(y.MaxFileSize),
	} {
		assert.Equal(t, want, config[key], key)
	}
	assert.Equal(t, map[string]interface{}{"--color-primary": "#112233"}, config["THEME_CUSTOM_LIGHT"])
	assert.Equal(t, map[string]interface{}{"--color-primary": "#445566"}, config["THEME_CUSTOM_DARK"])
	createRequest(t, handler, testPublicKey(t), "test bypass", 3600)
	encrypted, err := yopass.Encrypt(strings.NewReader("testing"), "key")
	require.NoError(t, err)
	body, err := json.Marshal(map[string]interface{}{"message": encrypted, "expiration": 3600, "receipt": true})
	require.NoError(t, err)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("POST", "/create/secret", bytes.NewReader(body)))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var result map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.NotEmpty(t, result["receipt_token"])
	// The runtime upload gate, not just the advertised config, allows >1MB.
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, streamUploadRequest(pgpBody(strings.Repeat("x", int(UnlicensedMaxFileSize)+1)), "3600", "false", "test.bin"))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestTestingBypassHonorsDisabledFeatures(t *testing.T) {
	t.Setenv("YOPASS_TEST_LICENSE_BYPASS", "true")
	for _, readOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled flags", true: "read only"}[readOnly], func(t *testing.T) {
			y := newRequestTestServer(t, newMemoryDB(), false)
			y.License = ResolveLicense("", zap.NewNop())
			y.ReadOnly = readOnly
			if !readOnly {
				y.DisableSecretRequests, y.DisableReadReceipts, y.DisableUpload = true, true, true
			}
			handler := y.HTTPHandler()
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest("GET", "/config", nil))
			var config map[string]interface{}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &config))
			assert.Equal(t, false, config["SECRET_REQUESTS"])
			assert.Equal(t, false, config["READ_RECEIPTS"])
			for _, path := range []string{"/request", "/create/file"} {
				w = httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequest("POST", path, nil))
				assert.NotEqual(t, http.StatusOK, w.Code, path)
			}
			if !readOnly {
				body, err := json.Marshal(map[string]interface{}{"expiration": 3600, "receipt": true})
				require.NoError(t, err)
				w = httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequest("POST", "/create/secret", bytes.NewReader(body)))
				assert.Equal(t, http.StatusBadRequest, w.Code)
				assert.Contains(t, w.Body.String(), "Read receipts are not enabled")
			}
		})
	}
}

func TestTestingBypassPreservesSecretAuthorization(t *testing.T) {
	t.Setenv("YOPASS_TEST_LICENSE_BYPASS", "true")
	db := newMemoryDB()
	y := newRequestTestServer(t, db, false)
	y.License = ResolveLicense("", zap.NewNop())
	const id = "00000000-0000-0000-0000-000000000000"
	require.NoError(t, db.Put(id, yopass.Secret{Message: "encrypted", RequireAuth: true, OneTime: true}))
	handler := y.HTTPHandler()
	for _, method := range []string{"GET", "DELETE"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(method, "/secret/"+id, nil))
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		_, err := db.Status(id)
		require.NoError(t, err, "denied request must not consume protected secret")
	}
}

func TestTestingBypassEnablesAudit(t *testing.T) {
	t.Setenv("YOPASS_TEST_LICENSE_BYPASS", "true")
	path := filepath.Join(t.TempDir(), "audit.ndjson")
	audit, err := NewAuditLogger(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = audit.Sync() })
	y := Server{License: ResolveLicense("", zap.NewNop()), Audit: audit}
	require.Same(t, audit, y.audit())
	y.audit().Log(AuditEvent{Event: "test.event"})
	require.NoError(t, audit.Sync())
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "test.event")
}

func TestTestingBypassOIDCLoginStillRequiresAuthentication(t *testing.T) {
	t.Setenv("YOPASS_TEST_LICENSE_BYPASS", "true")
	y := newOIDCTestServer(t)
	y.License = ResolveLicense("", zap.NewNop())
	y.OIDCProvider = newFullMockOIDCProvider()
	y.RequireAuth = true
	handler := y.HTTPHandler()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/auth/login", nil))
	require.Equal(t, http.StatusFound, w.Code)
	assert.True(t, strings.HasPrefix(w.Header().Get("Location"), "https://issuer.example/authorize"))
	for _, path := range []string{"/create/secret", "/create/file", "/request"} {
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("POST", path, nil))
		assert.Equal(t, http.StatusUnauthorized, w.Code, path)
	}
}

func TestTestingBypassDeliversSignedWebhook(t *testing.T) {
	t.Setenv("YOPASS_TEST_LICENSE_BYPASS", "true")
	sink := newWebhookSink(t)
	notifier := newTestNotifier(t, WebhookConfig{URL: sink.server.URL, Secret: "test-signing-secret"}, sink.client)
	y := newRequestTestServer(t, newMemoryDB(), false)
	y.License = ResolveLicense("", zap.NewNop())
	y.Webhooks = notifier
	createRequest(t, y.HTTPHandler(), testPublicKey(t), "test webhook", 3600)
	delivery := sink.waitForEvent(t)
	assert.Equal(t, WebhookEventRequestCreated, delivery.event.Event)
	mac := hmac.New(sha256.New, []byte("test-signing-secret"))
	_, err := mac.Write(delivery.body)
	require.NoError(t, err)
	assert.Equal(t, "sha256="+hex.EncodeToString(mac.Sum(nil)), delivery.signature)
}
