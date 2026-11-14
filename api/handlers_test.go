package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"unbound-dashboard/core"
	"unbound-dashboard/database"
)

func newTestHandler(t *testing.T, debugPublic bool) *Handler {
	t.Helper()
	db, err := database.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return NewHandler(db, &core.Config{DebugPublic: debugPublic}, "vTEST")
}

func TestRenderBars_EscapesAndUsesSinglePercent(t *testing.T) {
	var b strings.Builder
	renderBars(&b, []database.StatItem{
		{Name: `evil"><script>alert(1)</script>`, Value: 10},
		{Name: "safe.example", Value: 5},
	}, "red")
	html := b.String()
	if strings.Contains(html, `%%`) {
		t.Error("literal %% in CSS width (the original bug)")
	}
	if !strings.Contains(html, `width:100%`) || !strings.Contains(html, `width:50%`) {
		t.Errorf("bar widths missing: %s", html)
	}
	if strings.Contains(html, "<script>") {
		t.Errorf("unescaped domain injected: %s", html)
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Errorf("expected escaped output: %s", html)
	}
}

func TestRenderBars_Empty(t *testing.T) {
	var b strings.Builder
	renderBars(&b, nil, "blue")
	if !strings.Contains(b.String(), "暂无数据") {
		t.Errorf("empty state missing: %s", b.String())
	}
}

func TestIndex_EscapesHostAndShowsBars(t *testing.T) {
	h := newTestHandler(t, false)
	if err := h.db.InsertRecord(core.QueryRecord{Domain: "x.test", Timestamp: 1, Count: 3}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.Host = `"><script>x</script>`
	rec := httptest.NewRecorder()
	h.GetRouter().ServeHTTP(rec, req)
	body := rec.Body.String()
	if strings.Contains(body, "<script>x</script>") {
		t.Error("Host header injected raw HTML")
	}
	if !strings.Contains(body, "width:100%") || !strings.Contains(body, "width:") {
		t.Errorf("bars not rendered: %s", body)
	}
}

func TestStats_LowercaseJSON(t *testing.T) {
	h := newTestHandler(t, false)
	if err := h.db.InsertRecord(core.QueryRecord{Domain: "a.test", Timestamp: 1, Count: 7}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.GetRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["total_queries"] != float64(7) {
		t.Errorf("total_queries = %v (want 7, weighted by count)", out["total_queries"])
	}
	top, ok := out["top_queries"].([]any)
	if !ok || len(top) == 0 {
		t.Fatalf("top_queries missing: %v", out["top_queries"])
	}
	item := top[0].(map[string]any)
	if item["name"] != "a.test" {
		t.Errorf("expected lowercase json tags, got %v", item)
	}
}

func TestDebug_TokenGuard(t *testing.T) {
	db, err := database.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	h := NewHandler(db, &core.Config{DebugPublic: true, DebugToken: "s3cret"}, "vTEST")
	req := httptest.NewRequest(http.MethodGet, "/debug", nil)
	req.RemoteAddr = "203.0.113.9:54321"
	rec := httptest.NewRecorder()
	h.GetRouter().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("missing token = %d, want 401", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/debug", nil)
	req.RemoteAddr = "203.0.113.9:54321"
	req.Header.Set("Authorization", "Bearer s3cret")
	rec = httptest.NewRecorder()
	h.GetRouter().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("valid token = %d, want 200", rec.Code)
	}
}

func TestDebug_LoopbackGuard(t *testing.T) {
	h := newTestHandler(t, false)
	req := httptest.NewRequest(http.MethodGet, "/debug", nil)
	req.RemoteAddr = "203.0.113.9:54321"
	rec := httptest.NewRecorder()
	h.GetRouter().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-loopback /debug = %d, want 403", rec.Code)
	}

	req.RemoteAddr = "127.0.0.1:54321"
	rec = httptest.NewRecorder()
	h.GetRouter().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("loopback /debug = %d, want 200", rec.Code)
	}
}

func TestMetricsAndHealth(t *testing.T) {
	h := newTestHandler(t, false)
	for _, path := range []string{"/metrics", "/healthz"} {
		rec := httptest.NewRecorder()
		h.GetRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s = %d", path, rec.Code)
		}
		if path == "/metrics" && !strings.Contains(rec.Body.String(), "unbound_dashboard_frames_received_total") {
			t.Errorf("metrics missing counter: %s", rec.Body.String())
		}
	}
}
