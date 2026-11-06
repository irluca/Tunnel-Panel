package audit

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/model"
)

func TestIsSecretField(t *testing.T) {
	secret := []string{
		"password", "Password", "current_password", "new_password", "passwd",
		"token", "access_token", "refresh_token", "csrf_token", "Authorization",
		"Cookie", "client_secret", "api_key", "apiKey", "private_key", "credential",
	}
	for _, name := range secret {
		if !IsSecretField(name) {
			t.Errorf("IsSecretField(%q) = false, want true", name)
		}
	}

	// GRE keys are configuration, not credentials. Redacting them would hide
	// the single most common misconfiguration from the audit trail, so a bare
	// "key" must not match.
	notSecret := []string{
		"ikey", "okey", "IKey", "OKey", "tunnel.default_key", "key",
		"username", "interface_name", "local_endpoint", "mtu", "ttl",
	}
	for _, name := range notSecret {
		if IsSecretField(name) {
			t.Errorf("IsSecretField(%q) = true, want false", name)
		}
	}
}

func TestRedactWalksNestedStructures(t *testing.T) {
	input := map[string]any{
		"username": "operator",
		"password": "correct horse battery staple",
		"tunnel": map[string]any{
			"interface_name": "gre-a-1",
			"ikey":           2749365187.0,
			"nested": map[string]any{
				"api_key": "sk-live-secret",
			},
		},
		"recent_logins": []any{
			map[string]any{"token": "abc.def.ghi", "created": "2026-01-01"},
		},
	}

	encoded, err := json.Marshal(Redact(input))
	if err != nil {
		t.Fatalf("encoding the redacted value failed: %v", err)
	}
	out := string(encoded)

	for _, leaked := range []string{"correct horse battery staple", "sk-live-secret", "abc.def.ghi"} {
		if strings.Contains(out, leaked) {
			t.Errorf("the redacted output still contains %q:\n%s", leaked, out)
		}
	}
	// Everything that is not a secret survives, or the audit trail is useless.
	for _, kept := range []string{"operator", "gre-a-1", "2749365187", "2026-01-01"} {
		if !strings.Contains(out, kept) {
			t.Errorf("the redacted output lost %q:\n%s", kept, out)
		}
	}
	if strings.Count(out, Redacted) != 3 {
		t.Errorf("expected three redactions, got %d:\n%s", strings.Count(out, Redacted), out)
	}
}

// TestRedactionIsDeliberatelyOverBroad documents the trade-off: a field whose
// own name looks like a secret is replaced whole, children included, even when
// some of those children are harmless. Losing a timestamp from the audit trail
// is a small cost; leaking a credential from a panel that runs as root is not.
func TestRedactionIsDeliberatelyOverBroad(t *testing.T) {
	encoded, err := json.Marshal(Redact(map[string]any{
		"credentials": map[string]any{"username": "operator", "issued": "2026-01-01"},
	}))
	if err != nil {
		t.Fatalf("encoding the redacted value failed: %v", err)
	}
	if got, want := string(encoded), `{"credentials":"`+Redacted+`"}`; got != want {
		t.Errorf("Redact = %s, want the whole subtree replaced as %s", got, want)
	}
}

func TestRedactDoesNotMutateTheInput(t *testing.T) {
	input := map[string]any{"password": "secret"}
	Redact(input)
	if input["password"] != "secret" {
		t.Error("Redact mutated the value it was given")
	}
}

func TestRedactJSON(t *testing.T) {
	got := RedactJSON([]byte(`{"username":"operator","password":"hunter2hunter2"}`))
	if strings.Contains(got, "hunter2hunter2") {
		t.Errorf("RedactJSON leaked the password: %s", got)
	}
	if !strings.Contains(got, "operator") {
		t.Errorf("RedactJSON dropped a non-secret field: %s", got)
	}

	if got := RedactJSON(nil); got != "{}" {
		t.Errorf("RedactJSON(nil) = %s, want {}", got)
	}
	// A body that is not JSON is discarded rather than stored unredacted,
	// because there is no way to know what is inside it.
	got = RedactJSON([]byte("password=hunter2hunter2&x=1"))
	if strings.Contains(got, "hunter2hunter2") {
		t.Errorf("RedactJSON stored an unparseable body verbatim: %s", got)
	}
}

func TestWriteAndPrune(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("opening the test database failed: %v", err)
	}
	defer database.Close()
	if err := db.Init(ctx, database); err != nil {
		t.Fatalf("initialising the test database failed: %v", err)
	}

	w := New(database, nil)
	w.Write(ctx, Entry{
		ActionID:   model.AuditActionLogin,
		TargetType: "AppUser",
		TargetID:   "1",
		Request:    map[string]any{"username": "operator", "password": "hunter2hunter2"},
		Operations: []Operation{{Kind: "netlink", Detail: "LinkAdd gre-a-1", DurationMs: 3}},
		IsSuccess:  true,
		ClientIP:   "203.0.113.7",
	})

	var request, operations, clientIP string
	var actionID int64
	err = database.Read.QueryRowContext(ctx,
		`SELECT AuditActionID, RequestJson, OperationsJson, ClientIp FROM AuditLog`).
		Scan(&actionID, &request, &operations, &clientIP)
	if err != nil {
		t.Fatalf("reading the audit row failed: %v", err)
	}
	if actionID != model.AuditActionLogin {
		t.Errorf("AuditActionID = %d, want %d", actionID, model.AuditActionLogin)
	}
	if strings.Contains(request, "hunter2hunter2") {
		t.Errorf("the stored request contains the password: %s", request)
	}
	if !strings.Contains(request, "operator") {
		t.Errorf("the stored request lost the username: %s", request)
	}
	if !strings.Contains(operations, "LinkAdd gre-a-1") {
		t.Errorf("the stored operations lost the trace: %s", operations)
	}
	if clientIP != "203.0.113.7" {
		t.Errorf("ClientIp = %q, want 203.0.113.7", clientIP)
	}

	// Pruning keeps recent entries and removes ones past the retention window.
	removed, err := w.Prune(ctx, 90)
	if err != nil {
		t.Fatalf("Prune returned an unexpected error: %v", err)
	}
	if removed != 0 {
		t.Errorf("Prune removed %d recent rows, want 0", removed)
	}

	if _, err := database.Write.ExecContext(ctx,
		`UPDATE AuditLog SET CreatedDate = '2020-01-01T00:00:00.000Z'`); err != nil {
		t.Fatalf("ageing the audit row failed: %v", err)
	}
	removed, err = w.Prune(ctx, 90)
	if err != nil {
		t.Fatalf("Prune returned an unexpected error: %v", err)
	}
	if removed != 1 {
		t.Errorf("Prune removed %d aged rows, want 1", removed)
	}
}

// TestWriteToleratesAFailedInsert confirms auditing never breaks the request it
// describes: the operation has already happened, so a logging failure must not
// surface as a request failure.
func TestWriteToleratesAFailedInsert(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("opening the test database failed: %v", err)
	}
	if err := db.Init(ctx, database); err != nil {
		t.Fatalf("initialising the test database failed: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("closing the database failed: %v", err)
	}

	// Must not panic and must not block.
	New(database, nil).Write(ctx, Entry{ActionID: model.AuditActionLogin})
	// A nil writer is equally safe, so callers need no nil checks.
	var nilWriter *Writer
	nilWriter.Write(ctx, Entry{ActionID: model.AuditActionLogin})
}

func TestRedactOperationsScrubsTheEspKey(t *testing.T) {
	ops := []Operation{
		{Kind: KindCommand, Argv: []string{"/sbin/ip", "link", "add", "name", "esp-a-1", "type", "xfrm", "if_id", "42"}},
		{Kind: KindCommand, Argv: []string{"/sbin/ip", "xfrm", "state", "add",
			"src", "203.0.113.10", "dst", "198.51.100.20", "proto", "esp", "spi", "0x12345678",
			"mode", "transport", "aead", "rfc4106(gcm(aes))", "0xaabbccddeeff00112233445566778899aabbccdd", "128",
			"replay-window", "32", "if_id", "42"}},
		{Kind: KindCommand, Argv: []string{"/sbin/ip", "xfrm", "policy", "add",
			"src", "0.0.0.0/0", "dst", "0.0.0.0/0", "dir", "out", "if_id", "42"}},
	}
	got := redactOperations(ops)
	// The key is gone, but the rest of the command — including the SPI and
	// the interface identifier — stays readable.
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshalling the redacted operations failed: %v", err)
	}
	if strings.Contains(string(encoded), "aabbccddeeff00112233445566778899aabbccdd") {
		t.Fatalf("the ESP key survived redaction: %s", encoded)
	}
	if !strings.Contains(string(encoded), "0x12345678") {
		t.Fatalf("redaction removed more than the key: %s", encoded)
	}
	if got[1].Argv[16] != Redacted {
		t.Fatalf("the element after the AEAD name = %q, want %q", got[1].Argv[16], Redacted)
	}
	// The input is not mutated: the caller's copy keeps the key, so a retry
	// of the same command still has it.
	if ops[1].Argv[16] != "0xaabbccddeeff00112233445566778899aabbccdd" {
		t.Fatal("redaction mutated the caller's operations")
	}
}
