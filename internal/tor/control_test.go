package tor

import (
	"bufio"
	"strings"
	"testing"
	"time"
)

// reply builds a Control reading from a canned server reply.
func reply(raw string) *Control {
	return &Control{r: bufio.NewReader(strings.NewReader(raw))}
}

func TestReadReplySingleLine(t *testing.T) {
	code, body, err := reply("250 OK\r\n").readReply()
	if err != nil {
		t.Fatalf("readReply: %v", err)
	}
	if code != 250 {
		t.Errorf("code = %d, want 250", code)
	}
	if body != "OK" {
		t.Errorf("body = %q, want %q", body, "OK")
	}
}

func TestReadReplyMidReplyErrorCodeWins(t *testing.T) {
	// A continuation carrying an error must not be masked by a 250 first line.
	code, _, err := reply("250-partial\r\n552 Unrecognized key\r\n").readReply()
	if err != nil {
		t.Fatalf("readReply: %v", err)
	}
	if code != 552 {
		t.Errorf("code = %d, want 552 (the error, not the leading 250)", code)
	}
}

func TestReadReplyDotQuotedPayload(t *testing.T) {
	raw := "250+circuit-status=\r\n" +
		"1 BUILT $AAA~a,$BBB~b PURPOSE=GENERAL\r\n" +
		"..hidden leading dot\r\n" +
		".\r\n" +
		"250 OK\r\n"
	code, body, err := reply(raw).readReply()
	if err != nil {
		t.Fatalf("readReply: %v", err)
	}
	if code != 250 {
		t.Errorf("code = %d, want 250", code)
	}
	if !strings.Contains(body, "1 BUILT") {
		t.Errorf("payload missing from body: %q", body)
	}
	// The doubled leading dot is an escape and must be unescaped exactly once.
	if !strings.Contains(body, ".hidden leading dot") {
		t.Errorf("escaped leading dot not unescaped: %q", body)
	}
}

func TestReadReplyRejectsMalformed(t *testing.T) {
	for name, raw := range map[string]string{
		"short line":    "25\r\n",
		"bad code":      "abc OK\r\n",
		"bad separator": "250*OK\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := reply(raw).readReply(); err == nil {
				t.Errorf("expected an error for %q", raw)
			}
		})
	}
}

func TestParseGetInfoInline(t *testing.T) {
	got, err := parseGetInfo("status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done", "status/bootstrap-phase")
	if err != nil {
		t.Fatalf("parseGetInfo: %v", err)
	}
	if !strings.Contains(got, "PROGRESS=100") {
		t.Errorf("got %q", got)
	}
}

func TestParseGetInfoMultiLineStripsTrailingOK(t *testing.T) {
	got, err := parseGetInfo("circuit-status=\n1 BUILT $AAA~a\n2 BUILT $BBB~b\nOK", "circuit-status")
	if err != nil {
		t.Fatalf("parseGetInfo: %v", err)
	}
	if strings.Contains(got, "OK") {
		t.Errorf("trailing OK should be stripped, got %q", got)
	}
	if !strings.Contains(got, "2 BUILT") {
		t.Errorf("payload truncated: %q", got)
	}
}

func TestParseGetInfoMissingKey(t *testing.T) {
	if _, err := parseGetInfo("something-else=1", "wanted"); err == nil {
		t.Fatal("expected an error when the key is absent")
	}
}

func TestBootstrapPercent(t *testing.T) {
	c := reply("250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=45 TAG=conn\r\n250 OK\r\n")
	c.authenticated = true
	c.conn = discardConn{}

	pct, err := c.BootstrapPercent()
	if err != nil {
		t.Fatalf("BootstrapPercent: %v", err)
	}
	if pct != 45 {
		t.Errorf("pct = %d, want 45", pct)
	}
}

func TestParseNetworkStatus(t *testing.T) {
	desc := "r SomeExit AAAAB3Nza dGVzdA== 2026-07-27 12:00:00 185.220.101.5 9001 9030\ns Exit Fast Running"
	node := parseNetworkStatus(desc)
	if node.Nickname != "SomeExit" {
		t.Errorf("Nickname = %q, want SomeExit", node.Nickname)
	}
	if node.Address != "185.220.101.5" {
		t.Errorf("Address = %q, want 185.220.101.5", node.Address)
	}
}

func TestQuoteControlValue(t *testing.T) {
	tests := map[string]string{
		"{us}":           "{us}",
		"a b":            `"a b"`,
		`say "hi"`:       `"say \"hi\""`,
		"back\\slash":    `"back\\slash"`,
		"line\nbreak":    `"linebreak"`, // newlines would end the command
		"tab\tseparated": `"tab	separated"`,
	}
	for in, want := range tests {
		if got := quoteControlValue(in); got != want {
			t.Errorf("quoteControlValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUnquoteControlValue(t *testing.T) {
	if got := unquoteControlValue(`"a b"`); got != "a b" {
		t.Errorf("got %q, want %q", got, "a b")
	}
	if got := unquoteControlValue("plain"); got != "plain" {
		t.Errorf("got %q, want %q", got, "plain")
	}
}

func TestCommandsRequireAuthentication(t *testing.T) {
	c := &Control{conn: discardConn{}, r: bufio.NewReader(strings.NewReader(""))}
	if err := c.Signal("NEWNYM"); err == nil {
		t.Error("Signal should refuse before authentication")
	}
	if _, err := c.GetInfo("version"); err == nil {
		t.Error("GetInfo should refuse before authentication")
	}
	if err := c.SetConf("ExitNodes", "{us}"); err == nil {
		t.Error("SetConf should refuse before authentication")
	}
}

func TestNewnymWaitTracksCooldown(t *testing.T) {
	c := &Control{}
	if got := c.NewnymWait(); got != 0 {
		t.Errorf("a connection that never signalled should not wait, got %s", got)
	}

	c.lastNewnym = time.Now()
	wait := c.NewnymWait()
	if wait <= 0 || wait > NewnymCooldown {
		t.Errorf("wait = %s, want within (0, %s]", wait, NewnymCooldown)
	}

	c.lastNewnym = time.Now().Add(-2 * NewnymCooldown)
	if got := c.NewnymWait(); got != 0 {
		t.Errorf("expired cooldown should not wait, got %s", got)
	}
}

func TestSplitTorLog(t *testing.T) {
	level, msg := splitTorLog("Jul 27 22:14:03.000 [notice] Bootstrapped 100% (done): Done")
	if level != "notice" {
		t.Errorf("level = %q, want notice", level)
	}
	if msg != "Bootstrapped 100% (done): Done" {
		t.Errorf("msg = %q", msg)
	}

	// Unrecognised lines are kept, not dropped.
	level, msg = splitTorLog("something unstructured")
	if level != "notice" || msg != "something unstructured" {
		t.Errorf("got (%q, %q), want (notice, something unstructured)", level, msg)
	}
}
