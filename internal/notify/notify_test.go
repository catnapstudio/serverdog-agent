package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
)

func TestValidate(t *testing.T) {
	for raw, ok := range map[string]bool{
		"":                                     true,
		"https://hooks.slack.com/services/x/y": true,
		"http://127.0.0.1:8080/hook":           true,
		"http://localhost/hook":                true,
		"http://hooks.slack.com/services/x":    false,
		"ftp://example.com":                    false,
		"hooks.slack.com":                      false,
		"https://user:pass@example.com/hook":   false,
	} {
		if err := Validate(raw); (err == nil) != ok {
			t.Errorf("Validate(%q) = %v, want ok %v", raw, err, ok)
		}
	}
}

func TestDeployText(t *testing.T) {
	failed := state.Deployment{State: state.Failed, Commit: "abcdef1234", CommitMessage: "Fix the thing\n\nbody", Error: "composer install failed"}
	if got, want := DeployText("core", "app.example.com", failed), "❌ Deploy of app.example.com on core failed (abcdef1 Fix the thing): composer install failed"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	rollback := state.Deployment{Kind: state.KindRollback, State: state.Succeeded}
	if got, want := DeployText("core", "worker", rollback), "✅ Rollback of worker on core succeeded."; got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	long := state.Deployment{State: state.Succeeded, Commit: "abcdef1234", CommitMessage: strings.Repeat("é", 100)}
	if got := DeployText("core", "w", long); !strings.HasSuffix(got, "…).") || !strings.Contains(got, strings.Repeat("é", 72)) {
		t.Errorf("long message cut badly: %q", got)
	}
}

func TestDeployPostsFailuresAndSuccessesOnlyWhenAsked(t *testing.T) {
	var posted []string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)

		var body map[string]string
		// The server's webhook sends both fields; a site's Slack or Discord webhook sends its own alone.
		if err := json.Unmarshal(raw, &body); err != nil || body["text"] != "" && body["content"] != "" && body["text"] != body["content"] {
			t.Errorf("body = %v, %v", body, err)
		}
		posted = append(posted, string(raw))
	}))
	defer hook.Close()

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	m := &Manager{Store: store}
	ctx := context.Background()

	// Nothing saved: nothing posted.
	if err := m.Deploy(ctx, site.Site{Name: "site"}, state.Deployment{State: state.Failed}); err != nil || len(posted) != 0 {
		t.Fatalf("unsaved: err %v, posted %v", err, posted)
	}

	revision, err := m.Put(Settings{WebhookURL: " " + hook.URL + " "}, 0)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := m.Put(Settings{}, 0); err == nil {
		t.Error("a stale revision was accepted")
	}

	_ = m.Deploy(ctx, site.Site{Name: "site"}, state.Deployment{State: state.Succeeded})
	_ = m.Deploy(ctx, site.Site{Name: "site"}, state.Deployment{State: state.Failed, Error: "boom"})
	_ = m.BackupFailed(ctx, "Nightly", "dump failed")

	if len(posted) != 2 || !strings.Contains(posted[0], "boom") || !strings.Contains(posted[1], "Nightly") {
		t.Fatalf("posted %q", posted)
	}

	if _, err := m.Put(Settings{WebhookURL: hook.URL, OnSuccess: true}, revision); err != nil {
		t.Fatal(err)
	}

	_ = m.Deploy(ctx, site.Site{Name: "site"}, state.Deployment{State: state.Succeeded})
	if len(posted) != 3 {
		t.Fatalf("a success wasn't posted with OnSuccess: %q", posted)
	}

	// A site with its own webhooks posts every deploy to each, whatever the server's settings say.
	if _, err := m.Put(Settings{}, revision+1); err != nil {
		t.Fatal(err)
	}

	own := site.Site{Name: "shop", RepositoryURL: "git@github.com:acme/shop.git", DeployNotifications: site.DeployNotifications{SlackURL: hook.URL, HookURL: hook.URL}}
	_ = m.Deploy(ctx, own, state.Deployment{State: state.Succeeded})

	if len(posted) != 5 || !strings.Contains(posted[3], "shop") || !strings.Contains(posted[4], `"status":"succeeded"`) {
		t.Fatalf("the site's own webhooks: %q", posted)
	}

	_ = m.Deploy(ctx, own, state.Deployment{State: state.Failed, Kind: state.KindRollback, Error: "bang"})

	if len(posted) != 7 || !strings.Contains(posted[5], "bang") || !strings.Contains(posted[6], `"kind":"rollback"`) || !strings.Contains(posted[6], `"status":"failed"`) {
		t.Fatalf("a failed rollback: %q", posted)
	}
}

func TestAWebhookErrorIsReported(t *testing.T) {
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusNotFound)
	}))
	defer hook.Close()

	if err := (&Manager{}).Test(context.Background(), hook.URL); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("err = %v, want the 404", err)
	}
}

func TestASitesChatMessageListsWhatIsKnown(t *testing.T) {
	s := site.Site{Name: "shop", RepositoryURL: "git@github.com:acme/shop.git"}
	d := state.Deployment{State: state.Succeeded, Actor: "Morgan's Mac", Commit: "2a20b06a267636c2", CommitMessage: "feat: sign in\n\nbody"}

	want := "✅ Deploy succeeded\n\n**Server:** core\n**Site:** shop\n**By:** Morgan's Mac\n**Commit:** https://github.com/acme/shop/commit/2a20b06a267636c2\n**Message:** feat: sign in"
	if got := DeployDetails("**", "core", s, d); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}

	failed := state.Deployment{State: state.Failed, Kind: state.KindRollback, Actor: "push", Error: "exit 3"}
	want = "❌ Rollback failed\n\n*Server:* core\n*Site:* shop\n*By:* Deploy on push\n*Error:* exit 3"
	if got := DeployDetails("*", "core", s, failed); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestCommitLinksAreMadeOnlyForKnownHosts(t *testing.T) {
	for repository, want := range map[string]string{
		"git@github.com:acme/shop.git":           "https://github.com/acme/shop/commit/abc1234",
		"https://gitlab.com/group/sub/shop.git":  "https://gitlab.com/group/sub/shop/commit/abc1234",
		"ssh://git@bitbucket.org/acme/shop.git":  "https://bitbucket.org/acme/shop/commits/abc1234",
		"git@git.example.com:acme/shop.git":      "",
		"git@127.0.0.1:/srv/git/laraveltest.git": "",
		"":                                       "",
	} {
		if got := CommitLink(repository, "abc1234"); got != want {
			t.Errorf("%q: got %q, want %q", repository, got, want)
		}
	}

	if got := CommitLink("git@github.com:acme/shop.git", ""); got != "" {
		t.Errorf("no commit: got %q", got)
	}
}

func TestACommitSubjectCannotMentionOrLink(t *testing.T) {
	d := state.Deployment{State: state.Failed, Commit: "abcdef1234", CommitMessage: "<!channel> @everyone [reset](https://evil.example)", Error: "<https://evil.example|log>"}

	for _, text := range []string{DeployText("core", "blog", d), DeployDetails("*", "core", site.Site{}, d)} {
		for _, markup := range []string{"<!", "@everyone", "](", "<https"} {
			if strings.Contains(text, markup) {
				t.Errorf("%q still holds %q", text, markup)
			}
		}
	}
}

func TestAFailedPostDoesNotNameTheWebhook(t *testing.T) {
	err := (&Manager{}).send(context.Background(), "http://127.0.0.1:1/services/SECRET-TOKEN", map[string]string{"text": "x"})

	if err == nil || strings.Contains(err.Error(), "SECRET-TOKEN") {
		t.Fatalf("got %v", err)
	}
}
