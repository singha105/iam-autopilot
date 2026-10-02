package githubpr

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/singha105/iam-autopilot/internal/config"
)

// fakeGitHub is a tiny in-memory GitHub: branches point at file trees, PRs and
// labels are recorded. It serves only the endpoints the client uses.
type fakeGitHub struct {
	mu       sync.Mutex
	t        *testing.T
	branches map[string]map[string]string // branch -> path -> content
	commits  []commit
	pulls    map[int]*pull
	labels   map[string]bool
	comments map[int][]string
	issueLbl map[int][]string
	nextPR   int
	auth     []string
}

type commit struct{ branch, path, message string }

type pull struct {
	Number      int
	Title, Body string
	Head, Base  string
	State       string
	Merged      bool
	MergedBy    string
	MergedAt    string
}

func blobSHA(s string) string { return fmt.Sprintf("%x", sha1.Sum([]byte(s))) }

func newFakeGitHub(t *testing.T, files map[string]string) (*fakeGitHub, *Client) {
	t.Helper()
	f := &fakeGitHub{
		t: t, branches: map[string]map[string]string{"main": files},
		pulls: map[int]*pull{}, labels: map[string]bool{}, comments: map[int][]string{}, issueLbl: map[int][]string{}, nextPR: 7,
	}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	c, err := New("test-token", config.GitHub{Owner: "o", Repo: "r", Branch: "main"}, srv.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

func (f *fakeGitHub) write(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (f *fakeGitHub) notFound(w http.ResponseWriter) {
	f.write(w, http.StatusNotFound, map[string]string{"message": "Not Found"})
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	path, _ := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), "/repos/o/r/"))
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	json.Unmarshal(raw, &body) // object payloads; array payloads stay in raw
	str := func(k string) string { s, _ := body[k].(string); return s }

	switch {
	case r.Method == "GET" && strings.HasPrefix(path, "git/ref/heads/"):
		branch := strings.TrimPrefix(path, "git/ref/heads/")
		if f.branches[branch] == nil {
			f.notFound(w)
			return
		}
		f.write(w, 200, map[string]any{"ref": "refs/heads/" + branch, "object": map[string]string{"sha": "sha-of-" + branch}})

	case r.Method == "POST" && path == "git/refs":
		branch := strings.TrimPrefix(str("ref"), "refs/heads/")
		if f.branches[branch] != nil {
			f.write(w, 422, map[string]string{"message": "Reference already exists"})
			return
		}
		from := strings.TrimPrefix(str("sha"), "sha-of-")
		copyTree := map[string]string{}
		for p, c := range f.branches[from] {
			copyTree[p] = c
		}
		f.branches[branch] = copyTree
		f.write(w, 201, map[string]any{"ref": str("ref"), "object": map[string]string{"sha": "sha-of-" + branch}})

	case r.Method == "DELETE" && strings.HasPrefix(path, "git/refs/heads/"):
		delete(f.branches, strings.TrimPrefix(path, "git/refs/heads/"))
		w.WriteHeader(204)

	case r.Method == "GET" && strings.HasPrefix(path, "contents/"):
		p, ref := strings.TrimPrefix(path, "contents/"), r.URL.Query().Get("ref")
		content, ok := f.branches[ref][p]
		if !ok {
			f.notFound(w)
			return
		}
		f.write(w, 200, map[string]any{"type": "file", "path": p, "encoding": "base64", "sha": blobSHA(content), "content": base64.StdEncoding.EncodeToString([]byte(content))})

	case r.Method == "PUT" && strings.HasPrefix(path, "contents/"):
		p, branch := strings.TrimPrefix(path, "contents/"), str("branch")
		old, exists := f.branches[branch][p]
		if exists && str("sha") != blobSHA(old) {
			f.write(w, 409, map[string]string{"message": "sha mismatch"})
			return
		}
		if !exists && str("sha") != "" {
			f.write(w, 422, map[string]string{"message": "sha given for a new file"})
			return
		}
		content, _ := base64.StdEncoding.DecodeString(str("content"))
		f.branches[branch][p] = string(content)
		f.commits = append(f.commits, commit{branch, p, str("message")})
		f.write(w, 200, map[string]any{"content": map[string]string{"path": p}})

	case r.Method == "POST" && path == "pulls":
		n := f.nextPR
		f.nextPR++
		f.pulls[n] = &pull{Number: n, Title: str("title"), Body: str("body"), Head: str("head"), Base: str("base"), State: "open"}
		f.write(w, 201, map[string]any{"number": n, "html_url": fmt.Sprintf("https://github.com/o/r/pull/%d", n), "state": "open"})

	case strings.HasPrefix(path, "pulls/"):
		n, _ := strconv.Atoi(strings.TrimPrefix(path, "pulls/"))
		p := f.pulls[n]
		if p == nil {
			f.notFound(w)
			return
		}
		if r.Method == "PATCH" {
			if s := str("state"); s != "" {
				p.State = s
			}
		}
		out := map[string]any{"number": n, "state": p.State, "merged": p.Merged}
		if p.Merged {
			out["merged_by"] = map[string]string{"login": p.MergedBy}
			out["merged_at"] = p.MergedAt
		}
		f.write(w, 200, out)

	case r.Method == "GET" && strings.HasPrefix(path, "labels/"):
		if !f.labels[strings.TrimPrefix(path, "labels/")] {
			f.notFound(w)
			return
		}
		f.write(w, 200, map[string]string{"name": strings.TrimPrefix(path, "labels/")})

	case r.Method == "POST" && path == "labels":
		f.labels[str("name")] = true
		f.write(w, 201, map[string]string{"name": str("name")})

	case r.Method == "POST" && strings.HasPrefix(path, "issues/") && strings.HasSuffix(path, "/labels"):
		n, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(path, "issues/"), "/labels"))
		var names []string
		if err := json.Unmarshal(raw, &names); err != nil {
			f.t.Errorf("labels payload %s: %v", raw, err)
		}
		f.issueLbl[n] = append(f.issueLbl[n], names...)
		f.write(w, 200, []map[string]string{{"name": Label}})

	case r.Method == "POST" && strings.HasPrefix(path, "issues/") && strings.HasSuffix(path, "/comments"):
		n, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(path, "issues/"), "/comments"))
		f.comments[n] = append(f.comments[n], str("body"))
		f.write(w, 201, map[string]any{"id": 1, "body": str("body")})

	default:
		f.t.Errorf("fake GitHub: unexpected %s %s", r.Method, r.URL.Path)
		f.notFound(w)
	}
}
