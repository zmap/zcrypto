package util

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// isURLSlow is the original IsURL: the guards, url.Parse and rxURL, without
// the plain hostname fast path.
func isURLSlow(str string) bool {
	if str == "" || utf8.RuneCountInString(str) >= maxURLRuneCount || len(str) <= minURLRuneCount || strings.HasPrefix(str, ".") {
		return false
	}
	strTemp := str
	if strings.Contains(str, ":") && !strings.Contains(str, "://") {
		strTemp = "http://" + str
	}
	u, err := url.Parse(strTemp)
	if err != nil {
		return false
	}
	if strings.HasPrefix(u.Host, ".") {
		return false
	}
	if u.Host == "" && (u.Path != "" && !strings.Contains(u.Path, ".")) {
		return false
	}
	return rxURL.MatchString(str)
}

// longRun reports whether the heavy exhaustive and random bounds were asked for
// with ZCRYPTO_PROOF_LONG; the default bounds keep go test ./util fast.
func longRun() bool { return os.Getenv("ZCRYPTO_PROOF_LONG") != "" }

func checkSame(t *testing.T, s string) {
	t.Helper()
	if got, want := IsURL(s), isURLSlow(s); got != want {
		t.Fatalf("IsURL(%q) = %v, original = %v", s, got, want)
	}
}

// enumerate calls fn for every string of length 1..maxLen over alphabet.
func enumerate(alphabet []string, maxLen int, fn func(string)) int {
	n := 0
	idx := make([]int, maxLen)
	var buf []byte
	for l := 1; l <= maxLen; l++ {
		for i := range idx[:l] {
			idx[i] = 0
		}
		for {
			buf = buf[:0]
			for _, k := range idx[:l] {
				buf = append(buf, alphabet[k]...)
			}
			fn(string(buf))
			n++
			p := l - 1
			for p >= 0 {
				idx[p]++
				if idx[p] < len(alphabet) {
					break
				}
				idx[p] = 0
				p--
			}
			if p < 0 {
				break
			}
		}
	}
	return n
}

func TestIsURLExhaustive(t *testing.T) {
	// One representative per character class the regexp and url.Parse tell apart.
	wide := []string{"a", "Z", "0", "9", "-", ".", "_", ":", "*", "/", " ", "é"}
	wideLen, narrowLen, hostLen := 5, 7, 9
	if longRun() {
		wideLen, narrowLen, hostLen = 6, 8, 10
	}
	n := enumerate(wide, wideLen, func(s string) { checkSame(t, s) })
	t.Logf("wide alphabet, length <= %d: %d strings", wideLen, n)

	// Longer strings over the characters that matter to the fast path.
	narrow := []string{"a", "0", "-", ".", "_", ":"}
	n = enumerate(narrow, narrowLen, func(s string) { checkSame(t, s) })
	t.Logf("narrow alphabet, length <= %d: %d strings", narrowLen, n)

	// Pure host alphabet at the lengths where the multi-label rules bite.
	host := []string{"a", "0", "-", "."}
	n = enumerate(host, hostLen, func(s string) { checkSame(t, s) })
	t.Logf("host alphabet, length <= %d: %d strings", hostLen, n)
}

func TestIsURLStructured(t *testing.T) {
	lens := []int{1, 2, 62, 63, 64}
	body := func(n int, fill byte) string { return strings.Repeat(string(fill), n) }
	var labelSet []string
	for _, n := range lens {
		labelSet = append(labelSet, body(n, 'a'), body(n, '0'), body(n, 'Z'))
		if n >= 2 {
			labelSet = append(labelSet, "-"+body(n-1, 'a'), body(n-1, 'a')+"-")
		}
		if n >= 3 {
			labelSet = append(labelSet, "a-"+body(n-2, 'b'), "a--"+body(n-3, 'b'), "a---"+body(n-4+1, 'b'))
		}
	}
	labelSet = append(labelSet, "xn--bcher-kva", "xn--80ak6aa92e", "a-b-c", "a--b", "a---b", "1", "123", "", "_", "a_b", "www", "*")
	tlds := []string{"com", "COM", "io", "c", "xn--p1ai", "123", "c0m", "co-m", "-com", "com-", "museum", "", "x1"}

	count := 0
	check := func(s string) {
		count++
		checkSame(t, s)
	}
	join := func(ls ...string) string { return strings.Join(ls, ".") }

	// The three-label cross product is the heavy part: by default the middle
	// label comes from a subset.
	middles := labelSet
	if !longRun() {
		middles = []string{"a", "ab", "a-b", "a--b", "a---b", "0", "-a", "a-", "", "_", "xn--bcher-kva", body(63, 'a')}
	}
	for _, a := range labelSet {
		for _, tld := range tlds {
			check(join(a, tld))
			check(join(a, tld) + ".")
			check("." + join(a, tld))
			check("*." + join(a, tld))
			check("www." + join(a, tld))
			for _, b := range middles {
				check(join(a, b, tld))
				check(join(a, b, tld) + ".")
				check(join(b, a, "com"))
			}
		}
	}

	// 3..6 labels drawn from a small set that covers each rule.
	small := []string{"a", "ab", "a-b", "a--b", "a---b", "0", "1-1", "xn--a", "-a", "a-"}
	var rec func(prefix []string, depth int)
	rec = func(prefix []string, depth int) {
		if len(prefix) >= 1 {
			for _, tld := range []string{"com", "c0m", "co", "x"} {
				ls := append(append([]string{}, prefix...), tld)
				check(join(ls...))
				check(join(ls...) + ".")
			}
		}
		if depth == 0 {
			return
		}
		for _, l := range small {
			rec(append(append([]string{}, prefix...), l), depth-1)
		}
	}
	depth := 4
	if longRun() {
		depth = 5
	}
	rec(nil, depth)

	// Total length around the 253/254 byte DNS limit and the 2083 guard.
	for _, total := range []int{250, 251, 252, 253, 254, 255, 256, 2081, 2082, 2083, 2084} {
		var ls []string
		n := 0
		for n+64 < total-4 {
			ls = append(ls, body(63, 'a'))
			n += 64
		}
		pad := total - 4 - n
		if pad > 0 {
			ls = append(ls, body(pad, 'b'))
		}
		ls = append(ls, "com")
		s := join(ls...)
		check(s)
		check(s + ".")
		check(strings.ToUpper(s))
	}
	t.Logf("structured: %d strings", count)
}

func TestIsURLRealWorld(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"example.com", true},
		{"www.example.com", true},
		{"mail.google.com", true},
		{"EXAMPLE.COM", true},
		{"a.b.c.d.e.example.co.uk", true},
		{"my-host.example.org", true},
		{"example.com.", true},
		{"xn--bcher-kva.example", true},
		{"xn--80ak6aa92e.com", true},
		{"foo.xn--p1ai", true},
		{"*.example.com", false},
		{"bücher.example", true},
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"[::1]", true},
		{"2001:db8::1", false},
		{"example.com:8443", true},
		{"https://example.com/path", true},
		{"user@example.com", true},
		{"localhost", false},
		{"..example.com", false},
		{".example.com", false},
		{"", false},
		{"a.b", false},
		{"ab.c", true},
		{"example", false},
		{"under_score.example.com", true},
	}
	for _, tc := range tests {
		got := IsURL(tc.in)
		if got != tc.want {
			t.Errorf("IsURL(%q) = %v, want %v", tc.in, got, tc.want)
		}
		if slow := isURLSlow(tc.in); got != slow {
			t.Errorf("IsURL(%q) = %v, original = %v", tc.in, got, slow)
		}
	}
}

func fuzzSeeds() []string {
	seeds := []string{
		"example.com", "www.example.com", "*.example.com", "a.b.c", "xn--bcher-kva.example",
		"xn--80ak6aa92e.com", "bücher.example", "例え.jp", "127.0.0.1", "[::1]", "::1", "1.2.3.4.5",
		"a--b.example.com", "a.b--c.example.com", "a-.com", "-a.com", "a.com.", "a.com..", "..a.com",
		"1.com", "a.1", "a.b1", "example.com:80", "http://a.com", "user@a.com", "a.com/x", "a.com?x", "a b.com",
		"a_b.com", "_a.com", "ab.com", "a.bc.de", "a.b.de", "ab.cd.ef.gh", strings.Repeat("a", 63) + ".com",
		strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 120) + "com",
	}
	for _, f := range []string{"../x509/testdata"} {
		files, _ := filepath.Glob(filepath.Join(f, "*"))
		for _, name := range files {
			base := filepath.Base(name)
			if i := strings.LastIndexByte(base, '.'); i > 0 && strings.Contains(base[:i], ".") {
				seeds = append(seeds, strings.TrimSuffix(base, filepath.Ext(base)))
			}
		}
	}
	return seeds
}

func FuzzIsURL(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got, want := IsURL(s), isURLSlow(s); got != want {
			t.Fatalf("IsURL(%q) = %v, original = %v", s, got, want)
		}
		if isPlainHostname(s) && len(s) > minURLRuneCount && len(s) < maxURLRuneCount && s[0] != '.' && !isURLSlow(s) {
			t.Fatalf("isPlainHostname(%q) accepted a string the original rejects", s)
		}
	})
}

var benchHosts = []string{
	"example.com",
	"mail.corp.internal.example-hosting.co.uk",
	strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + ".example.org",
	"*.example.com",
	"bücher.example",
	"192.168.10.20",
	"xn--80ak6aa92e.com",
}

func BenchmarkIsURL(b *testing.B) {
	for _, h := range benchHosts {
		name := h
		if len(name) > 24 {
			name = fmt.Sprintf("%s...(%d)", name[:12], len(h))
		}
		b.Run("fast/"+name, func(b *testing.B) {
			for b.Loop() {
				IsURL(h)
			}
		})
		b.Run("orig/"+name, func(b *testing.B) {
			for b.Loop() {
				isURLSlow(h)
			}
		})
	}
}
