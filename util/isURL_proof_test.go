package util

// Proof that the IsURL fast path never answers true where the original IsURL
// answers false.
//
// Theorem. Let A be the 64 symbols [A-Za-z0-9.-]. Let L(fast) be the set of
// byte strings for which fastStart, fastStep and fastAccept (the automaton
// behind isPlainHostname) end in an accepting state, and L(rx) the set of
// strings matched by rxURL. Then L(fast) is a subset of L(rx), for every string
// length.
//
// TestFastPathLanguageInclusion proves it in two exhaustive searches over
// finite state spaces. First, every reachable fast state is stepped over all
// 256 byte values; a byte outside A that does not lead to the dead state is a
// counterexample, so L(fast) is a subset of A*. Second, an NFA re-derived from
// the live rxURL source (regexp/syntax.Parse, Simplify, Compile, then
// interpretation of the Prog) is determinised by subset construction over A,
// and the reachable product of that DFA with the fast automaton is explored: if
// no reachable product state is (fast accepting, regexp rejecting), no string is
// a counterexample. A breadth-first search returns a shortest counterexample
// when one exists.
//
// Validation. TestFastPathModelsAgree checks the regexp DFA against
// rxURL.MatchString, and isPlainHostname against the automaton, on every short
// string over a 14-symbol alphabet covering the regexp's distinguishing classes
// and on random strings over all 64 symbols.
// TestFastPathMutants shows the checks are not vacuous: unsound automata each
// produce a counterexample. ZCRYPTO_PROOF_LONG raises the bounds of the sampled
// tests; the exact searches are always full.
//
// Lemma (TestFastPathPreconditions). IsURL runs checks before rxURL; for every
// string in L(fast) none of them can reject, so whenever the fast path answers
// true the original reaches rxURL.MatchString and gets true by the theorem. The
// checks are: the empty, rune count, byte length and leading-dot guards (they
// run before the fast path in IsURL itself); url.Parse succeeds; the parsed
// Host does not start with '.'; and an empty Host implies a Path containing
// '.'. For s over A, net/url finds no scheme, authority, query or fragment, so
// url.Parse succeeds with Host == "" and Path == s. A product search with a
// tracker proves, for all lengths and from the automaton alone, that every
// accepted string has at least four bytes, contains a dot and does not start
// with one; the test also calls url.Parse on every accepted string up to a
// length bound and on a shortest representative of every accepting state.
//
// Model assumptions.
//   - The regexp is modelled by interpreting the compiled Prog as an NFA. Rune
//     instructions are evaluated with Inst.MatchRune, which honours rune ranges
//     and FoldCase; only the 64 symbols of A are fed to it, which is sound
//     because L(fast) is a subset of A*.
//   - The model computes the anchored language: BeginText holds only before the
//     first symbol and EndText only after the last. That language is always a
//     subset of the one MatchString decides, so soundness of the inclusion does
//     not depend on the anchors; only tightness does, and
//     TestFastPathModelsAgree cross-checks it against rxURL.MatchString. Any
//     other empty-width op or instruction kind in the Prog fails the test
//     loudly instead of being ignored.
//
// Not proven: the behaviour of net/url that the lemma cites (checked by calls,
// not derived from the Go source); the correctness of regexp/syntax and of the
// NFA interpretation beyond the sampled cross-checks; and that IsURL calls the
// fast path only after its guards (a property of the code, covered by the
// differential tests in isURL_test.go). A changed URL regexp or fast automaton
// is re-checked automatically because everything is re-derived at run time.

import (
	"fmt"
	"math/rand"
	"net/url"
	"regexp/syntax"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

const proofAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-"

var allBytes = func() []byte {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}()

type regexpDFA struct {
	prog   *syntax.Prog
	ids    map[string]int
	sets   [][]uint32
	trans  [][]int
	accept []bool
}

func newRegexpDFA(t *testing.T, src string) *regexpDFA {
	t.Helper()
	re, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
		t.Fatalf("parse regexp: %v", err)
	}
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		t.Fatalf("compile regexp: %v", err)
	}
	var begin, end int
	for pc, in := range prog.Inst {
		switch in.Op {
		case syntax.InstEmptyWidth:
			switch syntax.EmptyOp(in.Arg) {
			case syntax.EmptyBeginText:
				begin++
			case syntax.EmptyEndText:
				end++
			default:
				t.Fatalf("inst %d: unsupported empty-width op %#b", pc, in.Arg)
			}
		case syntax.InstAlt, syntax.InstAltMatch, syntax.InstCapture, syntax.InstNop, syntax.InstFail,
			syntax.InstMatch, syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
		default:
			t.Fatalf("inst %d: unsupported op %v", pc, in.Op)
		}
	}
	if begin != 1 || end != 1 {
		t.Fatalf("expected exactly one BeginText and one EndText, got %d and %d", begin, end)
	}
	d := &regexpDFA{prog: prog, ids: map[string]int{}}
	d.add(d.closure([]uint32{uint32(prog.Start)}, true, false), true)
	return d
}

// closure returns the sorted epsilon closure of seeds, keeping only what the
// model needs afterwards: rune matchers, InstMatch, and an EndText assertion
// that is not satisfied yet. Every op was vetted by newRegexpDFA.
func (d *regexpDFA) closure(seeds []uint32, atStart, atEnd bool) []uint32 {
	seen := map[uint32]bool{}
	var out []uint32
	stack := slices.Clone(seeds)
	for len(stack) > 0 {
		pc := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[pc] {
			continue
		}
		seen[pc] = true
		in := &d.prog.Inst[pc]
		switch in.Op {
		case syntax.InstAlt, syntax.InstAltMatch:
			stack = append(stack, in.Out, in.Arg)
		case syntax.InstCapture, syntax.InstNop:
			stack = append(stack, in.Out)
		case syntax.InstEmptyWidth:
			switch {
			case syntax.EmptyOp(in.Arg) == syntax.EmptyBeginText && atStart,
				syntax.EmptyOp(in.Arg) == syntax.EmptyEndText && atEnd:
				stack = append(stack, in.Out)
			case syntax.EmptyOp(in.Arg) == syntax.EmptyEndText:
				out = append(out, pc)
			}
		case syntax.InstFail:
		default:
			out = append(out, pc)
		}
	}
	slices.Sort(out)
	return out
}

func (d *regexpDFA) add(set []uint32, initial bool) int {
	key := fmt.Sprint(set, initial)
	if id, ok := d.ids[key]; ok {
		return id
	}
	id := len(d.sets)
	d.ids[key] = id
	d.sets = append(d.sets, set)
	d.trans = append(d.trans, nil)
	acc := false
	for _, pc := range d.closure(set, initial, true) {
		acc = acc || d.prog.Inst[pc].Op == syntax.InstMatch
	}
	d.accept = append(d.accept, acc)
	return id
}

// next returns the successor of state id on the symbol at index sym.
func (d *regexpDFA) next(id, sym int) int {
	if d.trans[id] == nil {
		d.trans[id] = slices.Repeat([]int{-1}, len(proofAlphabet))
	}
	if n := d.trans[id][sym]; n >= 0 {
		return n
	}
	r := rune(proofAlphabet[sym])
	var seeds []uint32
	for _, pc := range d.sets[id] {
		in := &d.prog.Inst[pc]
		switch in.Op {
		case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
			if in.MatchRune(r) {
				seeds = append(seeds, in.Out)
			}
		}
	}
	n := d.add(d.closure(seeds, false, false), false)
	d.trans[id][sym] = n
	return n
}

type fastAutomaton struct {
	start  fastState
	step   func(fastState, byte) (fastState, bool)
	accept func(fastState) bool
}

var realAutomaton = fastAutomaton{start: fastStart, step: fastStep, accept: fastAccept}

// search explores, breadth first, every state reachable from start over syms
// and returns the shortest string leading to a state for which bad holds.
func search[K comparable](start K, syms []byte, step func(K, byte) (K, bool), bad func(K) bool) (string, bool) {
	type edge struct {
		prev K
		sym  byte
	}
	parent := map[K]edge{}
	seen := map[K]bool{start: true}
	queue := []K{start}
	for head := 0; head < len(queue); head++ {
		k := queue[head]
		if bad(k) {
			var b []byte
			for k != start {
				e := parent[k]
				b = append(b, e.sym)
				k = e.prev
			}
			slices.Reverse(b)
			return string(b), true
		}
		for _, c := range syms {
			if n, ok := step(k, c); ok && !seen[n] {
				seen[n] = true
				parent[n] = edge{k, c}
				queue = append(queue, n)
			}
		}
	}
	return "", false
}

type productKey struct {
	f fastState
	r int
}

// refute looks for a string accepted by fa and rejected by the regexp: first a
// byte outside A that fa does not reject (the premise of the inclusion), then a
// reachable product state that is fast accepting and regexp rejecting. It
// returns which check failed and a shortest counterexample.
func refute(d *regexpDFA, fa fastAutomaton) (kind, counterexample string) {
	type outKey struct {
		f   fastState
		out bool
	}
	s, ok := search(outKey{fa.start, false}, allBytes,
		func(k outKey, c byte) (outKey, bool) {
			n, ok := fa.step(k.f, c)
			return outKey{n, strings.IndexByte(proofAlphabet, c) < 0}, ok
		},
		func(k outKey) bool { return k.out })
	if ok {
		return "alphabet", s
	}
	s, ok = search(productKey{fa.start, 0}, []byte(proofAlphabet),
		func(k productKey, c byte) (productKey, bool) {
			n, ok := fa.step(k.f, c)
			return productKey{n, d.next(k.r, strings.IndexByte(proofAlphabet, c))}, ok
		},
		func(k productKey) bool { return fa.accept(k.f) && !d.accept[k.r] })
	if ok {
		return "inclusion", s
	}
	return "", ""
}

func TestFastPathLanguageInclusion(t *testing.T) {
	d := newRegexpDFA(t, URL)
	if kind, s := refute(d, realAutomaton); kind != "" {
		t.Fatalf("%s check failed: counterexample %q (rxURL accepts it: %v)", kind, s, rxURL.MatchString(s))
	}
	short, ok := search(fastStart, []byte(proofAlphabet), fastStep, fastAccept)
	if !ok {
		t.Fatal("fast automaton accepts nothing: the proof would be vacuous")
	}
	t.Logf("proved: L(fast) is a subset of A* and of L(rx); shortest accepted string %q", short)
}

type agreement struct {
	t              *testing.T
	d              *regexpDFA
	fastAcc, rxAcc int
}

func (a *agreement) check(s string, r int, f fastState) {
	rxModel := a.d.accept[r]
	if want := rxURL.MatchString(s); rxModel != want {
		a.t.Fatalf("regexp DFA = %v but rxURL.MatchString(%q) = %v", rxModel, s, want)
	}
	fa := fastAccept(f)
	if isPlainHostname(s) != fa {
		a.t.Fatalf("isPlainHostname(%q) disagrees with the automaton", s)
	}
	if fa {
		a.fastAcc++
		if !rxModel {
			a.t.Fatalf("fast accepts %q but rxURL rejects it", s)
		}
	}
	if rxModel {
		a.rxAcc++
	}
}

func (a *agreement) walk(alphabet string, buf []byte, maxLen int, r int, f fastState) {
	if len(buf) > 0 {
		a.check(string(buf), r, f)
	}
	if len(buf) == maxLen {
		return
	}
	for i := 0; i < len(alphabet); i++ {
		c := alphabet[i]
		nf, _ := fastStep(f, c)
		a.walk(alphabet, append(buf, c), maxLen, a.d.next(r, strings.IndexByte(proofAlphabet, c)), nf)
	}
}

func (a *agreement) vacuous() bool { return a.rxAcc == 0 || a.fastAcc == 0 }

func TestFastPathModelsAgree(t *testing.T) {
	d := newRegexpDFA(t, URL)

	// Letters of both cases, hex and non-hex letters, 'w' for the "www." branch,
	// digits that matter to the IP alternative, and the two punctuation symbols.
	const rep = "afwWZe012359-."
	maxLen, random := 5, 200000
	if longRun() {
		maxLen, random = 7, 2000000
	}
	a := &agreement{t: t, d: d}
	a.walk(rep, make([]byte, 0, maxLen), maxLen, 0, fastStart)
	t.Logf("exhaustive over %d symbols, length 1..%d: regexp accepts %d, fast accepts %d", len(rep), maxLen, a.rxAcc, a.fastAcc)
	if a.vacuous() {
		t.Fatal("cross-check is vacuous")
	}

	rng := rand.New(rand.NewSource(1))
	a = &agreement{t: t, d: d}
	for i := 0; i < random; i++ {
		var b []byte
		for n := 1 + rng.Intn(40); n > 0; n-- {
			switch x := rng.Intn(100); {
			case x < 15:
				b = append(b, '.')
			case x < 28:
				b = append(b, '-')
			default:
				b = append(b, proofAlphabet[rng.Intn(62)])
			}
		}
		r, f := 0, fastStart
		for _, c := range b {
			r = d.next(r, strings.IndexByte(proofAlphabet, c))
			f, _ = fastStep(f, c)
		}
		a.check(string(b), r, f)
	}
	t.Logf("random over 64 symbols, length <= 40: %d strings, regexp accepts %d, fast accepts %d", random, a.rxAcc, a.fastAcc)
	if a.vacuous() {
		t.Fatal("random cross-check is vacuous")
	}
}

// withStep and withAccept derive an automaton from the real one by replacing
// its transition or its accepting predicate; editAccept rewrites the state
// just before the real predicate looks at it.
func withStep(f func(fastState, byte) (fastState, bool)) fastAutomaton {
	return fastAutomaton{start: fastStart, step: f, accept: fastAccept}
}

func withAccept(f func(fastState) bool) fastAutomaton {
	return fastAutomaton{start: fastStart, step: fastStep, accept: f}
}

func editAccept(edit func(*fastState)) fastAutomaton {
	return withAccept(func(s fastState) bool { edit(&s); return fastAccept(s) })
}

func TestFastPathMutants(t *testing.T) {
	d := newRegexpDFA(t, URL)
	mutants := []struct {
		name string
		kind string
		fa   fastAutomaton
	}{
		{"TLD may contain digits", "inclusion", withStep(func(s fastState, c byte) (fastState, bool) {
			if c >= '0' && c <= '9' {
				c = 'a'
			}
			return fastStep(s, c)
		})},
		{"hyphen runs of three allowed", "inclusion", withStep(func(s fastState, c byte) (fastState, bool) {
			n, ok := fastStep(s, c)
			n.hy2Bad = false
			return n, ok
		})},
		{"one-character first label with three or more labels", "inclusion", editAccept(func(s *fastState) { s.firstB = true })},
		{"drop the TLD letters-only rule", "inclusion", editAccept(func(s *fastState) { s.nonLetter = false })},
		{"drop the second-to-last label rule", "inclusion", editAccept(func(s *fastState) { s.prevOK = true })},
		{"drop the middle label hyphen rule", "inclusion", editAccept(func(s *fastState) { s.midBad = false })},
		{"two-label first label may have hyphen runs of any length", "inclusion", editAccept(func(s *fastState) { s.firstA = true })},
		{"underscore counts as alphanumeric after the first byte", "alphabet", withStep(func(s fastState, c byte) (fastState, bool) {
			if c == '_' && s.pos > 0 {
				c = 'a'
			}
			return fastStep(s, c)
		})},
	}
	for _, m := range mutants {
		kind, s := refute(d, m.fa)
		if kind != m.kind {
			t.Errorf("mutant %q: caught by the %q check (counterexample %q), want %q", m.name, kind, s, m.kind)
			continue
		}
		t.Logf("mutant %q: %s counterexample %q", m.name, kind, s)
	}

	// The underscore mutant accepts a whole name that rxURL rejects.
	underscore := mutants[len(mutants)-1].fa
	st := underscore.start
	for _, c := range []byte("ab_.com") {
		st, _ = underscore.step(st, c)
	}
	if !underscore.accept(st) || rxURL.MatchString("ab_.com") {
		t.Error(`the underscore mutant should accept "ab_.com", which rxURL rejects`)
	}
}

// checkPreconditions searches the product of fa with a tracker of three facts
// and returns a shortest accepted string that has fewer than four bytes, no dot
// or a leading dot. Together with the alphabet search of refute, this decides
// those facts for all lengths without trusting the meaning of the state fields.
func checkPreconditions(fa fastAutomaton) (string, bool) {
	type tracked struct {
		f       fastState
		sawDot  bool
		leadDot bool
		n       uint8
	}
	return search(tracked{f: fa.start}, allBytes,
		func(k tracked, c byte) (tracked, bool) {
			nf, ok := fa.step(k.f, c)
			return tracked{nf, k.sawDot || c == '.', k.leadDot || (k.n == 0 && c == '.'), min(k.n+1, 4)}, ok
		},
		func(k tracked) bool { return fa.accept(k.f) && (!k.sawDot || k.leadDot || k.n < 4) })
}

func TestFastPathPreconditions(t *testing.T) {
	if s, bad := checkPreconditions(realAutomaton); bad {
		t.Fatalf("accepted %q is shorter than four bytes, has no dot or starts with a dot", s)
	}

	// The inclusion theorem cannot see these mutants, because rxURL accepts
	// "aaaa" and "a.a"; only the tracker can.
	for _, m := range []struct {
		name string
		fa   fastAutomaton
	}{
		{"drop the contains-a-dot requirement", withAccept(func(s fastState) bool {
			return s.done == 0 && !s.dead && s.total >= 4 && s.pos != 0 && s.run == 0 && !s.nonLetter || fastAccept(s)
		})},
		{"drop the four-byte minimum", editAccept(func(s *fastState) { s.total = 4 })},
	} {
		s, bad := checkPreconditions(m.fa)
		if !bad {
			t.Errorf("precondition mutant %q was not detected", m.name)
			continue
		}
		t.Logf("precondition mutant %q: counterexample %q", m.name, s)
	}

	check := func(s string) {
		t.Helper()
		if len(s) < 4 || s[0] == '.' || !strings.Contains(s, ".") || strings.Contains(s, ":") {
			t.Fatalf("accepted %q violates the length, leading dot, dot or colon property", s)
		}
		u, err := url.Parse(s)
		if err != nil {
			t.Fatalf("url.Parse(%q) failed: %v", s, err)
		}
		if u.Scheme != "" || u.Opaque != "" || u.Host != "" || u.Path != s || u.RawQuery != "" || u.Fragment != "" {
			t.Fatalf("url.Parse(%q) = %+v, want only Path == input", s, u)
		}
	}

	// url.Parse on every accepted string up to a length bound.
	walked := 0
	var walk func(alphabet string, buf []byte, maxLen int, f fastState)
	walk = func(alphabet string, buf []byte, maxLen int, f fastState) {
		if fastAccept(f) {
			walked++
			check(string(buf))
		}
		if len(buf) == maxLen {
			return
		}
		for i := 0; i < len(alphabet); i++ {
			if n, ok := fastStep(f, alphabet[i]); ok {
				walk(alphabet, append(buf, alphabet[i]), maxLen, n)
			}
		}
	}
	walk("a0-.", nil, 12, fastStart)
	walk("afwZ09-.", nil, 6, fastStart)
	if walked == 0 {
		t.Fatal("no accepted string was walked")
	}

	// The guards of IsURL that are not regular still win: a string the fast
	// automaton accepts but the original rejects for its size is rejected.
	long := strings.Repeat("a", maxURLRuneCount) + ".com"
	if !isPlainHostname(long) || utf8.RuneCountInString(long) < maxURLRuneCount {
		t.Fatal("sanity: the long name is in L(fast) and over the limit")
	}
	if IsURL(long) || isURLSlow(long) {
		t.Fatal("IsURL accepted a name longer than the rune limit")
	}
	for _, s := range []string{"", "a", "a.b", ".a.bc", ".abc"} {
		if IsURL(s) || isURLSlow(s) {
			t.Fatalf("a guard-rejected string %q was accepted", s)
		}
	}
}
