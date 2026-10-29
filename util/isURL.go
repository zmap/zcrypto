/*
The MIT License (MIT)

Copyright (c) 2014 Alex Saskevich

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package util

import (
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	maxURLRuneCount = 2083
	minURLRuneCount = 3

	IP           = `(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))`
	URLSchema    = `((ftp|tcp|udp|wss?|https?):\/\/)`
	URLUsername  = `(\S+(:\S*)?@)`
	URLPath      = `((\/|\?|#)[^\s]*)`
	URLPort      = `(:(\d{1,5}))`
	URLIP        = `([1-9]\d?|1\d\d|2[01]\d|22[0-3])(\.(1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.([0-9]\d?|1\d\d|2[0-4]\d|25[0-4]))`
	URLSubdomain = `((www\.)|([a-zA-Z0-9]+([-_\.]?[a-zA-Z0-9])*[a-zA-Z0-9]\.[a-zA-Z0-9]+))`
)

var (
	URL   = `^` + URLSchema + `?` + URLUsername + `?` + `((` + URLIP + `|(\[` + IP + `\])|(([a-zA-Z0-9]([a-zA-Z0-9-_]+)?[a-zA-Z0-9]([-\.][a-zA-Z0-9]+)*)|(` + URLSubdomain + `?))?(([a-zA-Z\x{00a1}-\x{ffff}0-9]+-?-?)*[a-zA-Z\x{00a1}-\x{ffff}0-9]+)(?:\.([a-zA-Z\x{00a1}-\x{ffff}]{1,}))?))\.?` + URLPort + `?` + URLPath + `?$`
	rxURL = regexp.MustCompile(URL)
)

// IsURL check if the string is an URL.
// This function is (graciously) adopted from
// https://github.com/asaskevich/govalidator to avoid needing a full dependency on
// `govalidator` for the one `IsURL` function.
func IsURL(str string) bool {
	if str == "" || utf8.RuneCountInString(str) >= maxURLRuneCount || len(str) <= minURLRuneCount || strings.HasPrefix(str, ".") {
		return false
	}
	if isPlainHostname(str) {
		return true
	}
	strTemp := str
	if strings.Contains(str, ":") && !strings.Contains(str, "://") {
		// support no indicated urlscheme but with colon for port number
		// http:// is appended so url.Parse will succeed, strTemp used so it does not impact rxURL.MatchString
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

// isPlainHostname reports whether str, which has already passed the length and
// leading-dot guards of IsURL, is certainly accepted by IsURL because it is a
// plain ASCII multi-label hostname. It exists only to skip url.Parse and rxURL
// for the overwhelmingly common case of DNS names.
//
// The result is one-sided: true means IsURL would return true; false means
// "not sure" and the caller must run the full url.Parse and rxURL check.
// Anything outside the shapes below, including names that rxURL would accept,
// returns false.
//
// Derivation from rxURL. For input made only of [A-Za-z0-9.-] the scheme,
// username, port and path groups cannot match (they need one of "://", "@",
// ":", "/", "?" or "#"), and url.Parse cannot fail, never yields a Host, and
// leaves a Path that contains a dot, so only the host part decides:
//
//	[P] C [ "." TLD ] [ "." ]
//
// where C is one or more alphanumerics with hyphen runs of at most two,
// starting and ending alphanumeric (no dots), TLD is one or more letters and P
// is either empty or "[A-Za-z0-9][A-Za-z0-9-_]*[A-Za-z0-9]([-.][A-Za-z0-9]+)*"
// (the "www." and subdomain alternatives are not used here). The rules below
// each build one such match, so they are sufficient and deliberately not
// necessary:
//
//   - a trailing dot is left to the regexp (its "\.?" would accept one, but the
//     last label must then end with a letter or digit, which excludes it here);
//   - letters are ASCII letters of either case;
//   - the name has at least two labels and no empty label (so no leading or
//     doubled dot), and every label starts and ends with a letter or digit;
//   - the last label is TLD and contains letters only;
//   - with two labels, the first label is C: hyphen runs of at most two;
//   - with three or more labels, P covers the first label (at least two
//     characters, any hyphens), every middle label (hyphen runs of at most
//     one, since P continues with single-hyphen "-x" or ".x" pieces) and the
//     first character of the second-to-last label together with the dot
//     before it; C is the rest of the second-to-last label, so that label
//     needs at least two characters, an alphanumeric second character and
//     hyphen runs of at most two.
//
// The regexp imposes no per-label or per-name length cap; the overall length
// bounds are the guards in IsURL.
func isPlainHostname(str string) bool {
	dots := 0
	for i := 0; i < len(str); i++ {
		c := str[i]
		switch {
		case c == '.':
			dots++
		case c == '-' || isASCIIAlnum(c):
		default:
			return false
		}
	}
	if dots == 0 {
		return false
	}
	labels := dots + 1
	rest := str
	for idx := 0; idx < labels; idx++ {
		label := rest
		if j := strings.IndexByte(rest, '.'); j >= 0 {
			label, rest = rest[:j], rest[j+1:]
		}
		if len(label) == 0 || !isASCIIAlnum(label[0]) || !isASCIIAlnum(label[len(label)-1]) {
			return false
		}
		switch {
		case idx == labels-1:
			for j := 0; j < len(label); j++ {
				if !isASCIILetter(label[j]) {
					return false
				}
			}
		case labels == 2:
			if maxHyphenRun(label) > 2 {
				return false
			}
		case idx == 0:
			if len(label) < 2 {
				return false
			}
		case idx == labels-2:
			if len(label) < 2 || !isASCIIAlnum(label[1]) || maxHyphenRun(label) > 2 {
				return false
			}
		default:
			if maxHyphenRun(label) > 1 {
				return false
			}
		}
	}
	return true
}

func isASCIILetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isASCIIAlnum(c byte) bool {
	return isASCIILetter(c) || c >= '0' && c <= '9'
}

// maxHyphenRun returns the length of the longest run of '-' in s.
func maxHyphenRun(s string) int {
	best, run := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			run++
			if run > best {
				best = run
			}
		} else {
			run = 0
		}
	}
	return best
}
