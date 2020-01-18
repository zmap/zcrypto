package x509

import "time"

// earlier returns the earlier of a and b
func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// later returns the later of a and b
func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// check expirations divides chains into a set of disjoint chains, containing
// current chains valid now, expired chains that were valid at some point, and
// the set of chains that were never valid.
func FilterByDate(chains []CertificateChain, now time.Time) (current, expired, never []CertificateChain) {
	for _, chain := range chains {
		if len(chain) == 0 {
			continue
		}
		leaf := chain[0]
		lowerBound := leaf.NotBefore
		upperBound := leaf.NotAfter
		for _, c := range chain[1:] {
			lowerBound = later(lowerBound, c.NotBefore)
			upperBound = earlier(upperBound, c.NotAfter)
		}
		valid := lowerBound.Before(now) && upperBound.After(now)
		wasValid := lowerBound.Before(upperBound)
		if valid && !wasValid {
			// Math/logic tells us this is impossible.
			panic("valid && !wasValid should not be possible")
		}
		if valid {
			current = append(current, chain)
		} else if wasValid {
			expired = append(expired, chain)
		} else {
			never = append(never, chain)
		}
	}
	return
}
