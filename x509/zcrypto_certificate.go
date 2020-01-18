package x509

import "time"

// TimeInValidityPeriod returns true if NotBefore < t < NotAfter
func (c *Certificate) TimeInValidityPeriod(t time.Time) bool {
	return c.NotBefore.Before(t) && c.NotAfter.After(t)
}
