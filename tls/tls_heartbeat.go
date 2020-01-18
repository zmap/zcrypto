// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
)

const (
	// Record Type
	recordTypeHeartbeat recordType = 24

	// Extension Number
	extensionHeartbeat uint16 = 15

	// Heartbeat Mode
	heartbeatModePeerAllowed    uint8 = 1
	heartbeatModePeerNotAllowed uint8 = 2

	// Heartbeat Message Types
	heartbeatTypeRequest  uint8 = 1
	heartbeatTypeResponse uint8 = 2
)

var (
	HeartbleedError = errors.New("Error after Heartbleed")
)

type Heartbleed struct {
	HeartbeatEnabled bool `json:"heartbeat_enabled"`
	Vulnerable       bool `json:"heartbleed_vulnerable"`
}

type heartbleedMessage struct {
	raw []byte
}

func (m *heartbleedMessage) marshal() []byte {
	x := []byte{1, 0, 0}
	m.raw = x
	return x
}

func (c *Conn) CheckHeartbleed(b []byte) (n int, err error) {
	if err = c.Handshake(); err != nil {
		return
	}
	if !c.heartbeat {
		return
	}
	c.in.Lock()
	defer c.in.Unlock()

	hb := heartbleedMessage{}
	hb.marshal()

	if _, err = c.writeRecord(recordTypeHeartbeat, hb.raw); err != nil {
		return 0, err
	}

	if err = c.readRecord(); err != nil {
		return 0, HeartbleedError
	}
	if c.in.err != nil {
		return 0, HeartbleedError
	}

	n, err = c.input.Read(b)
	if n != 0 {
		return n, HeartbleedError
	}
	if err != nil {
		return 0, HeartbleedError
	}
	return 0, HeartbleedError
}

func (c *Conn) GetHeartbleedLog() *Heartbleed {
	return c.heartbleedLog
}
