/*
 * ZCrypto Copyright 2017 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package zcertificate

import (
	"bufio"
	"encoding/base64"
	"encoding/pem"
	"io"
	"sync"
)

const MaxPEMEncodedBytes = 10 * 1024 * 1024

// ScannerSplitPEM is a split function for a bufio.Scanner that breaks input
// into chunks that can be handled by pem.Decode().
func ScannerSplitPEM(data []byte, atEOF bool) (int, []byte, error) {
	block, rest := pem.Decode(data)
	if block != nil {
		size := len(data) - len(rest)
		return size, data[:size], nil
	}
	return 0, nil, nil
}

// BreakPEMAsync uses a scanner to split in into decoded PEM objects, and sends
// them through out. It only returns PEM where the Type matches pemType. If
// pemType is empty, it returns PEMs of all types.
func BreakPEMAsync(out chan []byte, in io.Reader, pemType string, wg *sync.WaitGroup) error {
	defer wg.Done()
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, MaxPEMEncodedBytes), 0) // 10 MB
	scanner.Split(ScannerSplitPEM)
	for count := 0; scanner.Scan(); count++ {
		p, _ := pem.Decode(scanner.Bytes())
		if p == nil {
			continue
		}
		// When pemType is non-empty, only send matching pemType.
		if pemType != "" && p.Type != pemType {
			continue
		}
		out <- p.Bytes
	}
	return nil
}

// BreakBase64ByLineAsync reads lines from in, decodes each as base64, and sends
// them through out. It calls wg.Done() when finished.
func BreakBase64ByLineAsync(out chan []byte, in io.Reader, wg *sync.WaitGroup) error {
	defer wg.Done()
	reader := bufio.NewReader(in)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			maxDecodedLen := base64.StdEncoding.DecodedLen(len(line))
			dst := make([]byte, maxDecodedLen)

			n, decodeErr := base64.StdEncoding.Decode(dst, line)
			if decodeErr != nil {
				continue
			}
			dst = dst[0:n]
			out <- dst
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}
