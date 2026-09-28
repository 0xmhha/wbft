// Copyright 2014 The go-ethereum Authors
// Copyright 2026 The wbft Authors
// This file is part of wbft.
//
// wbft is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// wbft is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
// more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with wbft. If not, see <http://www.gnu.org/licenses/>.
//
// The key file format and its reader follow LoadECDSA, readASCII and
// checkKeyFileEnd of crypto/crypto.go of go-ethereum as vendored in
// go-stablenet (commit 740526d03).

package privval

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/0xmhha/wbft/crypto/ecdsa"
)

// Errors of the key file.
var (
	ErrKeyFileShort = errors.New("privval: key file too short, want 64 hex characters")
	ErrKeyFileLong  = errors.New("privval: key file too long, want 64 hex characters")
	ErrKeyFileHex   = errors.New("privval: invalid hex data for private key")
)

// ParseKeyFile reads a node key file of go-stablenet: 64 hex characters of
// the secp256k1 secret key, followed by at most two newline characters. It
// returns the 32-byte secret key.
func ParseKeyFile(data []byte) ([]byte, error) {
	r := bufio.NewReader(bytes.NewReader(data))
	buf := make([]byte, 64)
	n, err := readASCII(buf, r)
	if err != nil {
		return nil, err
	}
	if n != len(buf) {
		return nil, ErrKeyFileShort
	}
	if err := checkKeyFileEnd(r); err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(string(buf))
	if err != nil {
		var byteErr hex.InvalidByteError
		if errors.As(err, &byteErr) {
			return nil, fmt.Errorf("%w: invalid hex character %q in private key", ErrKeyFileHex, byte(byteErr))
		}
		return nil, ErrKeyFileHex
	}
	if _, err := ecdsa.PrivateKeyFromBytes(key); err != nil {
		return nil, err
	}
	return key, nil
}

// readASCII reads into buf, stopping when the buffer is full or when a
// non-printable control character is encountered.
func readASCII(buf []byte, r *bufio.Reader) (n int, err error) {
	for ; n < len(buf); n++ {
		buf[n], err = r.ReadByte()
		switch {
		case err == io.EOF || buf[n] < '!':
			return n, nil
		case err != nil:
			return n, err
		}
	}
	return n, nil
}

// checkKeyFileEnd skips over additional newlines at the end of a key file.
func checkKeyFileEnd(r *bufio.Reader) error {
	for i := 0; ; i++ {
		b, err := r.ReadByte()
		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return err
		case b != '\n' && b != '\r':
			return fmt.Errorf("privval: invalid character %q at end of key file", b)
		case i >= 2:
			return ErrKeyFileLong
		}
	}
}

// FormatKeyFile returns the key file content of a 32-byte secret key, as
// go-stablenet writes it: 64 lowercase hex characters without a newline.
func FormatKeyFile(key []byte) []byte {
	return []byte(hex.EncodeToString(key))
}
