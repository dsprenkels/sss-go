package sss

import (
	"bytes"
	"errors"
	"math/rand"
	"testing"
	"testing/quick"
)

func makeKey(c byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = c
	}
	return key
}

func TestCreateKeyshares(t *testing.T) {
	key := makeKey(42)
	keyshares, err := CreateKeyshares(key, 5, 4)
	if err != nil {
		t.Error(err)
	}
	if len(keyshares) != 5 {
		t.Error(errors.New("expected 5 keyshares"))
	}
	for _, keyshare := range keyshares {
		if len(keyshare) != 33 {
			t.Error(errors.New("keyshare should be 33 bytes long"))
		}
	}
}

func TestCombineKeyshares(t *testing.T) {
	f := func(n, k, k2 int, keyArr [32]byte) bool {
		n, k, k2 = n&0xff, k&0xff, k2&0xff
		key := keyArr[:]

		// Unable to test if not n is not larger than k and k2
		if k > n || k2 > n || k < 1 {
			return true
		}

		keyshares, err := CreateKeyshares(key, n, k)
		if err != nil {
			t.Error(err)
		}

		// Throw some of the keyshares away
		newKeyshares := make([][]byte, k2)
		for i, idx := range rand.Perm(n)[:k2] {
			newKeyshares[i] = keyshares[idx]
		}

		// Combine the filtered keyshares
		restored, err := CombineKeyshares(newKeyshares)
		if err != nil {
			if k2 == 0 {
				return true
			}
			t.Error(err)
		}

		return (k <= k2) == bytes.Equal(key, restored)
	}

	if err := quick.Check(f, &quick.Config{MaxCountScale: 10}); err != nil {
		t.Error(err)
	}
}
