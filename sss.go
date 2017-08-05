// Package sss implements Shamir secret sharing over GF(256). The API exposes
// two kinds of functions: functions for "shares" and functions for "keyshares".
//
// Both will split and recombine secret strings of data with a certain
// threshold, but when using normal shares, the secret is first encapsulated in
// an AEAD crypto_secretbox (Salsa20/Poly1305 from tweetnacl). This provides
// cryptographic integrity and prevents tampering with the shares. So for
// splitting a regular secret string, you should just use CreateShares and
// CombineShares.
//
// However, CreateShares takes 64 bytes and produces shares that are 113 bytes
// long. If this is not suitable for you, you can choose to use CreateKeyshares.
// This function takes 32 bytes, and produces shares of just 33 bytes long. The
// catch is that you can *only* use this for sharing cryptographic keys. In
// other words: Any data that is shared by CreateKeyshares has to be uniformly
// random, otherwise it may be possible for share-holders to tamper with their
// shares in order to craft a different secret.
package sss

// #include "sss.h"
//
// /* There seems to be a anomaly in the CGo setup which causes weird typing
//  * issues with C types that are annotated as `const`. Passing `const` values
//  * to C function directly from Go code seems to be something that the CGo
//  * compiler cannot really handle. So we therefore need a small wrapper for
//  * `sss_combine_shares` in C space which takes the non-const value of
//  * `shares` and casts it to `(const sss_Share*)`.
//  * See also: https://stackoverflow.com/a/32940436
//  */
// int
// sss_combine_shares_go_wrapper(uint8_t *data, sss_Share *shares, uint8_t k)
// {
//     sss_combine_shares(data, shares, k);
// }
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// CreateShares splits secret `data` into `n` shares, requiring `k` shares for
// restoring the original secret.
// `data` must be a buffer of exactly 64 bytes.
// `n` and `k` must be numbers from 1 to 255 (inclusive).
// `k` may not be larger than `n`, as this would make it impossible to
// restore the secret.
//
// This function returns a tuple `(shares, err)`. The caller must check if
// `err` is not `nil`, as this indicates an error. If (and only if) `err` is
// `nil`, `shares` will be a slice of share bufs which are each exactly 113
// bytes long.
func CreateShares(data []byte, count int, threshold int) ([][]byte, error) {
	if len(data) != C.sss_MLEN {
		msg := fmt.Sprintf("`data` must be %d bytes long", C.sss_MLEN)
		return nil, errors.New(msg)
	}
	if err := checkNK(count, threshold); err != nil {
		return nil, err
	}

	// Convert n and k to bytes
	var ctyN, ctyK C.uint8_t = C.uint8_t(count), C.uint8_t(threshold)

	// Create a temporary buffer to hold the shares
	cShares := make([]byte, count*C.sizeof_sss_Share)

	// Create the shares
	C.sss_create_shares(
		(*C.sss_Share)(unsafe.Pointer(&cShares[0])),
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		ctyN, ctyK)

	// Move the shares into a Go-friendly slice of slices
	shares := make([][]byte, count)
	for i := 0; i < count; i++ {
		shares[i] = cShares[i*C.sizeof_sss_Share : (i+1)*C.sizeof_sss_Share]
	}

	return shares, nil
}

// CombineShares to combine the shares in `serialized_shares`. Each of the
// shares passed to `CombineShares`, must be exactly 113 bytes long.
// This funtion returns a tuple `(data, err)`. The caller must check if `err`
// is not `nil`, as this indicates an error. If `err` is `nil`, `data` may be
// a slice containing the original data. If it was impossible to restore a
// sensible secret from the provided shares, `data` will be `nil`. (In this
// case, the function returns `(nil, nil)`).
func CombineShares(shares [][]byte) ([]byte, error) {
	// Check the lengths of the shares
	for i, share := range shares {
		if len(share) != C.sss_SHARE_LEN {
			msg := fmt.Sprintf("share %d has an invalid length", i)
			return nil, errors.New(msg)
		}
	}

	// Check `n` and `k` parameters
	k := len(shares)
	if err := checkCombineK(k); err != nil {
		return nil, err
	}

	// Create a temporary buffer to hold the shares
	cShares := make([]byte, k*C.sss_SHARE_LEN)

	// Memcpy the share into our shares buffer
	for i, share := range shares {
		copy(cShares[i*C.sss_SHARE_LEN:(i+1)*C.sss_SHARE_LEN], share[:])
	}

	// Create a new slice to store the restored data in
	data := make([]byte, C.sss_MLEN)

	// Convert k to uint8_t
	ctyK := C.uint8_t(k)

	// Combine the shares to restore the secret
	ret, err := C.sss_combine_shares_go_wrapper(
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		(*C.sss_Share)(unsafe.Pointer(&cShares[0])),
		ctyK)
	if err != nil {
		return nil, err
	}

	// If recombination failed, return `nil` w/o error
	if ret != 0 {
		return nil, nil
	}
	return data, nil
}
