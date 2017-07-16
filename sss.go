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

// Splits secret `data` into `n` shares, requiring `k` shares for restoring
// the original secret.
// `data` must be a buffer of exactly 64 bytes.
// `n` and `k` must be numbers from 1 to 255 (inclusive).
// `k` may not be larger than `n`, as this would make it impossible to
// restore the secret.
//
// This function returns a tuple `(shares, err)`. The caller must check if
// `err` is not `nil`, as this indicates an error. If (and only if) `err` is
// `nil`, `shares` will be a slice of share bufs which are each exactly 113
// bytes long.
func CreateShares(data []byte, n int, k int) ([][]byte, error) {
	if len(data) != C.sss_MLEN {
		msg := fmt.Sprintf("`data` must be %d bytes long", C.sss_MLEN)
		return nil, errors.New(msg)
	}
	if err := checkNK(n, k); err != nil {
		return nil, err
	}

	// Convert n and k to bytes
	var cty_n, cty_k C.uint8_t = C.uint8_t(n), C.uint8_t(k)

	// Create a temporary buffer to hold the shares
	shares := make([]byte, n*C.sizeof_sss_Share)

	// Create the shares
	C.sss_create_shares(
		(*C.sss_Share)(unsafe.Pointer(&shares[0])),
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		cty_n, cty_k)

	// Move the shares into a Go-friendly slice of slices
	go_shares := make([][]byte, n)
	for i := 0; i < n; i += 1 {
		go_shares[i] = shares[i*C.sizeof_sss_Share : (i+1)*C.sizeof_sss_Share]
	}

	return go_shares, nil
}

// Tries to combine the shares in `serialized_shares`. Each of the shares
// passed to `CombineShares`, must be exactly 113 bytes long.
// This funtion returns a tuple `(data, err)`. The caller must check if `err`
// is not `nil`, as this indicates an error. If `err` is `nil`, `data` may be
// a slice containing the original data. If it was impossible to restore a
// sensible secret from the provided shares, `data` will be `nil`. (In this
// case, the function returns `(nil, nil)`).
func CombineShares(go_shares_in [][]byte) ([]byte, error) {
	// Check the lengths of the shares
	for i, share := range go_shares_in {
		if len(share) != C.sss_SHARE_LEN {
			msg := fmt.Sprintf("share %d has an invalid length", i)
			return nil, errors.New(msg)
		}
	}

	// Remove duplicate shares
	go_shares_set := make(map[[C.sss_SHARE_LEN]byte]struct{}, len(go_shares_in))
	for _, share := range go_shares_in {
		var key [C.sss_SHARE_LEN]byte
		copy(key[:], share)
		var empty struct{}
		go_shares_set[key] = empty
	}
	go_shares := make([][]byte, 0, len(go_shares_set))
	for share, _ := range go_shares_set {
		new_share := make([]byte, C.sss_SHARE_LEN)
		copy(new_share[:], share[:])
		go_shares = append(go_shares, new_share)
	}

	// Check `n` and `k` parameters
	k := len(go_shares)
	if err := checkCombineK(k); err != nil {
		return nil, err
	}

	// Create a temporary buffer to hold the shares
	shares := make([]byte, k*C.sss_SHARE_LEN)

	// Memcpy the share into our shares buffer
	for i, share := range go_shares {
		copy(shares[i*C.sss_SHARE_LEN:(i+1)*C.sss_SHARE_LEN], share[:])
	}

	// Create a new slice to store the restored data in
	data := make([]byte, C.sss_MLEN)

	// Convert k to uint8_t
	cty_k := C.uint8_t(k)

	// Combine the shares to restore the secret
	ret, err := C.sss_combine_shares_go_wrapper(
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		(*C.sss_Share)(unsafe.Pointer(&shares[0])),
		cty_k)
	if err != nil {
		return nil, err
	}

	// If recombination failed, return `nil` w/o error
	if ret != 0 {
		return nil, nil
	} else {
		return data, nil
	}
}
