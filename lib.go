package sss

// #include "sss.h"
// #include "serialize.h"
import "C"

import (
    "crypto/rand"
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
// `err` is not `nil`, as this indicates an error. If `err` is not `nil`,
// `shares` will be a slice of share bufs which are each exactly 113 bytes long.
func CreateShares(data []byte, n int, k int) ([][]byte, error) {
    if len(data) != C.sss_MLEN {
        msg := fmt.Sprintf("`data` must be %d bytes long", C.sss_MLEN)
        return nil, errors.New(msg)
    }
    if n < 1 || n > 255 {
        msg := fmt.Sprintf("`n` must be in `[1..255]` (is %d)", n)
        return nil, errors.New(msg)
    }
    if k < 1 || k > n {
        msg := fmt.Sprintf("`k` must be in `[1..n]` (is %d and n = %d)", k, n)
        return nil, errors.New(msg)
    }

    // Convert n and k to bytes
    var cty_n, cty_k C.uint8_t = C.uint8_t(n), C.uint8_t(k)

    // Create a temporary buffer to hold the shares
    shares := make([]byte, n * C.sizeof_sss_Share)

    // Generate a random key
    var random_bytes [32]byte;
    _, rand_err := rand.Read(random_bytes[:])
    if rand_err != nil {
        return nil, rand_err
    }

    // Create the shares
    C.sss_create_shares(
        (*C.sss_Share)(unsafe.Pointer(&shares[0])),
        (*C.uint8_t)(unsafe.Pointer(&data[0])),
        cty_n, cty_k,
        (*C.uint8_t)(unsafe.Pointer(&random_bytes[0])))

    // Serialize the shares into a Go-friendly slice of slices
    serialized_shares := make([][]byte, n)
    for i := 0; i < n; i += 1 {
        serialized_shares[i] = make([]byte, C.sss_SHARE_SERIALIZED_LEN)
        C.sss_serialize_share(
            (*C.uint8_t)(unsafe.Pointer(&serialized_shares[i][0])),
            (*C.sss_Share)(unsafe.Pointer(&shares[i*C.sizeof_sss_Share])))
    }

    return serialized_shares, nil
}


// Tries to combine the shares in `serialized_shares`. Each of the shares
// passed to `CombineShares`, must be exactly 113 bytes long.
// This funtion returns a tuple `(data, err)`. The caller must check if `err`
// is not `nil`, as this indicates an error. If `err` is `nil`, `data` may be
// a slice containing the original data. If it was impossible to restore a
// sensible secret from the provided shares, `data` will be `nil`. (In this
// case, the function returns `(nil, nil)`).
func CombineShares(serialized_shares [][]byte) ([]byte, error) {
    k := len(serialized_shares)
    if k < 1 {
        return nil, errors.New("input slice was empty")
    }
    if k > 254 {
        msg := fmt.Sprintf("too many input slices supplied (%d)", k)
        return nil, errors.New(msg)
    }

    // Create a temporary buffer to hold the shares
    shares := make([]byte, k * C.sizeof_sss_Share)

    for i, share := range serialized_shares {
        if len(share) != C.sss_SHARE_SERIALIZED_LEN {
            msg := fmt.Sprintf("share %d has an invalid length", i)
            return nil, errors.New(msg)
        }
        // Decode the share
        C.sss_unserialize_share(
            (*C.sss_Share)(unsafe.Pointer(&shares[i*C.sizeof_sss_Share])),
            (*C.uint8_t)(unsafe.Pointer(&serialized_shares[i][0])))

    }

    // Create a new slice to store the restored data in
    data := make([]byte, C.sss_MLEN)

    // Convert k to uint8_t
    cty_k := C.uint8_t(k)

    // Combine the shares to restore the secret
    ret, err := C.sss_combine_shares(
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
