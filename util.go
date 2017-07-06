package sss;


import (
    "errors"
    "fmt"
)


// Check if the arguments `n` and `k` are valid parameters for generating
// shares with.
func checkNK(n, k int) error {
    if n < 1 || n > 255 {
        msg := fmt.Sprintf("`n` must be in `[1..255]` (is %d)", n)
        return errors.New(msg)
    }
    if k < 1 || k > n {
        msg := fmt.Sprintf("`k` must be in `[1..n]` (is %d and n = %d)", k, n)
        return errors.New(msg)
    }
    return nil
}


func checkCombineK(k int) error {
    if k < 1 {
        return errors.New("input slice was empty")
    }
    if k > 254 {
        msg := fmt.Sprintf("too many input slices supplied (%d)", k)
        return errors.New(msg)
    }
    return nil
}
