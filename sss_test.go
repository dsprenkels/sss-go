package sss

import (
    "bytes"
    "math/rand"
    "testing"
    "testing/quick"
)


func makeData(c byte) []byte {
    data := make([]byte, 64)
    for i, _ := range data {
        data[i] = c
    }
    return data
}


func TestCreateShares(t *testing.T) {
    data := makeData(42)
    shares, err := CreateShares(data, 5, 3)
    if err != nil {
        t.Fail()
    }
    if len(shares) != 5 {
        t.Fail()
    }
    for _, share := range shares {
        if len(share) != 113 {
            t.Fail()
        }
    }
}


func TestCombineShares(t *testing.T) {
    f := func(n, k, k2 int, dataArr [64]byte) bool {
        n, k, k2 = n & 0xff, k & 0xff, k2 & 0xff
        data := dataArr[:]

        // We can't really test anything if not n is not larger than k and k2
        if k > n || k2 > n || k < 1 {
            return true
        }

        shares, err := CreateShares(data, n, k)
        if err != nil {
            t.Error(err)
        }

        // Throw some of the shares away
        new_shares := make([][]byte, k2);
        for i, idx := range rand.Perm(n)[:k2] {
            new_shares[i] = shares[idx]
        }

        // Combine the filtered shares
        restored, err := CombineShares(new_shares)
        if err != nil {
            if k2 == 0 {
                return true
            }
            t.Error(err)
        }

        if k2 < k {
            return restored == nil
        } else {
            return bytes.Equal(data, restored)
        }
    }

    if err := quick.Check(f, &quick.Config{MaxCountScale: 10}); err != nil {
        t.Error(err)
    }
}


func BenchmarkCreateShares(b *testing.B) {
    data := makeData(42)
    for i := 0; i < b.N; i++ {
        CreateShares(data, 5, 3)
    }
}


func BenchmarkCombineShares(b *testing.B) {
    data := makeData(42)
    shares, err := CreateShares(data, 5, 3)
    if err != nil {
        b.Error()
    }
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        CombineShares(shares)
    }
}
