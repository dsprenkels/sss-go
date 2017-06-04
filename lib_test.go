package sss

import (
    "bytes"
    "testing"
)


func MakeData() []byte {
    data := make([]byte, 64)
    for i, _ := range data {
        data[i] = 42
    }
    return data
}


func TestCreateShares(t *testing.T) {
    data := MakeData()
    shares, err := CreateShares(data, 5, 3)
    if err != nil {
        t.Fail()
    }
    if len(shares) != 5 {
        t.Fail()
    }
}


func TestCombineShares(t *testing.T) {
    data := MakeData()
    shares, err := CreateShares(data, 5, 3)
    if err != nil {
        t.Error()
    }
    restored, err2 := CombineShares(shares)
    if err2 != nil {
        t.Fail()
    }

    if !bytes.Equal(data, restored) {
        t.Fail()
    }
}


func TestCombineSharesFail(t *testing.T) {
    data := MakeData()
    shares, err := CreateShares(data, 5, 3)
    if err != nil {
        t.Error()
    }
    filtered_shares := make([][]byte, 2)
    filtered_shares[0], filtered_shares[1] = shares[4], shares[1]

    restored, err2 := CombineShares(filtered_shares)
    if err2 != nil {
        t.Fail()
    }
    if restored != nil {
        t.Fail()
    }
}


func BenchmarkCreateShares(b *testing.B) {
    data := MakeData()
    shares, err := CreateShares(data, 5, 3)
    if err != nil {
        b.Error()
    }
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        CombineShares(shares)
    }
}


func BenchmarkCombineShares(b *testing.B) {
    data := MakeData()
    for i := 0; i < b.N; i++ {
        CreateShares(data, 5, 3)
    }
}
