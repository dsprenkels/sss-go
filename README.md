# Shamir secret sharing with Go

[![Build Status](https://travis-ci.org/dsprenkels/sss-go.svg?branch=master)](https://travis-ci.org/dsprenkels/sss-go)

`sss-go` contains Go bindings for my [Shamir secret sharing library][sss].
This library allows users to split secret data into a number of different
shares. With the possession of some or all of these shares, the original secret
can be restored.

An example use case is a beer brewery which has a vault which contains their
precious super secret recipe. The 5 board members of this brewery do not trust
all the others well enough that they won't secretly break into the vault and
sell the recipe to a competitor. So they split the code into 5 shares, and
allow 4 shares to restore the original code. Now they are sure that the
majority of the staff will know when the vault is opened, but they can still
open the vault when one of the staff members is abroad or sick at home.

## Installation

```shell
go get github.com/dsprenkels/sss-go
```

## Usage

Secrets are provided as `[]byte` slices with a length of 64. Shares are
generated from secret data using `sss.CreateShares` and shares can be combined
again using the `sss.CombineShares` function. Shares are always 113 bytes long
and `sss.CombineShares` will return an error if one of the given shares is of
an invalid length.

```go
package main

import (
    "log"
    "github.com/dsprenkels/sss-go"
)

func main() {
    // Make a new slice of secret data [42, ..., 42]
    data := make([]byte, 64)
    for i, _ := range data {
        data[i] = 42
    }

    // Create 5 shares; allow 4 to restore the original data
    shares, err := sss.CreateShares(data, 5, 4)
    if err != nil {
        log.Fatalln(err)
    }

    // Permute and lose some of the shares (for demonstrational purposes)
    new_shares := make([][]byte, 4)
    new_shares[0] = shares[2]
    new_shares[1] = shares[4]
    new_shares[2] = shares[0]
    new_shares[3] = shares[3]

    // Try to restore the original secret
    restored, err := sss.CombineShares(new_shares)
    if err != nil {
        log.Fatalln(err)
    }

    log.Println(restored)
}
```

## Changelog

### Version 0.1.1

- Remove an unintended side channel which allows a participating attacker with
  access to a accurate timing channel to iteratively guess shares during the
  execution of `combine_shares`.

## Questions

Feel free to send me an email on my Github associated e-mail address.

[randombytes]: https://github.com/dsprenkels/randombytes
[sss]: https://github.com/dsprenkels/sss
