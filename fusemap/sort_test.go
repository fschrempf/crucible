// crucible
// One-Time-Programmable (OTP) fusing tool
//
// Copyright (c) WithSecure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package fusemap

import (
	"testing"
)

func TestSort(t *testing.T) {
	y := `
---
reference: test
driver: nvmem-imx-ocotp
bank_size: 8
registers:
  REG1:
    bank: 0
    word: 0
    fuses:
      OTP1:
        offset: 0
        len: 32
      OTP2:
        offset: 0
        len: 8
      OTP3:
        offset: 8
        len: 16
  REG2:
    bank: 0
    word: 1
  REG3:
    bank: 0
    word: 2
...
`

	f, err := Parse([]byte(y), nil)

	if err != nil {
		t.Fatal(err)
	}

	exp := []string{"REG1", "REG2", "REG3"}

	for i, reg := range f.RegistersByReadAddress() {
		if exp[i] != reg.Name {
			t.Errorf("unexpected order, %s != %s", reg.Name, exp[i])
		}
	}

	for i, reg := range f.RegistersByWriteAddress() {
		if exp[i] != reg.Name {
			t.Errorf("unexpected order, %s != %s", reg.Name, exp[i])
		}
	}

	exp = []string{"OTP1", "OTP2", "OTP3"}

	for i, fuse := range f.Registers["REG1"].FusesByOffset() {
		if exp[i] != fuse.Name {
			t.Errorf("unexpected order, %s != %s", fuse.Name, exp[i])
		}
	}
}
