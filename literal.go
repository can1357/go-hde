package hde

import (
	"encoding/binary"
	"fmt"
)

// Literal represents a numeric value with a specific bit width.
type Literal struct {
	Value uint64 // The actual numeric value
	Bits  uint8  // Number of bits used to represent the value
}

// Valid returns true if this literal has a non-zero bit width.
func (lit Literal) Valid() bool {
	return lit.Bits != 0
}

// Int returns the signed integer interpretation of this literal.
// Returns 0,false if the literal is invalid (has 0 bits).
// For valid literals, sign extends based on the bit width.
func (lit Literal) Int() (int64, bool) {
	if lit.Bits == 0 {
		return 0, false
	}
	u := lit.Value
	if lit.Bits == 64 {
		return int64(u), true
	}
	shift := 64 - lit.Bits
	return int64(u<<shift) >> shift, true
}

// Uint returns the unsigned integer value.
// Returns 0,false if the literal is invalid (has 0 bits).
func (lit Literal) Uint() (uint64, bool) {
	return lit.Value, lit.Bits > 0
}

// String returns a string representation of the literal.
// Shows both hex and decimal values, prefixed with bit width.
// Returns "-" for invalid literals.
func (lit Literal) String() string {
	i, ok := lit.Int()
	if !ok {
		return "-"
	}
	u, _ := lit.Uint()
	return fmt.Sprintf("i%d(0x%x / %d)", lit.Bits, u, i)
}

// read64 attempts to read a 64-bit value from the byte slice.
// Returns true and updates the slice position on success.
func (lit *Literal) read64(bb *[]byte) bool {
	buf := *bb
	if len(buf) < 8 {
		return false
	}
	lit.Bits = 64
	lit.Value = binary.LittleEndian.Uint64(buf)
	*bb = buf[8:]
	return true
}

// read32 attempts to read a 32-bit value from the byte slice.
// Returns true and updates the slice position on success.
func (lit *Literal) read32(bb *[]byte) bool {
	buf := *bb
	if len(buf) < 4 {
		return false
	}
	lit.Bits = 32
	lit.Value = uint64(binary.LittleEndian.Uint32(buf))
	*bb = buf[4:]
	return true
}

// read16 attempts to read a 16-bit value from the byte slice.
// Returns true and updates the slice position on success.
func (lit *Literal) read16(bb *[]byte) bool {
	buf := *bb
	if len(buf) < 2 {
		return false
	}
	lit.Bits = 16
	lit.Value = uint64(binary.LittleEndian.Uint16(buf))
	*bb = buf[2:]
	return true
}

// read8 attempts to read an 8-bit value from the byte slice.
// Returns true and updates the slice position on success.
func (lit *Literal) read8(bb *[]byte) bool {
	buf := *bb
	if len(buf) < 1 {
		return false
	}
	lit.Bits = 8
	lit.Value = uint64(buf[0])
	*bb = buf[1:]
	return true
}
