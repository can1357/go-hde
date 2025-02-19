package bitfield

import (
	"fmt"
	"math/bits"
	"reflect"
	"strconv"
	"strings"
	"unsafe"
)

// intLike is a constraint interface for 32-bit or smaller integer types
type intLike interface {
	~int8 | ~uint8 | ~int16 | ~uint16 | ~int32 | ~uint32 | ~int64 | ~uint64 | ~int | ~uint
}

// Formatter formats integer flag values as strings
type Formatter[T intLike] struct {
	typeName  string     // Name of the flag type without package prefix
	bitNames  [32]string // Names of individual flag bits
	valueMask uint64     // Mask of bits to include in output
	knownMask uint64     // Mask of bits that have defined names
}

// NewFormatter creates a new formatter for the given flag type and bit names
func NewFormatter[T intLike](names map[T]string) (ff *Formatter[T]) {
	ff = &Formatter[T]{
		typeName:  reflect.TypeOf(T(0)).String(),
		valueMask: ^uint64(0),
	}

	// Strip package name from type
	lastDot := strings.LastIndex(ff.typeName, ".")
	if lastDot != -1 {
		ff.typeName = ff.typeName[lastDot+1:]
	}

	// Process flag names
	for flag, name := range names {
		if name == "" {
			for u := uint64(flag); u != 0; {
				bit := bits.TrailingZeros64(u)
				u &= ^(uint64(1) << bit)
				ff.valueMask &^= uint64(1) << bit
			}
			continue
		}

		if n := bits.OnesCount64(uint64(flag)); n != 1 {
			panic(fmt.Sprintf("flag %x (%s) has %d bits set", uint64(flag), name, n))
		}
		idx := bits.TrailingZeros64(uint64(flag))
		if ff.bitNames[idx] != "" {
			panic(fmt.Sprintf("flag %x (%s) has multiple names", flag, name))
		}
		ff.knownMask |= uint64(flag)
		ff.bitNames[idx] = name
	}
	return
}

// Format converts a flag value to its string representation.
// For a single known bit, returns just that flag's name.
// For multiple bits, returns names joined with '|'.
// Unknown bits are formatted as a hex value.
// Returns "None" if no bits are set.
func (ff *Formatter[T]) Format(f T) string {
	known := uint64(f) & ff.valueMask
	if known == 0 { // None
		return "None"
	}

	unknown := known & ^ff.knownMask
	known ^= unknown

	if known == 0 { // No known bits, only unrecognized.
		return fmt.Sprintf("%s(0x%x)", ff.typeName, unknown)
	}
	if unknown == 0 && known&(known-1) == 0 { // Single known bit.
		return ff.bitNames[bits.TrailingZeros64(known)]
	}

	// Render known bits
	result := make([]byte, 0, 128)
	for u := known; u != 0; {
		bit := bits.TrailingZeros64(u)
		u &= ^(uint64(1) << bit)
		if len(result) > 0 {
			result = append(result, '|')
		}
		result = append(result, ff.bitNames[bit]...)
	}

	// Render unknown bits
	if unknown != 0 {
		if len(result) > 0 {
			result = append(result, '|')
		}
		result = append(result, ff.typeName...)
		result = append(result, "(0x"...)
		result = strconv.AppendUint(result, uint64(unknown), 16)
		result = append(result, ')')
	}
	return unsafe.String(unsafe.SliceData(result), len(result))
}
