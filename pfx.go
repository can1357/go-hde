package hde

import (
	"fmt"
	"iter"
	"math/bits"
)

// Instruction prefixes
const (
	PRE_SEG_CS    byte = 0x2e
	PRE_SEG_SS    byte = 0x36
	PRE_SEG_DS    byte = 0x3e
	PRE_SEG_ES    byte = 0x26
	PRE_SEG_FS    byte = 0x64
	PRE_SEG_GS    byte = 0x65
	PRE_LOCK      byte = 0xf0
	PRE_REPNZ     byte = 0xf2
	PRE_REPX      byte = 0xf3
	PRE_OP_SIZE   byte = 0x66
	PRE_ADDR_SIZE byte = 0x67
)

// Segment ID
type Segment byte

const (
	SegNone Segment = iota // No segment specified
	SegDS                  // Data segment
	SegCS                  // Code segment
	SegSS                  // Stack segment
	SegES                  // Extra segment
	SegFS                  // 4th data segment
	SegGS                  // 5th data segment
)

// segToPfxTable maps segments to their corresponding prefix opcodes
var segToPfxTable = [...]byte{
	SegDS: PRE_SEG_DS,
	SegCS: PRE_SEG_CS,
	SegSS: PRE_SEG_SS,
	SegES: PRE_SEG_ES,
	SegFS: PRE_SEG_FS,
	SegGS: PRE_SEG_GS,
}

// Prefix returns the prefix opcode for the given segment
func (p Segment) Prefix() byte {
	if int(p) >= len(segToPfxTable) {
		return 0
	}
	return segToPfxTable[p]
}

// PrefixSet is a set of prefixes
type PrefixSet uint16

const (
	psetSegMask PrefixSet = PrefixSet(1)<<PreSegDS |
		PrefixSet(1)<<PreSegCS |
		PrefixSet(1)<<PreSegSS |
		PrefixSet(1)<<PreSegES |
		PrefixSet(1)<<PreSegFS |
		PrefixSet(1)<<PreSegGS
	psetRepMask PrefixSet = PrefixSet(1)<<PreRep |
		PrefixSet(1)<<PreRepNZ
)

// Add adds a prefix to the set, clearing any conflicting prefixes.
// If adding a segment prefix, clears any existing segment prefix.
// If adding a REP/REPNZ prefix, clears any existing REP/REPNZ prefix.
func (p PrefixSet) Add(pfx PrefixID) PrefixSet {
	// If segment prefix, clear the previous segment flag
	if PreSegDS <= pfx && pfx <= PreSegGS {
		p &^= psetSegMask
	}
	// If REP or REPZ prefix, clear the previous REP or REPZ flag
	if PreRepNZ <= pfx && pfx <= PreRep {
		p &^= psetRepMask
	}
	return p | (1 << pfx)
}

// Remove removes a prefix from the set
func (p PrefixSet) Remove(pfx PrefixID) PrefixSet {
	return p &^ (1 << pfx)
}

// Has returns true if the set contains the given prefix
func (p PrefixSet) Has(pfx PrefixID) bool {
	return p&(1<<pfx) != 0
}

// FirstPrefix returns the first prefix in the set, or PfNone if empty
func (p PrefixSet) FirstPrefix() PrefixID {
	if p == 0 {
		return PreNone
	}
	bit := bits.TrailingZeros16(uint16(p))
	return PrefixID(bit)
}

// Prefixes returns an iterator over all prefixes in the set
func (p PrefixSet) Prefixes() iter.Seq[PrefixID] {
	return func(yield func(PrefixID) bool) {
		for p != 0 {
			pfx := p.FirstPrefix()
			if !yield(pfx) {
				return
			}
			p = p.Remove(pfx)
		}
	}
}

// Segment returns the segment prefix in the set, if any
func (p PrefixSet) Segment() Segment {
	p &= psetSegMask
	return p.FirstPrefix().Segment()
}

// Prefix identifiers
type PrefixID uint8

const (
	PreNone PrefixID = iota
	PreRepNZ
	PreRep
	PreOpSize
	PreAddrSize
	PreLock
	PreREX
	PreSegDS
	PreSegCS
	PreSegSS
	PreSegES
	PreSegFS
	PreSegGS
)

// PrefixToID returns the PrefixID for the given prefix opcode
func PrefixToID(op byte) PrefixID {
	return prefixTable[op]
}

var prefixTable = [256]PrefixID{
	PRE_REPX:      PreRep,
	PRE_REPNZ:     PreRepNZ,
	PRE_LOCK:      PreLock,
	PRE_SEG_CS:    PreSegCS,
	PRE_SEG_SS:    PreSegSS,
	PRE_SEG_DS:    PreSegDS,
	PRE_SEG_ES:    PreSegES,
	PRE_SEG_FS:    PreSegFS,
	PRE_SEG_GS:    PreSegGS,
	PRE_OP_SIZE:   PreOpSize,
	PRE_ADDR_SIZE: PreAddrSize,
}

// Segment returns the segment ID of the prefix
// If this is not a segment prefix, returns SegNone
func (p PrefixID) Segment() Segment {
	if PreSegDS <= p && p <= PreSegGS {
		return Segment(p-PreSegDS) + SegDS
	}
	return SegNone
}

// String returns the string representation of the prefixes
func (p PrefixID) String() string {
	if int(p) >= len(prefixNames) {
		return fmt.Sprintf("PrefixID(%d)", p)
	}
	return prefixNames[p]
}

var prefixNames = [...]string{
	PreNone:     "None",
	PreRepNZ:    "RepNZ",
	PreRep:      "Rep",
	PreOpSize:   "OpSize",
	PreAddrSize: "AddrSize",
	PreLock:     "Lock",
	PreREX:      "REX",
	PreSegDS:    "DS",
	PreSegCS:    "CS",
	PreSegSS:    "SS",
	PreSegES:    "ES",
	PreSegFS:    "FS",
	PreSegGS:    "GS",
}

// SIB represents the SIB (Scale-Index-Base) byte of an x86 instruction
type SIB uint8

// Scale returns the scale factor (0-3) from the SIB byte
func (b SIB) Scale() uint8 {
	return uint8(b) >> 6
}

// Index returns the index register (0-7) from the SIB byte
func (b SIB) Index() uint8 {
	return uint8(b&0x3f) >> 3
}

// Base returns the base register (0-7) from the SIB byte
func (b SIB) Base() uint8 {
	return uint8(b) & 7
}

func (b SIB) String() string {
	return fmt.Sprintf("SIB[scale=%d,index=%d,base=%d]", b.Scale(), b.Index(), b.Base())
}

// ModRM represents the ModR/M byte of an x86 instruction
type ModRM uint8

// Mod returns the mode (0-3) from the ModR/M byte
func (b ModRM) Mod() uint8 {
	return uint8(b) >> 6
}

// Reg returns the register operand (0-7) from the ModR/M byte
func (b ModRM) Reg() uint8 {
	return uint8(b&0x3f) >> 3
}

// RM returns the R/M operand (0-7) from the ModR/M byte
func (b ModRM) RM() uint8 {
	return uint8(b) & 7
}

func (b ModRM) String() string {
	return fmt.Sprintf("ModRM[mod=%d,reg=%d,rm=%d]", b.Mod(), b.Reg(), b.RM())
}

// REX represents the REX prefix byte of an x86-64 instruction
type REX uint8

// W returns the operand size override bit from the REX byte
func (b REX) W() uint8 {
	return uint8(b&0xf) >> 3
}

// R returns the ModR/M reg field extension from the REX byte
func (b REX) R() uint8 {
	return uint8(b&7) >> 2
}

// X returns the SIB index field extension from the REX byte
func (b REX) X() uint8 {
	return uint8(b&3) >> 1
}

// B returns the ModR/M r/m field, SIB base field, or opcode reg field extension from the REX byte
func (b REX) B() uint8 {
	return uint8(b & 1)
}

func (b REX) String() string {
	return fmt.Sprintf("REX[W=%d,R=%d,X=%d,B=%d]", b.W(), b.R(), b.X(), b.B())
}
