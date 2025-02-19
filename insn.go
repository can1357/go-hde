package hde

import (
	"github.com/can1357/go-hde/internal/bitfield"
)

// Instruction flags
type Flag uint32

const (
	IsModRM    Flag = 0x00000001 // Indicates ModRM byte present. C: F_MODRM
	IsSIB      Flag = 0x00000002 // Indicates SIB byte present. C: F_SIB
	HasImm8    Flag = 0x00000004 // Indicates immediate value is 8 bits. C: F_IMM8
	HasImm16   Flag = 0x00000008 // Indicates immediate value is 16 bits. C: F_IMM16
	HasImm32   Flag = 0x00000010 // Indicates immediate value is 32 bits. C: F_IMM32
	HasImm64   Flag = 0x00000020 // Indicates immediate value is 64 bits. C: F_IMM64
	Has2Imm16  Flag = 0x00000020 // Indicates two immediate values are 16 bits. C: F_2IMM16
	HasDisp8   Flag = 0x00000040 // Indicates displacement value is 8 bits. C: F_DISP8
	HasDisp16  Flag = 0x00000080 // Indicates displacement value is 16 bits. C: F_DISP16
	HasDisp32  Flag = 0x00000100 // Indicates displacement value is 32 bits. C: F_DISP32
	IsRelative Flag = 0x00000200 // Indicates relative addressing. C: F_RELATIVE

	prefixSetShift = 10

	NotPrefixed Flag = Flag(1) << (prefixSetShift + PreNone)     // Indicates no prefix present.
	HasRepNZ    Flag = Flag(1) << (prefixSetShift + PreRepNZ)    // Indicates REPNZ prefix present. C: p_rep & F_REPNZ
	HasRep      Flag = Flag(1) << (prefixSetShift + PreRep)      // Indicates REP prefix present. C: p_rep & F_REPX
	HasOpSize   Flag = Flag(1) << (prefixSetShift + PreOpSize)   // Indicates operand size prefix present. C: p_66 & F_PREFIX_66
	HasAddrSize Flag = Flag(1) << (prefixSetShift + PreAddrSize) // Indicates address size prefix present. C: p_67 & F_PREFIX_67
	HasLock     Flag = Flag(1) << (prefixSetShift + PreLock)     // Indicates LOCK prefix present. C: p_lock & F_PREFIX_LOCK
	HasREX      Flag = Flag(1) << (prefixSetShift + PreREX)      // Indicates REX prefix present. C: rex_* & F_PREFIX_REX
	HasSegCS    Flag = Flag(1) << (prefixSetShift + PreSegCS)    // Indicates CS segment prefix. C: p_seg
	HasSegSS    Flag = Flag(1) << (prefixSetShift + PreSegSS)    //	 Indicates SS segment prefix. C: p_seg
	HasSegDS    Flag = Flag(1) << (prefixSetShift + PreSegDS)    // Indicates DS segment prefix. C: p_seg
	HasSegES    Flag = Flag(1) << (prefixSetShift + PreSegES)    // Indicates ES	 segment prefix. C: p_seg
	HasSegFS    Flag = Flag(1) << (prefixSetShift + PreSegFS)    // Indicates FS segment prefix. C: p_seg
	HasSegGS    Flag = Flag(1) << (prefixSetShift + PreSegGS)    // Indicates GS segment prefix. C: p_seg
)

// Prefixes returns the set of prefixes present in the instruction
func (f Flag) Prefixes() PrefixSet {
	return PrefixSet(f >> prefixSetShift)
}

// AddPrefixes returns a new flag with the given prefixes added
func (f Flag) AddPrefixes(ps PrefixSet) Flag {
	return f | (Flag(ps) << prefixSetShift)
}

// WithPrefixes returns a new flag with the given prefixes added
func (f Flag) WithPrefixes(ps PrefixSet) Flag {
	f &= (1 << prefixSetShift) - 1 // Clear the prefix bits
	return f.AddPrefixes(ps)
}

// Segment returns the segment prefix of the instruction
func (f Flag) Segment() Segment {
	return f.Prefixes().Segment()
}

// String returns the string representation of the flags
func (f Flag) String() string {
	return flagFmt.Format(f)
}

var flagFmt = bitfield.NewFormatter(map[Flag]string{
	IsModRM:     "ModRM",
	IsSIB:       "SIB",
	HasImm8:     "Imm8",
	HasImm16:    "Imm16",
	HasImm32:    "Imm32",
	HasImm64:    "Imm64",
	HasDisp8:    "Disp8",
	HasDisp16:   "Disp16",
	HasDisp32:   "Disp32",
	IsRelative:  "Relative",
	HasSegCS:    "CS",
	HasSegSS:    "SS",
	HasSegDS:    "DS",
	HasSegES:    "ES",
	HasSegFS:    "FS",
	HasSegGS:    "GS",
	NotPrefixed: "",
	HasRepNZ:    "RepNZ",
	HasRep:      "Rep",
	HasOpSize:   "OpSize",
	HasAddrSize: "AddrSize",
	HasLock:     "Lock",
})

// Insn represents a decoded x86 instruction
type Insn struct {
	Flags   Flag    // Instruction flags indicating prefixes and operand types
	Length  uint8   // Length of the instruction
	Opcode  uint8   // Primary opcode byte
	Opcode2 uint8   // Secondary opcode byte (for 0F-prefixed instructions)
	REX     REX     // REX prefix byte (64-bit mode only)
	ModRM   ModRM   // ModR/M byte
	SIB     SIB     // SIB byte
	Imm     Literal // Immediate value
	Disp    Literal // Displacement value
}

// Len returns the length of the instruction
func (insn *Insn) Len() uint8 {
	return insn.Length
}

// SegmentPrefix returns the segment override prefix byte, if any
func (insn *Insn) SegmentPrefix() byte {
	return insn.Flags.Segment().Prefix()
}

// RepPrefix returns the REP/REPNZ prefix byte, if any
func (insn *Insn) RepPrefix() byte {
	if insn.Flags&HasRep != 0 {
		return PRE_REPX
	}
	if insn.Flags&HasRepNZ != 0 {
		return PRE_REPNZ
	}
	return 0
}

// LockPrefix returns the LOCK prefix byte, if present
func (insn *Insn) LockPrefix() byte {
	if insn.Flags&HasLock != 0 {
		return PRE_LOCK
	}
	return 0
}

// OpSizePrefix returns the operand size override prefix byte, if present
func (insn *Insn) OpSizePrefix() byte {
	if insn.Flags&HasOpSize != 0 {
		return PRE_OP_SIZE
	}
	return 0
}

// AddrSizePrefix returns the address size override prefix byte, if present
func (insn *Insn) AddrSizePrefix() byte {
	if insn.Flags&HasAddrSize != 0 {
		return PRE_ADDR_SIZE
	}
	return 0
}

// IsJCC returns true if this is a conditional jump instruction
func (insn *Insn) IsJCC() bool {
	if insn.Opcode&0xF0 == 0x70 {
		return true
	}
	if insn.Opcode == 0x0F && insn.Opcode2&0xF0 == 0x80 {
		return true
	}
	return false
}

// IsJMP returns true if this is an unconditional jump instruction
func (insn *Insn) IsJMP() bool {
	if insn.Opcode == 0xE9 || insn.Opcode == 0xEB {
		return true
	}
	return false
}

// IsRET returns true if this is a return instruction
func (insn *Insn) IsRET() bool {
	if insn.Opcode == 0xC3 || insn.Opcode == 0xC2 {
		return true
	}
	return false
}

// IsCALL returns true if this is a call instruction
func (insn *Insn) IsCALL() bool {
	if insn.Opcode == 0xE8 || insn.Opcode == 0xFF || insn.Opcode == 0x15 {
		return true
	}
	return false
}

// IsINT returns true if this is an interrupt instruction
func (insn *Insn) IsINT() bool {
	if insn.Opcode == 0xCD || insn.Opcode == 0xCE || insn.Opcode == 0xCF || insn.Opcode == 0xCC {
		return true
	}
	return false
}
