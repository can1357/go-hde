package hdeutil

import (
	"github.com/can1357/go-hde"
	"github.com/can1357/go-hde/internal/bitfield"
)

const (
	F_MODRM         = 0x00000001
	F_SIB           = 0x00000002
	F_IMM8          = 0x00000004
	F_IMM16         = 0x00000008
	F_IMM32         = 0x00000010
	F_IMM64         = 0x00000020
	F_2IMM16        = 0x00000020
	F_DISP8         = 0x00000040
	F_DISP16        = 0x00000080
	F_DISP32        = 0x00000100
	F_RELATIVE      = 0x00000200
	F_ERROR         = 0x00001000
	F_ERROR_OPCODE  = 0x00002000
	F_ERROR_LENGTH  = 0x00004000
	F_ERROR_LOCK    = 0x00008000
	F_ERROR_OPERAND = 0x00010000
	F_PREFIX_NONE   = 0x00800000
	F_PREFIX_REPNZ  = 0x01000000
	F_PREFIX_REPX   = 0x02000000
	F_PREFIX_66     = 0x04000000
	F_PREFIX_67     = 0x08000000
	F_PREFIX_LOCK   = 0x10000000
	F_PREFIX_SEG    = 0x20000000
	F_PREFIX_REX    = 0x40000000
	F_PREFIX_ANY    = 0x7f000000
)

var cgoFlagFmt = bitfield.NewFormatter[uint32](map[uint32]string{
	F_MODRM:         "ModRM",
	F_SIB:           "SIB",
	F_IMM8:          "Imm8",
	F_IMM16:         "Imm16",
	F_IMM32:         "Imm32",
	F_IMM64:         "Imm64",
	F_DISP8:         "Disp8",
	F_DISP16:        "Disp16",
	F_DISP32:        "Disp32",
	F_RELATIVE:      "Relative",
	F_ERROR:         "Error",
	F_ERROR_OPCODE:  "ErrorOpcode",
	F_ERROR_LENGTH:  "ErrorLength",
	F_ERROR_LOCK:    "ErrorLock",
	F_ERROR_OPERAND: "ErrorOperand",
	F_PREFIX_NONE:   "PrefixNone",
	F_PREFIX_REPNZ:  "PrefixRepNZ",
	F_PREFIX_REPX:   "PrefixRepX",
	F_PREFIX_66:     "Prefix66",
	F_PREFIX_67:     "Prefix67",
	F_PREFIX_LOCK:   "PrefixLock",
	F_PREFIX_SEG:    "PrefixSeg",
	F_PREFIX_REX:    "PrefixRex",
})

func FormatCgoFlags(f uint32) string {
	return cgoFlagFmt.Format(f)
}

func ToCgoFlags(f hde.Flag) (fl uint32, seg byte) {
	fl |= uint32(f) & 0x3ff // these map 1:1

	if f&hde.HasSegCS != 0 {
		seg = byte(hde.PRE_SEG_CS)
		fl |= F_PREFIX_SEG
	} else if f&hde.HasSegSS != 0 {
		seg = byte(hde.PRE_SEG_SS)
		fl |= F_PREFIX_SEG
	} else if f&hde.HasSegDS != 0 {
		seg = byte(hde.PRE_SEG_DS)
		fl |= F_PREFIX_SEG
	} else if f&hde.HasSegES != 0 {
		seg = byte(hde.PRE_SEG_ES)
		fl |= F_PREFIX_SEG
	} else if f&hde.HasSegFS != 0 {
		seg = byte(hde.PRE_SEG_FS)
		fl |= F_PREFIX_SEG
	} else if f&hde.HasSegGS != 0 {
		seg = byte(hde.PRE_SEG_GS)
		fl |= F_PREFIX_SEG
	}

	if f&hde.NotPrefixed != 0 {
		fl |= F_PREFIX_NONE
	}
	if f&hde.HasRepNZ != 0 {
		fl |= F_PREFIX_REPNZ
	}
	if f&hde.HasRep != 0 {
		fl |= F_PREFIX_REPX
	}
	if f&hde.HasOpSize != 0 {
		fl |= F_PREFIX_66
	}
	if f&hde.HasAddrSize != 0 {
		fl |= F_PREFIX_67
	}
	if f&hde.HasLock != 0 {
		fl |= F_PREFIX_LOCK
	}
	if f&hde.HasREX != 0 {
		fl |= F_PREFIX_REX
	}
	return
}
