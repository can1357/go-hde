package hde

import (
	"errors"
	"fmt"
	"io"
)

// DecoderError is the error type for disassembly errors.
type DecoderError struct {
	inner error
}

// Error implements the error interface.
func (e *DecoderError) Error() string {
	return fmt.Sprintf("hde error: %s", e.inner.Error())
}

// Unwrap returns the underlying error.
func (e *DecoderError) Unwrap() error {
	return e.inner
}

var (
	// ErrLength is returned when there is not enough bytes to decode an instruction
	ErrLength error = &DecoderError{io.EOF}
	// ErrUnknownOpcode is returned when the opcode is not recognized
	ErrUnknownOpcode error = &DecoderError{errors.New("unknown opcode")}
	// ErrInvalidLock is returned when a LOCK prefix is used on an instruction that does not support it
	ErrInvalidLock error = &DecoderError{errors.New("invalid lock")}
	// ErrBadOperand is returned when an instruction has an invalid operand encoding
	ErrBadOperand error = &DecoderError{errors.New("bad operand")}
)

// MaxInsnLen is the maximum length of an instruction.
const MaxInsnLen = 15

// Disasm disassembles the given code into an instruction.
// It returns the instruction and an error if the code is invalid.
func (mode *Mode) Decode(code []byte) (hs Insn, err error) {
	if maxN := len(code); maxN == 0 {
		return hs, ErrLength
	} else if maxN > MaxInsnLen {
		code = code[:MaxInsnLen]
	}

	var (
		x, c, opcode uint8
		cflags       cflag
		pref         PrefixSet
		mod, reg, rm uint8
		op64         bool
	)

	p := code
	for x = 16; x > 0; x-- {
		if len(p) == 0 {
			return hs, ErrLength
		}
		c, p = p[0], p[1:]

		// If not a prefix, we're done
		pi := PrefixToID(c)
		if pi == PreNone {
			break
		}
		pref = pref.Add(pi)
	}
	hs.Flags = hs.Flags.AddPrefixes(pref)

	if pref == 0 {
		pref = pref.Add(PreNone)
	}

	if mode.long {
		if (c & 0xf0) == 0x40 {
			hs.Flags |= HasREX
			hs.REX = REX(c)
			if hs.REX.W() != 0 && len(p) > 0 && (p[0]&0xf8) == 0xb8 {
				op64 = true
			}
			if len(p) == 0 {
				return hs, ErrLength
			}
			c, p = p[0], p[1:]
			if (c & 0xf0) == 0x40 {
				return hs, ErrUnknownOpcode
			}
		}
	}

	hs.Opcode = c
	tbl := mode.table
	if c == 0x0f {
		if len(p) == 0 {
			return hs, ErrLength
		}
		c, p = p[0], p[1:]
		hs.Opcode2 = c
		tbl = tbl[mode.dtOpcodes:]
	} else if c >= 0xa0 && c <= 0xa3 {
		op64 = true
		if pref.Has(PreAddrSize) {
			pref = pref.Add(PreOpSize)
		} else {
			pref = pref.Remove(PreOpSize)
		}
	}

	opcode = c
	cflags = tbl[tbl[opcode>>2]+(opcode&3)]

	if cflags == cfError {
		return hs, ErrUnknownOpcode
	}

	x = 0
	if cflags&cfGroup != 0 {
		t := uint16(tbl[cflags&0x7f]) | uint16(tbl[cflags&0x7f+1])<<8
		cflags = uint8(t)
		x = uint8(t >> 8)
	}

	if hs.Opcode2 != 0 {
		tbl = mode.table[mode.dtPrefixes:]
		if tbl[tbl[opcode>>2]+(opcode&3)]&byte(pref) != 0 {
			return hs, ErrUnknownOpcode
		}
	}

	if cflags&cfModRM != 0 {
		if len(p) == 0 {
			return hs, ErrLength
		}
		c, p = p[0], p[1:]

		hs.Flags |= IsModRM
		hs.ModRM = ModRM(c)
		mod = hs.ModRM.Mod()
		rm = hs.ModRM.RM()
		reg = hs.ModRM.Reg()

		if x != 0 && ((x<<reg)&0x80) != 0 {
			return hs, ErrUnknownOpcode
		}

		if hs.Opcode2 == 0 && opcode >= 0xd9 && opcode <= 0xdf {
			t := opcode - 0xd9
			if mod == 3 {
				tbl = mode.table[mode.dtFPUModRM+int(t)*8:]
				t = tbl[reg] << rm
			} else {
				tbl = mode.table[mode.dtFPUReg:]
				t = tbl[t] << reg
			}
			if t&0x80 != 0 {
				return hs, ErrUnknownOpcode
			}
		}

		if pref.Has(PreLock) {
			if mod == 3 {
				return hs, ErrInvalidLock
			} else {
				op := opcode
				var end []cflag
				if hs.Opcode2 != 0 {
					tbl = mode.table[mode.dtOp2LockOk:]
					end = tbl[mode.dtOpOnlyMem-mode.dtOp2LockOk:]
				} else {
					tbl = mode.table[mode.dtOpLockOk:]
					end = tbl[mode.dtOp2LockOk-mode.dtOpLockOk:]
					op &= 0xFE
				}
				err = ErrInvalidLock
				for i := 0; i < len(end); i += 2 {
					if tbl[i] == op {
						if (tbl[i+1]<<reg)&0x80 == 0 {
							err = nil
						}
						break
					}
				}
				if err != nil {
					return
				}
			}
		}

		if hs.Opcode2 != 0 {
			switch opcode {
			case 0x20, 0x22:
				mod = 3
				if reg > 4 || reg == 1 {
					return hs, ErrBadOperand
				}
			case 0x21, 0x23:
				mod = 3
				if reg == 4 || reg == 5 {
					return hs, ErrBadOperand
				}
			}
		} else {
			switch opcode {
			case 0x8c:
				if reg > 5 {
					return hs, ErrBadOperand
				}
			case 0x8e:
				if reg == 1 || reg > 5 {
					return hs, ErrBadOperand
				}
			}
		}

		if mod == 3 {
			var it, end int
			if hs.Opcode2 != 0 {
				it = mode.dtOp2OnlyMem
				end = len(mode.table) - mode.dtOp2OnlyMem
			} else {
				it = mode.dtOpOnlyMem
				end = mode.dtOp2OnlyMem - mode.dtOpOnlyMem
			}
			for ; it < end; it += 2 {
				if tbl[it] == opcode {
					it++
					if tbl[it-1]&byte(pref) != 0 {
						if (tbl[it]<<reg)&0x80 == 0 {
							return hs, ErrBadOperand
						}
						break
					}
				}
			}
		} else if hs.Opcode2 != 0 {
			switch opcode {
			case 0x50, 0xd7, 0xf7:
				if pref.Has(PreNone) || pref.Has(PreOpSize) {
					return hs, ErrBadOperand
				}
			case 0xd6:
				if pref.Has(PreRepNZ) || pref.Has(PreRep) {
					return hs, ErrBadOperand
				}
			case 0xc5:
				return hs, ErrBadOperand
			}
		}

		if reg <= 1 {
			if opcode == 0xf6 {
				cflags |= cfImm8
			} else if opcode == 0xf7 {
				cflags |= cfImmP66
			}
		}

		var dispSize uint8
		switch mod {
		case 0:
			if pref.Has(PreAddrSize) {
				if rm == 6 {
					dispSize = 2
				}
			} else {
				if rm == 5 {
					dispSize = 4
				}
			}
		case 1:
			dispSize = 1
		case 2:
			dispSize = 2
			if !pref.Has(PreAddrSize) {
				dispSize <<= 1
			}
		}

		if mod != 3 && rm == 4 {
			if mode.long || !pref.Has(PreAddrSize) {
				hs.Flags |= IsSIB
				if len(p) == 0 {
					return hs, ErrLength
				}
				c, p = p[0], p[1:]
				hs.SIB = SIB(c)
				if hs.SIB.Base() == 5 && mod&1 == 0 {
					dispSize = 4
				}
			}
		}

		switch dispSize {
		case 1:
			hs.Flags |= HasDisp8
			if !hs.Disp.read8(&p) {
				return hs, ErrLength
			}
		case 2:
			hs.Flags |= HasDisp16
			if !hs.Disp.read16(&p) {
				return hs, ErrLength
			}
		case 4:
			hs.Flags |= HasDisp32
			if !hs.Disp.read32(&p) {
				return hs, ErrLength
			}
		}
	} else if pref.Has(PreLock) {
		return hs, ErrInvalidLock
	}

	if cflags&cfImmP66 != 0 {
		if cflags&cfRel32 != 0 {
			if pref.Has(PreOpSize) {
				hs.Flags |= IsRelative | HasImm16
				if !hs.Imm.read16(&p) {
					return hs, ErrLength
				}
				hs.Length = uint8(len(code) - len(p))
				return
			}
			cflags |= cfRel32
			cflags &= ^uint8(cfImm16 | cfImm8)
			//goto rel32_ok
		} else {
			if mode.long {
				if op64 {
					hs.Flags |= HasImm64
					if !hs.Imm.read64(&p) {
						return hs, ErrLength
					}
				} else if !pref.Has(PreOpSize) {
					hs.Flags |= HasImm32
					if !hs.Imm.read32(&p) {
						return hs, ErrLength
					}
				} else {
					cflags |= cfImm16
					//goto imm16_ok
				}
			} else {
				if pref.Has(PreOpSize) {
					hs.Flags |= HasImm16
					if !hs.Imm.read16(&p) {
						return hs, ErrLength
					}
				} else {
					hs.Flags |= HasImm32
					if !hs.Imm.read32(&p) {
						return hs, ErrLength
					}
				}
			}
		}
	}

	if cflags&cfImm16 != 0 {
		var dst *Literal
		if mode.long {
			hs.Flags |= HasImm16
			dst = &hs.Imm
		} else {
			if hs.Flags&HasImm32 != 0 {
				hs.Flags |= HasImm16
				dst = &hs.Disp
			} else if hs.Flags&HasImm16 != 0 {
				hs.Flags |= Has2Imm16
				dst = &hs.Disp
			} else {
				hs.Flags |= HasImm16
				dst = &hs.Imm
			}
		}
		if !dst.read16(&p) {
			return hs, ErrLength
		}
	}
	if cflags&cfImm8 != 0 {
		hs.Flags |= HasImm8
		if !hs.Imm.read8(&p) {
			return hs, ErrLength
		}
	}

	if cflags&cfRel32 != 0 {
		//rel32_ok:
		hs.Flags |= IsRelative | HasImm32
		if !hs.Imm.read32(&p) {
			return hs, ErrLength
		}
	} else if cflags&cfRel8 != 0 {
		hs.Flags |= IsRelative | HasImm8
		if !hs.Imm.read8(&p) {
			return hs, ErrLength
		}
	}
	hs.Length = uint8(len(code) - len(p))
	return
}
