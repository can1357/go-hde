package cgohde64

/*
#include <stdint.h>
#include "hde64.h"
*/
import "C"

import (
	"encoding/binary"
	"unsafe"

	hde "github.com/can1357/go-hde"
	"github.com/can1357/go-hde/tests/hdeutil"
)

type CgoInsn = C.hde64s

func CgoFlags(hs *CgoInsn) uint32 {
	return uint32(hs.flags)
}

func CgoLen(hs *CgoInsn) int {
	return int(hs.len)
}

func CgoDecode(code []byte) (hs CgoInsn) {
	var buf [15]byte
	copy(buf[:], code)
	hs.len = C.uint8_t(C.hde64_disasm(unsafe.Pointer(&buf[0]), &hs))
	return
}

func GoToCGo(dec *hde.Insn, org *CgoInsn) (h CgoInsn) {
	fl, seg := hdeutil.ToCgoFlags(dec.Flags)
	h.flags = C.uint32_t(fl)
	h.p_seg = C.uint8_t(seg)
	h.len = C.uint8_t(dec.Len())
	h.p_rep = C.uint8_t(dec.RepPrefix())
	h.p_lock = C.uint8_t(dec.LockPrefix())
	h.p_66 = C.uint8_t(dec.OpSizePrefix())
	h.p_67 = C.uint8_t(dec.AddrSizePrefix())
	h.rex_w = C.uint8_t(dec.REX.W())
	h.rex_r = C.uint8_t(dec.REX.R())
	h.rex_x = C.uint8_t(dec.REX.X())
	h.rex_b = C.uint8_t(dec.REX.B())
	h.opcode = C.uint8_t(dec.Opcode)
	h.opcode2 = C.uint8_t(dec.Opcode2)
	h.modrm = C.uint8_t(dec.ModRM)
	h.modrm_mod = C.uint8_t(dec.ModRM.Mod())
	h.modrm_reg = C.uint8_t(dec.ModRM.Reg())
	h.modrm_rm = C.uint8_t(dec.ModRM.RM())
	h.sib = C.uint8_t(dec.SIB)
	h.sib_scale = C.uint8_t(dec.SIB.Scale())
	h.sib_index = C.uint8_t(dec.SIB.Index())
	h.sib_base = C.uint8_t(dec.SIB.Base())
	binary.LittleEndian.PutUint64(h.imm[:], dec.Imm.Value)
	binary.LittleEndian.PutUint32(h.disp[:], uint32(dec.Disp.Value))
	copy(h.imm[dec.Imm.Bits/8:], org.imm[dec.Imm.Bits/8:])
	copy(h.disp[dec.Disp.Bits/8:], org.disp[dec.Disp.Bits/8:])
	return
}
