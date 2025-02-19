package cgohde32_test

import (
	_ "embed"
	"fmt"
	"testing"

	hde "github.com/can1357/go-hde"
	cgohde32 "github.com/can1357/go-hde/tests/hde32"
	"github.com/can1357/go-hde/tests/hdeutil"
)

//go:embed winrar-x86-602.exe
var winrar []byte

func BenchmarkHde32(b *testing.B) {
	b.Run("Cgo", func(b *testing.B) {
		it := winrar
		for i := 0; i < b.N; i++ {
			if len(it) < 15 {
				it = winrar
			}
			insn := cgohde32.CgoDecode(it)
			flg := cgohde32.CgoFlags(&insn)
			if flg&hdeutil.F_ERROR != 0 {
				it = it[1:]
			} else {
				it = it[cgohde32.CgoLen(&insn):]
			}
		}
	})
	b.Run("Go", func(b *testing.B) {
		it := winrar
		for i := 0; i < b.N; i++ {
			if len(it) < 15 {
				it = winrar
			}
			insn, err := hde.Mode32.Decode(it)
			if err != nil {
				it = it[1:]
			} else {
				it = it[insn.Len():]
			}
		}
	})
}

func TestHde32(t *testing.T) {
	numOk := 0
	for i := 0; i < len(winrar)-15; {
		insn := cgohde32.CgoDecode(winrar[i:])
		numOk++
		flg := cgohde32.CgoFlags(&insn)
		if flg&hdeutil.F_ERROR != 0 {
			i++
			continue
		}
		dec, err := hde.Mode32.Decode(winrar[i:])
		if err != nil {
			// Fail if HDE did not error, Go port did
			t.Fatal(err)
		}
		insn2 := cgohde32.GoToCGo(&dec, &insn)
		if insn != insn2 {
			fmt.Printf("%s\n", dec.Flags.String())
			fmt.Printf("insn : %s\n %+v\n", hdeutil.FormatCgoFlags(flg), insn)
			fmt.Printf("insn': %s\n %+v\n", hdeutil.FormatCgoFlags(cgohde32.CgoFlags(&insn2)), insn2)
			dec, err = hde.Mode32.Decode(winrar[i:])
			if err != nil {
				t.Fatal(err)
			}
			cf, seg := hdeutil.ToCgoFlags(dec.Flags)
			fmt.Printf("cf: %x, seg: %d\n", cf, seg)
			t.Fatal("disasm mismatch")
		}
		_, seg := hdeutil.ToCgoFlags(dec.Flags)
		if pfx := dec.SegmentPrefix(); byte(pfx) != seg {
			t.Fatalf("seg mismatch: %d != %d\n", seg, pfx)
		}
		i += cgohde32.CgoLen(&insn)
	}
	t.Logf("numOk: %d", numOk)
}
