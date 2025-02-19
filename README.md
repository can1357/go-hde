# go-hde

[![Go Tests with CGo](https://github.com/can1357/go-hde/actions/workflows/test.yml/badge.svg)](https://github.com/can1357/go-hde/actions/workflows/test.yml)

A high-performance x86/x86-64 instruction decoder library written in Go.

## Overview

go-hde (Go Hacker Disassembler Engine) is a lightweight and efficient library for decoding x86 and x86-64 machine code instructions. It provides basic information about instruction prefixes, opcodes, operands, and other instruction-specific details.

This library is inspired by and based on the Hacker Disassembler Engine (hde) by Vyacheslav Patkov, though it has evolved from the original implementation.

## Features

- x86 and x86-64 instruction decoding (Up until AVX)
- Support for all instruction prefixes (REX, segment, operand size, etc.)
- Detailed instruction information including:
  - ModR/M and SIB byte parsing
  - Immediate values
  - Displacement values
  - Instruction length calculation
  - Relative addressing
- Special instruction detection (JCC, JMP, RET, CALL, INT)
- Efficient structure for storing instructions

## Installation

```bash
go get github.com/can1357/go-hde
```

## Usage

```go
package main

import (
    "fmt"
    hde "github.com/can1357/go-hde"
)

func main() {
    // Example machine code bytes
    code := []byte{/* your x86/x64 machine code */}

    // 32-bit mode decoding
    if insn, err := hde.Mode32.Decode(code); err == nil {
        // Get instruction length
        length := insn.Len()

        // Get instruction flags
        flags := insn.Flags

        // Get segment prefix if any
        segPrefix := insn.SegmentPrefix()

        // Move to next instruction
        code = code[length:]
    }

    // 64-bit mode decoding
    if insn, err := hde.Mode64.Decode(code); err == nil {
        // Process the instruction
        fmt.Printf("Instruction length: %d\n", insn.Len())
        fmt.Printf("Flags: %s\n", insn.Flags.String())
    }
}
```

The main instruction structure containing all decoded information:

```go
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

func (insn *Insn) AddrSizePrefix() byte
func (insn *Insn) IsCALL() bool
func (insn *Insn) IsINT() bool
func (insn *Insn) IsJCC() bool
func (insn *Insn) IsJMP() bool
func (insn *Insn) IsRET() bool
func (insn *Insn) Len() uint8
func (insn *Insn) LockPrefix() byte
func (insn *Insn) OpSizePrefix() byte
func (insn *Insn) RepPrefix() byte
func (insn *Insn) SegmentPrefix() byte
```

### Instruction Decoding Loop

Here's an example of how to decode a stream of instructions:

```go
func decodeStream(code []byte) {
    // Choose mode based on your target architecture
    mode := hde.Mode64 // or hde.Mode32

    // Iterate through the byte stream
    for len(code) >= 15 { // Ensure enough bytes for max instruction length
        insn, err := mode.Decode(code)
        if err != nil {
            // Handle invalid instruction by skipping one byte
            code = code[1:]
            continue
        }

        // Process the valid instruction
        // ... your processing logic here ...

        // Move to next instruction
        code = code[insn.Len():]
    }
}
```
