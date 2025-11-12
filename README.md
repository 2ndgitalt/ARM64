# GEMi - ARM64/ARMv9 Instruction Explorer & Analyzer

GEMi is a tool for exploring and analyzing AARCH64 instructions. It allows you to convert between hex and assembly, explore instruction encodings, and much more.

## Usage

To use GEMi, you can run the `ARMv9.py` script with various command-line arguments. To see a full list of options, run:

```bash
python3 ARMv9.py --help
```

## Examples

Here are some examples of how to use GEMi:

### Convert Hex to Assembly

You can convert a hexadecimal value to its corresponding assembly instruction:

```bash
python3 ARMv9.py --convert hex D20401aa
```

Output:

```
  Assembly: eor x10, x13, #0x1000000010000000
  Hex:      0xD20401AA
  Bytes (LE): AA0104D2
  Bytes (BE): D20401AA
```

### Convert Assembly to Hex

You can also convert an assembly instruction to its hexadecimal representation:

```bash
python3 ARMv9.py --convert asm "ADD X0, X1, #0x123"
```

### Explore an Instruction

You can explore the encoding of an instruction:

```bash
python3 ARMv9.py ADD
```

### Interactive Mode

For a more interactive experience, you can use the interactive mode:

```bash
python3 ARMv9.py --interactive
```
