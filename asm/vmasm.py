import re
import struct
import sys


OPTYPE_NONE = 0x00
OPTYPE_REGB = 0x01
OPTYPE_REGW = 0x02
OPTYPE_IMMED = 0x03
OPTYPE_MEMB = 0x04
OPTYPE_MEMW = 0x05
OPTYPE_MEMRB = 0x06
OPTYPE_MEMRW = 0x07


OPCODES = {
    "nop": 0x00,
    "in":  0x01,
    "out": 0x02,
    "mov": 0x03,
    "add": 0x04,
    "sub": 0x05,
    "xor": 0x06,
    "and": 0x07,
    "or":  0x08,
    "hlt": 0x09,
    "brk": 0x0A,
    "push": 0x0B,
    "pop":  0x0C,
    "call": 0x0D,
    "ret": 0x0E
}


OPERAND_COUNT = {
    "nop":  0,
    "in":   1,
    "out":  1,
    "mov":  2,
    "add":  2,
    "sub":  2,
    "xor":  2,
    "and":  2,
    "or":   2,
    "hlt":  0,
    "brk":  0,
    "push": 1,
    "pop":  1,
    "call": 1,
    "ret": 0
}


def pack_u32(value):
    return struct.pack("<I", value & 0xFFFFFFFF)


def parse_number(text):
    text = text.strip()

    if text.lower().startswith("0x"):
        return int(text, 16)

    return int(text, 10)


def parse_operand(text):
    text = text.strip()

    m = re.fullmatch(r"byte\s+r(\d+)", text, re.IGNORECASE)
    if m:
        reg = int(m.group(1))

        if not 0 <= reg < 32:
            raise ValueError(f"invalid register: r{reg}")

        return bytes([OPTYPE_REGB]) + pack_u32(reg)

    m = re.fullmatch(r"r(\d+)", text, re.IGNORECASE)
    if m:
        reg = int(m.group(1))

        if not 0 <= reg < 32:
            raise ValueError(f"invalid register: r{reg}")

        return bytes([OPTYPE_REGW]) + pack_u32(reg)

    m = re.fullmatch(r"byte\s+\[(0x[0-9a-fA-F]+|\d+)\]", text, re.IGNORECASE)
    if m:
        address = parse_number(m.group(1))

        return bytes([OPTYPE_MEMB]) + pack_u32(address)

    m = re.fullmatch(r"\[(0x[0-9a-fA-F]+|\d+)\]", text, re.IGNORECASE)
    if m:
        address = parse_number(m.group(1))

        return bytes([OPTYPE_MEMW]) + pack_u32(address)

    m = re.fullmatch(r"byte\s+\[r(\d+)\]", text, re.IGNORECASE)
    if m:
        reg = int(m.group(1))

        if not 0 <= reg < 32:
            raise ValueError(f"invalid register: r{reg}")

        return bytes([OPTYPE_MEMRB]) + pack_u32(reg)

    m = re.fullmatch(r"\[r(\d+)\]", text, re.IGNORECASE)
    if m:
        reg = int(m.group(1))

        if not 0 <= reg < 32:
            raise ValueError(f"invalid register: r{reg}")

        return bytes([OPTYPE_MEMRW]) + pack_u32(reg)

    m = re.fullmatch(r"0x([0-9a-fA-F]+)", text)
    if m:
        value = int(m.group(1), 16)

        return bytes([OPTYPE_IMMED]) + pack_u32(value)

    if re.fullmatch(r"\d+", text):
        value = int(text, 10)

        return bytes([OPTYPE_IMMED]) + pack_u32(value)

    raise ValueError(f"invalid operand: {text}")


def parse_instruction(line, line_number):
    line = line.strip()

    if not line:
        return b""

    parts = line.split(None, 1)

    mnemonic = parts[0].lower()

    if mnemonic not in OPCODES:
        raise ValueError(
            f"line {line_number}: unknown instruction '{mnemonic}'"
        )

    operands_text = ""

    if len(parts) == 2:
        operands_text = parts[1].strip()

    if operands_text:
        operands = []
        for x in operands_text.split(","):
            operands.append(x.strip())
        
    else:
        operands = []

    expected = OPERAND_COUNT[mnemonic]

    if len(operands) != expected:
        raise ValueError(
            f"line {line_number}: {mnemonic} expects "
            f"{expected} operand(s), got {len(operands)}"
        )

    encoded_operands = []

    for operand in operands:
        encoded_operands.append(parse_operand(operand))

    while len(encoded_operands) < 2:
        encoded_operands.append(
            bytes([OPTYPE_NONE]) + b"\x00" * 4
        )

    return (
        bytes([OPCODES[mnemonic]]) +
        encoded_operands[0] +
        encoded_operands[1]
    )


def assemble(source):
    result = bytearray()

    for line_number, line in enumerate(source.splitlines(), 1):
        encoded = parse_instruction(line, line_number)

        if encoded:
            if len(encoded) != 11:
                raise ValueError(
                    f"line {line_number}: "
                    f"internal error: instruction size != 11"
                )

            result.extend(encoded)

    return bytes(result)


def main():
    if len(sys.argv) > 3:
        print(
            f"usage: {sys.argv[0]} [input.asm] [output.bin]",
            file=sys.stderr
        )
        return 1

    if len(sys.argv) >= 2:
        with open(sys.argv[1], "r", encoding="utf-8") as f:
            source = f.read()
    else:
        source = sys.stdin.read()

    try:
        result = assemble(source)
    except ValueError as e:
        print(f"assembler error: {e}", file=sys.stderr)
        return 1

    if len(sys.argv) == 3:
        with open(sys.argv[2], "wb") as f:
            f.write(result)
    else:
        sys.stdout.buffer.write(result)

    return 0


if __name__ == "__main__":
    sys.exit(main())
