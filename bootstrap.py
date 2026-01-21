import sys
import struct
import os

# Register Mapping
REG = {
    'rax': 0, 'rcx': 1, 'rdx': 2, 'rbx': 3,
    'rsp': 4, 'rbp': 5, 'rsi': 6, 'rdi': 7,
    'r8': 8, 'r9': 9, 'r10': 10, 'r11': 11,
    'r12': 12, 'r13': 13, 'r14': 14, 'r15': 15
}

# Inverse Jump Mapping for Fox Structures
# jika_X implies "execute block if X". So we jump over if NOT X.
JUMP_INVERSE = {
    'jika_kurang': 'jge',      # if <, jump if >= (skip)
    'jika_lebih': 'jle',       # if >, jump if <= (skip)
    'jika_sama': 'jne',        # if ==, jump if != (skip)
    'jika_beda': 'je',         # if !=, jump if == (skip)
    'jika_bukan_nol': 'je',    # if != 0, jump if == 0
    'jika_nol': 'jne'          # if == 0, jump if != 0
}

OPCODES = {
    'syscall': b'\x0F\x05',
    'ret': b'\xC3',
}

def parse_imm(s):
    if s.startswith('0x'): return int(s, 16)
    return int(s)

def encode_modrm(reg, rm):
    return 0xC0 | ((reg & 7) << 3) | (rm & 7)

def get_rex(w, r, x, b):
    rex = 0x40
    if w: rex |= 8
    if r: rex |= 4
    if x: rex |= 2
    if b: rex |= 1
    return rex

class Compiler:
    def __init__(self):
        self.labels = {}
        self.code = bytearray()
        self.scope_stack = [] # Stack of (type, label_name)
        self.label_counter = 0

    def new_label(self):
        self.label_counter += 1
        return f"L_{self.label_counter}"

    def emit(self, b):
        self.code += b

    def compile_instr(self, line, pass_num):
        parts = line.strip().replace(',', ' ').split()
        if not parts: return
        mnemonic = parts[0]

        if mnemonic.startswith(';'): return

        # Structural Keywords
        if mnemonic == 'fungsi':
            # Entry point, maybe label?
            return
        if mnemonic == 'tutup_fungsi':
            # ret
            self.emit(b'\xC3')
            return

        if mnemonic in JUMP_INVERSE:
            # Start of IF block
            skip_label = self.new_label()
            self.scope_stack.append(('IF', skip_label))
            # Emit Conditional Jump to skip_label
            cond = JUMP_INVERSE[mnemonic]
            self.emit_jump(cond, skip_label, pass_num)
            return

        if mnemonic == 'tutup_jika':
            if not self.scope_stack: return
            type_, label = self.scope_stack.pop()
            if type_ == 'IF':
                # Define label here
                self.labels[label] = len(self.code)
            return

        # Instructions
        if mnemonic == 'syscall':
            self.emit(b'\x0F\x05')
            return

        if mnemonic == 'push':
            reg = REG[parts[1]]
            # 50 + rd
            if reg > 7:
                self.emit(bytes([0x41, 0x50 + (reg & 7)]))
            else:
                self.emit(bytes([0x50 + reg]))
            return

        if mnemonic == 'pop':
            reg = REG[parts[1]]
            # 58 + rd
            if reg > 7:
                self.emit(bytes([0x41, 0x58 + (reg & 7)]))
            else:
                self.emit(bytes([0x58 + reg]))
            return

        if mnemonic == 'sub':
            # sub r64, imm32
            dest = REG[parts[1]]
            imm = parse_imm(parts[2])
            rex = get_rex(1, 0, 0, dest > 7)
            modrm = encode_modrm(5, dest) # 5 is opcode ext for SUB
            self.emit(bytes([rex, 0x81, modrm]))
            self.emit(struct.pack('<I', imm))
            return

        if mnemonic == 'add':
            dest = REG[parts[1]]
            imm = parse_imm(parts[2])
            rex = get_rex(1, 0, 0, dest > 7)
            modrm = encode_modrm(0, dest) # 0 is opcode ext for ADD
            self.emit(bytes([rex, 0x81, modrm]))
            self.emit(struct.pack('<I', imm))
            return

        if mnemonic == 'cmp':
            op1 = parts[1]
            op2 = parts[2]
            if op1 in REG and op2.isdigit(): # cmp reg, imm
                dest = REG[op1]
                imm = parse_imm(op2)
                rex = get_rex(1, 0, 0, dest > 7)
                modrm = encode_modrm(7, dest) # 7 is opcode ext for CMP
                # Use 81 for imm32, 83 for imm8
                if 0 <= imm <= 127: # imm8 opt
                     self.emit(bytes([rex, 0x83, modrm, imm]))
                else:
                     self.emit(bytes([rex, 0x81, modrm]))
                     self.emit(struct.pack('<I', imm))
            elif op1 in REG and op2 in REG: # cmp reg, reg
                dest = REG[op1]
                src = REG[op2]
                rex = get_rex(1, src > 7, 0, dest > 7)
                modrm = encode_modrm(src, dest)
                self.emit(bytes([rex, 0x39, modrm]))
            return

        if mnemonic == 'mov':
            dest_str = parts[1]
            src_str = parts[2]

            if dest_str in REG and (src_str[0].isdigit() or src_str.startswith('0x') or src_str.startswith('-')):
                dest = REG[dest_str]
                imm = parse_imm(src_str)
                # Mov r64, imm64 (B8+rd)
                opcode = 0xB8 + (dest & 7)
                rex = get_rex(1, 0, 0, dest > 7)
                self.emit(bytes([rex, opcode]))
                self.emit(struct.pack('<Q', imm & 0xFFFFFFFFFFFFFFFF))
                return

            if dest_str in REG and src_str in REG:
                dest = REG[dest_str]
                src = REG[src_str]
                rex = get_rex(1, src > 7, 0, dest > 7)
                modrm = encode_modrm(src, dest)
                self.emit(bytes([rex, 0x89, modrm]))
                return

    def emit_jump(self, cond, label, pass_num):
        # We use rel32 jumps (near)
        # JNE: 0F 85 rel32
        # JGE: 0F 8D rel32
        # JLE: 0F 8E rel32
        # JE:  0F 84 rel32
        OP = {
            'jne': b'\x0F\x85',
            'je':  b'\x0F\x84',
            'jge': b'\x0F\x8D',
            'jle': b'\x0F\x8E',
            'jmp': b'\xE9'
        }

        self.emit(OP[cond])

        if pass_num == 1:
            self.emit(b'\x00\x00\x00\x00')
        else:
            target = self.labels.get(label, 0)
            current = len(self.code) + 4 # relative to next instr
            rel = target - current
            self.emit(struct.pack('<i', rel))

def make_elf(code):
    elf_header = b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    elf_header += struct.pack('<H', 2) + struct.pack('<H', 62) + struct.pack('<I', 1)
    entry_point = 0x400000 + 0x78
    elf_header += struct.pack('<Q', entry_point)
    elf_header += struct.pack('<Q', 64) + struct.pack('<Q', 0) + struct.pack('<I', 0)
    elf_header += struct.pack('<H', 64) + struct.pack('<H', 56) + struct.pack('<H', 1)
    elf_header += struct.pack('<H', 64) + struct.pack('<H', 0) + struct.pack('<H', 0)

    phdr = struct.pack('<I', 1) + struct.pack('<I', 7) + struct.pack('<Q', 0)
    phdr += struct.pack('<Q', 0x400000) + struct.pack('<Q', 0x400000)
    filesz = 0x78 + len(code)
    phdr += struct.pack('<Q', filesz) + struct.pack('<Q', filesz) + struct.pack('<Q', 0x1000)

    return elf_header + phdr + code

def main():
    filename = 'morph_runner.fox'
    with open(filename, 'r') as f:
        lines = f.readlines()

    # Pass 1: Calculate labels
    c = Compiler()
    for line in lines:
        c.compile_instr(line, 1)

    labels = c.labels

    # Pass 2: Generate code
    c2 = Compiler()
    c2.labels = labels
    for line in lines:
        c2.compile_instr(line, 2)

    binary = make_elf(c2.code)
    with open('morph', 'wb') as f:
        f.write(binary)
    os.chmod('morph', 0o755)
    print(f"Generated 'morph' ({len(binary)} bytes)")

if __name__ == '__main__':
    main()
