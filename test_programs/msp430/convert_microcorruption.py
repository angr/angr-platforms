import elffile
import subprocess
import re
import sys

filename = sys.argv[1]

tag_rgx = re.compile(r'<(.*?)>')
bytes_rgx = re.compile(r'^([0-9A-Fa-f]{4} )+\s*', )
jmp_rgx = re.compile(r'(j[A-Za-z]+|call|br)\s+#0x[0-9A-Fa-f]+\s*<(.*?)>')
str_rgx = re.compile(r'"(.*?)"')
bad_str_rgx = re.compile(r'(#.*?)".*?"')
strln_rgx = re.compile(r'[0-9A-Fa-f]{4}: ".*?"')
strarg_rgx = re.compile(r'#.*?".*?"')

with open(filename, 'r') as disassembly:
    lines = [l.strip() for l in disassembly.readlines()]

processed_lines = { }
labels = [ ]

deconstructed_lines = [ ]

marked_lines = [ ]

def add_line(addr, l):
    try:
        processed_lines[addr] += l
    except KeyError:
        processed_lines[addr] = l

try:
    while True:
        line = lines.pop(0).replace('\t', ' ').replace('sp', 'r1').replace('sr', 'r2')

        addr = int(line[:4], 16)

        if '.strings' in line: # We are the strings section
            add_line(addr, '.strings: ')
            while strln_rgx.match(lines[0]):
                line = lines.pop(0)
                addr = int(line[:4], 16)
                value = str_rgx.search(line).groups(1)[0]
                add_line(addr, ".string \"%s\"" % value)
            continue

        if line[4] != ':': # We are a label
            label_name = tag_rgx.search(line).groups(1)[0]
            add_line(addr, '%s: ' % label_name)
            labels.append(label_name)
        else: # We are an instruction
            instruction_stuff = line[22:]
            if jmp_rgx.match(instruction_stuff):
                sometag_ind = instruction_stuff.find('<')
                # print hex(addr), instruction_stuff.split()
                instruction = instruction_stuff.split()[0]
                operand = int(instruction_stuff.split()[1][3:], 16)
                if instruction != 'call' and instruction != 'br':
                    operand -= addr
                if operand < 0:
                    operand_str = '-0x%x' % (-1 * operand)
                else:
                    operand_str = '0x%x' % operand
                add_line(addr, '%s %s' % (instruction, operand_str))
            else:
                strings_removed = re.sub(str_rgx, '', instruction_stuff)
                add_line(addr, strings_removed)
except IndexError:
    pass

assemblefile_name = sys.argv[2]
with open(assemblefile_name, 'w') as outfile:
    for label in labels:
        outfile.write('.global %s\n' % label)
    outfile.write('\n.text\n')
    for addr, line in sorted(processed_lines.iteritems()):
        outfile.write('.org 0x%x\n' % addr)
        outfile.write(line + '\n')

outfile_name = sys.argv[3]
if not subprocess.call(['/opt/ti/mspgcc/bin/msp430-elf-as', assemblefile_name, '-o', outfile_name]):
    eo = elffile.open(name=outfile_name)
    eo.fileHeader.entry = 0x4400
    eo.fileHeader.type = 2
    with open(outfile_name, 'wb') as ofile:
        ofile.write(eo.pack())
else:
    raise Exception('Could not assemble.')
