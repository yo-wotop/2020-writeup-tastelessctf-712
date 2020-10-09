#!/usr/bin/python3

import struct
import pwn
import subprocess
import re

folder = '/shr/part2/'
solved = folder + 'solved8.png'

DO_REGEX = 'dataOffset\\s*:\\s*(0x[^\\s]*)'
PS_REGEX = 'packSize\\[\\d\\]\\s*:\\s*(0x[^\\s]*)'
errors = []
def getData(file_number):
    global errors
    # Run the fucking guy's shit lol
    fil = 'part2_%s.7z' % file_number
    p = subprocess.run(['python2','../7z_parser.py', fil], cwd=folder, stdout=subprocess.PIPE,
                                timeout=2, env={})

    text = p.stdout.decode()

    try:
        data_finds = re.findall(DO_REGEX, text)
        pack_finds = re.findall(PS_REGEX, text)

        data_offset = int(data_finds[0], 16)
        packed_size = int(pack_finds[0], 16)

        return data_offset, packed_size

    except:
        #errors.append(file_number)
        return 0,0

debug = True
def read_number(inp):
    global debug
    if debug:
        for i in inp:
            print(i)
    inp_len = len(inp) - 1
    mask = inp[0]
    value = 0

    if (mask & 0x80) == 0 or (mask == 0x0):
        return (mask, 1)

    ormask = (mask - 0x80)
    # print("ormask: %s" % hex(ormask))
    unpack_str = "B"  # lololol

    for i in range(1, inp_len):
        if mask & (0x80 >> i):  # bit set, read a byte
            # print hex(ord(inp[i]))
            unpack_str += "B"
            ormask -= 1 << (8 - (i + 1))
        else:  #
            try:
                valuetup = struct.unpack(unpack_str, inp[1:(i + 1)])
                ormask <<= (i * 8)
                break
            except Exception as e:
                print("Invalid value %s, %d" % (repr(inp), len(inp)))
                print
                unpack_str
                raise
                # not enough bytes given. Error

    for j in range(len(valuetup), 0, -1):
        value += valuetup[j - 1] << (8 * (j - 1))

    if value < 0:
        value *= -1
    # print("value: 0x%lx, ormask: %s"%(value,hex(ormask)))
    value |= ormask
    return (value, i + 1)


'''
data = []
for i in range(376):
    print(i)
    data.append(getData(i))

print(data)
print("Bad files: %s" % errors)

raise Exception()
'''

new_file = b''
HEADER_LEN = 0x20
for i in range(376):
    file_name = 'part2_%s.7z' % i
    full_name = folder + file_name

    with open(full_name, 'rb') as f:
        data = f.read()
        byts = data[0x14:0x14+8]
        footer_length = pwn.u64(byts)
        footer = data[-footer_length:]

        data_offset, pack_size = getData(i)

        if data_offset == 0 and pack_size == 0:
            data_offset,_ = read_number(footer[6:15])
            pack_size = 0

        start = HEADER_LEN + data_offset + pack_size
        end = -footer_length

        extract = data[start:end]

        #print(footer,extract)
        #raise Exception()

        new_file += extract

with open(solved, 'wb+') as f:
    f.write(new_file)

print(new_file)
