#!/bin/python

import re
import shutil

SHA_256_FILE = "sha-256_ALICE.txt"
PBKDF_N_FILE_PREFIX = "pbkdf2-sha256-"
PBKDF_N_FILE_SUFFIX = ".txt"

IN_LEN = 512
OUT_LEN = 256

def mod_first():
    PBKDF_OUT_FILE = PBKDF_N_FILE_PREFIX + "1e0" + PBKDF_N_FILE_SUFFIX

    with open(SHA_256_FILE, "r") as in_f:
        gates = in_f.readlines()
    if not gates or len(gates) == 0:
        print("Failed to read input file")
        exit(1)

    # Parse first two lines of bristol format
    m = re.match(r"\s*(\d+)\s+(\d+)\s*\n", gates[0])
    numgates = int(m.group(1))
    numwires = int(m.group(2))
    m = re.match(r"\s*(\d+)\s+(\d+)\s+(\d+)\s*\n", gates[1])
    bobinputs = int(m.group(1))
    aliceinputs = int(m.group(2))
    outputs = int(m.group(3))
    gates = gates[3:] # skip first three lines
    if gates[-1] == "\n":
        gates = gates[:-1]

    #print(f"numgates: {numgates}\nnumwires: {numwires}\nbobinputs: {bobinputs}\naliceinputs: {aliceinputs}\noutputs: {outputs}")
        
    # Changes to first SHA256 iteration:
    # 1. Set wires 0-255 by XORing Alice's inputs with themselves to get 0 (prepend 256 gates)
    # 2. Rather than outputting directly, XOR with these zero-wires to get same result 
    #    (append 256 gates and wires)
    # 3. Modify initial line to have numgates += 512, numwires += 256
    # 4. No need to change internal wire/gate indices this time

    new_numgates = numgates + 512
    new_numwires = numwires + 256
    with open(PBKDF_OUT_FILE, "w") as out_f:
        out_f.writelines([
            str(new_numgates)+" "+str(new_numwires)+"\n",
            str(bobinputs)+" "+str(aliceinputs)+" "+str(outputs)+"\n",
            "\n" 
            ])
        out_f.writelines(get_prependgates_first())
        out_f.writelines(gates)
        out_f.writelines(get_appendgates_first(numwires))

def get_prependgates_first():
    return ["2 1 "+str(i+256)+" "+str(i+256)+" "+str(i)+" XOR\n" for i in range(256)]

def overwrite_startin_with_prevout(line, start):
    # must call AFTER incrementing wires to start at start
    if line[0] == "1":
        m = re.match(r"\s*1\s+1\s+(\d+)\s+(\d+)\s+INV\s*\n", line)
        inwire = int(m.group(1))
        outwire = int(m.group(2))
        if inwire < start + 256:
            inwire = start - 512 + inwire
        elif start+256 <= inwire < start+512:
            inwire = inwire - start
        if outwire < start + 256:
            outwire = start - 512 + outwire
        elif start+256 <= outwire < start+512:
            outwire = outwire - start
        return "1 1 "+str(inwire+wirenum)+" "+str(outwire+wirenum)+" INV\n"
    elif line[0] == "2":
        m = re.match(r"\s*2\s+1\s+(\d+)\s+(\d+)\s+(\d+)\s+(XOR|AND)\s*\n", line)
        inwire1 = int(m.group(1))
        inwire2 = int(m.group(2))
        outwire = int(m.group(3))
        opcode = int(m.group(4))
        if inwire1 < start + 256:
            inwire1 = start - 512 + inwire1
        elif start+256 <= inwire1 < start+512:
            inwire1 = inwire1 - start
        if inwire1 < start + 256:
            inwire2 = start - 512 + inwire2
        elif start+256 <= inwire2 < start+512:
            inwire2 = inwire2 - start
        if outwire < start + 256:
            outwire = start - 512 + outwire
        elif start+256 <= outwire < start+512:
            outwire = outwire - start
        return "2 1 "+str(inwire1+wirenum)+" "+str(inwire2+wirenum)+" "+str(outwire+wirenum)+" "+opcode+"\n"
    else:
        print(f"Error: Gates must have 1 or 2 inputs, was given {line[0]}")
        exit(1)
    


def get_appendgates_first(old_numwires):
    return ["2 1 "+str(i)+" "+str(old_numwires-256+i)+" "+str(old_numwires+i)+" XOR\n" for i in range(256)]

def get_appendgates(start, next_old_numwires):
    return ["2 1 "+str(start-256+i)+" "+str(next_old_numwires-256+i)+" "+str(next_old_numwires+i)+" XOR\n" for i in range(256)]

def process_line(line, start):
    """
    i between 0 and 255: start - 512 + i (prev output)
    i between 256 and 511: actual i (A's original input)
    i between 512 and end: start + i - 512 (normal wires, but shifted by start-512)
    does not handle appendgates
    """
    #print("Processing line: ", line)
    if line[0] == "1":
        m = re.match(r"\s*1\s+1\s+(\d+)\s+(\d+)\s+INV\s*\n", line)
        inwire = int(m.group(1))
        if inwire >= 512 or inwire < 256:
            inwire = start - 512 + inwire
        outwire = int(m.group(2))
        if outwire >= 512 or outwire < 256:
            outwire = start - 512 + outwire
        return "1 1 "+str(inwire)+" "+str(outwire)+" INV\n"
    elif line[0] == "2":
        m = re.match(r"\s*2\s+1\s+(\d+)\s+(\d+)\s+(\d+)\s+(XOR|AND)\s*\n", line)
        inwire1 = int(m.group(1))
        if inwire1 >= 512 or inwire1 < 256:
            inwire1 = start - 512 + inwire1
        inwire2 = int(m.group(2))
        if inwire2 >= 512 or inwire2 < 256:
            inwire2 = start - 512 + inwire2
        outwire = int(m.group(3))
        if outwire >= 512 or outwire < 256:
            outwire = start - 512 + outwire
        opcode = m.group(4)
        return "2 1 "+str(inwire1)+" "+str(inwire2)+" "+str(outwire)+" "+opcode+"\n"
    else:
        print(f"Error: Gates must have 1 or 2 inputs, was given {line[0]}")
        exit(1)

def add_n_iters(startfile, endfile, n):

    with open(SHA_256_FILE, "r") as in_f:
        sha256_gates = in_f.readlines()

    # Parse first two lines of bristol format
    m = re.match(r"\s*(\d+)\s+(\d+)\s*\n", sha256_gates[0])
    orig_numgates = int(m.group(1))
    orig_numwires = int(m.group(2))
    m = re.match(r"\s*(\d+)\s+(\d+)\s+(\d+)\s*\n", sha256_gates[1])
    orig_bobinputs = int(m.group(1))
    orig_aliceinputs = int(m.group(2))
    orig_outputs = int(m.group(3))
    sha256_gates = sha256_gates[3:] # skip first three lines
    if sha256_gates[-1] == "\n":
        sha256_gates = sha256_gates[:-1]

    prev_file = "tmp1.txt"
    next_file = "tmp2.txt"
    shutil.copyfile(startfile, prev_file)

    # To add next iteration to modded first:
    # 1. 2nd-last 256 of previous should be 1st 256 of next
    # 2. ORIGINAL 256-511 should be 2nd 256 of next
    # 3. Append 256 additional wires: output XORed with last 256 of previous
    for i in range(n):
        print(f"Iteration {i}")
        with open(prev_file, "r") as in_f:
            m = re.match(r"\s*(\d+)\s+(\d+)\s*\n", in_f.readline())
            prev_numgates = int(m.group(1))
            prev_numwires = int(m.group(2))
            in_f.readline()
            in_f.readline() # get to beginning of fourth line
            new_numgates = prev_numgates + orig_numgates + 256
            new_numwires = prev_numwires + orig_numwires - 256 # prev + (new-512) + 256
            with open(next_file, "w") as out_f:
                out_f.writelines([str(new_numgates)+" "+str(new_numwires)+"\n",
                    str(orig_bobinputs)+" "+str(orig_aliceinputs)+" "+str(orig_outputs)+"\n",
                    "\n"
                    ])
                shutil.copyfileobj(in_f, out_f)
        with open(next_file, "a") as out_f:
            for line in sha256_gates:
                out_f.write(process_line(line, prev_numwires))
            out_f.writelines(get_appendgates(prev_numwires, new_numwires-256))
        shutil.copyfile(next_file, prev_file)

    shutil.copyfile(next_file, endfile)


def pbkdf_file(nen):
    return PBKDF_N_FILE_PREFIX + nen + PBKDF_N_FILE_SUFFIX
        
#add_n_iters(pbkdf_file("1e0"), pbkdf_file("1e2"), 99)
#add_n_iters(pbkdf_file("1e2"), pbkdf_file("1e3"), 900)
add_n_iters(pbkdf_file("1e3"), pbkdf_file("5e3"), 4000)
