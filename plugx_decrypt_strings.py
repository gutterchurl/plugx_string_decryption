#!/usr/bin/env python
# Copyright (c) 2015-2017 Vector 35 LLC
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

import binaryninja.log as log
from binaryninja.binaryview import BinaryViewType, BinaryReader
from binaryninja import *
import binaryninja.interaction as interaction
from binaryninja.plugin import PluginCommand
import sys
import yara

XOR_KEY = ''
# TODO: Input location - currently assumes these files are in the curr dir
rules = yara.compile('plugx.yar')
rules.save('plugx_compiled.yar')
rules = yara.load('plugx_compiled.yar')

def get_bininfo(bv):
    if bv is None:
        filename = ""
        if len(sys.argv) > 1:
            filename = sys.argv[1]
        else:
            filename = interaction.get_open_filename_input("Filename:")
            if filename is None:
                log.log_warn("No file specified")
                sys.exit(1)
        bv = BinaryViewType.get_view_of_file(filename)
        log.log_to_stdout(True)

    contents = "## %s ##\n" % bv.file.filename
    contents += "- START: 0x%x\n\n" % bv.start
    contents += "- ENTRY: 0x%x\n\n" % bv.entry_point
    contents += "- ARCH: %s\n\n" % bv.arch.name
    contents += "### First 10 Functions ###\n"

    contents += "| Start | Name   |\n"
    contents += "|------:|:-------|\n"
    for i in xrange(min(10, len(bv.functions))):
        contents += "| 0x%x | %s |\n" % (bv.functions[i].start, bv.functions[i].symbol.full_name)

    contents += "### First 10 Strings ###\n"
    contents += "| Start | Length | String |\n"
    contents += "|------:|-------:|:-------|\n"
    for i in xrange(min(10, len(bv.strings))):
        start = bv.strings[i].start
        length = bv.strings[i].length
        string = bv.read(start, length)
        contents += "| 0x%x |%d | %s |\n" % (start, length, string)

    return contents


def display_bininfo(bv):
    interaction.show_markdown_report("Binary Info Report", get_bininfo(bv))

def get_bin_view(bv):
    if bv is None:
        filename = ""
        if len(sys.argv) > 1:
            filename = sys.argv[1]
        else:
            filename = interaction.get_open_filename_input("Filename:")
            if filename is None:
                log.log_warn("No file specified")
                sys.exit(1)
        bv = BinaryViewType.get_view_of_file(filename)
        log.log_to_stdout(True)
        return bv

def decode_strings(filename):
    y_offsets = get_yara_offset(filename)
    bv = BinaryViewType.get_view_of_file(filename)
    bv.add_analysis_option("linearsweep")
    bv.update_analysis_and_wait()
    xref_funcs = get_xrefs(bv, y_offsets)
    keys = get_key(bv, y_offsets)

    # TODO: Need to make this work for multiple keys but not y_offset
    XOR_KEY = keys[0].value.value
    #for y in y_offsets:
    #    xor_dec(XOR_KEY, xref_funcs, y_off
    xor_dec(bv, XOR_KEY, xref_funcs, y_offsets)

    # TODO: Again need to have an input dir, or cmdline options
    bv.save('AShldRes_new.dll')
    
    #print bv.get_strings(0x10002030, 200)

def xor_dec(bv, key, xref_funcs, y_offsets):
    br = BinaryReader(bv)
    bw = BinaryWriter(bv)
    print "Decrypted strings:"
    for xref in xref_funcs[0]:
        # print xref.function, hex(xref.address)
        il = xref.function.get_low_level_il_at(xref.address).medium_level_il
        if (il.operation == MediumLevelILOperation.MLIL_CALL):
            enc_str = il.params[0].value.value
            str_size = il.params[1].value.value
            diff = il.params[2].value.value
            dec_str = ''
            br.seek(enc_str)
            bw.seek(enc_str)
            for i in xrange(str_size): 
                enc_byte = br.read8()
                x = ((enc_byte - diff) ^ key) + diff
                dec_str = dec_str + chr(x)
                # Patch binary 
                bw.write8(x)

# AShldRes.exp @ 0x10002048

def get_key(bv, y_offsets):
    keys = []
    fn = None
    il_bb = None
    for y in y_offsets:
        virt_off = bv.get_address_for_data_offset(y)
        fn = bv.get_functions_containing(virt_off)[0]
        fn_blocks = bv.get_basic_blocks_at(virt_off)
        il = fn.get_low_level_il_at(fn_blocks[0].start)
        for bb in fn.low_level_il:
            if bb.start == il.instr_index:
                il_bb = bb
                break
        for il in il_bb:
            if (il.operation == LowLevelILOperation.LLIL_SET_REG and
                il.src.operation == LowLevelILOperation.LLIL_XOR):
                keys.append(il.src.right)
                break
        return keys

def get_xrefs(bv, y_offsets):
    xref_funcs = []
    hit_funcs = []
    for y in y_offsets:
        hit_init = bv.get_address_for_data_offset(y)
        hit_funcs.append(bv.get_functions_containing(hit_init))

    for func_list in hit_funcs:
        for func in func_list:
            xref_funcs.append(bv.get_code_refs(func.start))
    return xref_funcs

def get_yara_offset(filename):
    y_offsets = []
    hit_offsets = yara_hit(filename)
    for hits in hit_offsets:
        y_offset = hits[0]
        y_offsets.append(y_offset)
    if not y_offsets:
        log.log_error("No yara hit offsets")
        sys.exit(1)
    else:
        return y_offsets

def yara_hit(filename):
    hit_offsets = []
    matches = rules.match(filename)
    for match in matches:
        hit_offset = match.strings[0]
        hit_offsets.append(hit_offset)
    if not hit_offsets:
        log.log_error("No yara hits")
        sys.exit(1)
    else:
        return hit_offsets

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print('Usage: {} <file>'.format(sys.argv[0]))
    else:
        decode_strings(sys.argv[1])
    print get_bininfo(None)
else:
    PluginCommand.register("Binary Info", "Display basic info about the binary", display_bininfo)
