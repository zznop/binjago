"""rop.py: Calculates ROP gadgets contained in the executable sections 
of binaries
"""

from binaryninja import *
from operator import itemgetter
import binascii
import argparse

_PREV_BYTE_SIZE = 9

_RET_INSTRS  = {
    "retn" : ["\xc3", "\xf2\xc3"],
    "retf" : ["\xcb",],
}

def _parse_args():
    """Parse command line arguments
    """
    parser = argparse.ArgumentParser(description='Calculate ROP gadgets')
    parser.add_argument('--file', type=str, required=True,
        help = 'File path to target binary')

    return parser.parse_args()

def _disas_all_instrs(bv, start_addr, ret_addr):
    """Disassemble all instructions in chunk
    """
    global _RET_INSTRS
    instructions = []
    curr_addr = start_addr
    while curr_addr < ret_addr:
        instr = bv.get_disassembly(curr_addr)

        # bad instruction
        if instr == None:
            return None
       
        # exclude jumps
        if instr[0] == 'j':
            return None

        # exclude leaves
        if instr == 'leave':
            return None

        # we don't want two rets
        if instr in _RET_INSTRS.keys():
            return None

        instructions.append(instr)
        curr_addr += bv.get_instruction_length(curr_addr)

    # ret opcode was included in last instruction calculation
    if curr_addr != ret_addr:
        return None

    return instructions

def _calculate_gadget_from_ret(bv, gadgets, baseaddr, ret_addr):
    """Decrement index from ret instruction and calculate gadgets
    """
    global _PREV_BYTE_SIZE
    ret_instr = bv.get_disassembly(ret_addr)
    for i in range(1, _PREV_BYTE_SIZE):
        instructions = _disas_all_instrs(bv, ret_addr - i, ret_addr)
        if instructions == None:
            continue 

        gadget_str = ""
        for instr in instructions:
            gadget_str += "{} ; ".format(instr)

        gadget_rva = ret_addr - i - baseaddr
        gadgets[gadget_rva] = "{}{}".format(gadget_str, ret_instr)

    return gadgets

def _find_gadgets_in_data(bv, baseaddr, section):
    """Find ret instructions and spawn a thread to calculate gadgets
    for each hit
    """
    global _RET_INSTRS
    gadgets = {}
    for ret_instr, bytecodes in _RET_INSTRS.iteritems():
        for bytecode in bytecodes:
            next_start = section.start
            next_ret_addr = 0
            while next_start < section.start + section.length:
                next_ret_addr = bv.find_next_data(next_start, bytecode)
                if next_ret_addr == None:
                    break

                # TODO: thread this
                gadgets = _calculate_gadget_from_ret(bv, gadgets, baseaddr, next_ret_addr)
                next_start = next_ret_addr + len(bytecode)

    return gadgets

def _generate_markdown_report(bv, gadgets, title):
    """Display ROP gadgets
    """
    markdown = ""
    found = []
    for addr, gadget in sorted(gadgets.items(), key=itemgetter(1)):
        if gadget not in found:
            markdown += "**{:08x}** ```{}```\n\n".format(addr, gadget)
            found.append(gadget)

    bv.show_markdown_report(title, markdown)

def _print_gadgets(gadgets):
    """Display ROP gadgets in headless mode
    """
    markdown = ""
    found = []
    for addr, gadget in sorted(gadgets.items(), key=itemgetter(1)):
        if gadget not in found:
            print "{:08x} {}".format(addr, gadget)

class ROPSearch(BackgroundTaskThread):
    """Class that assists in locating ROP gadgets in exectable code segments
    """
    def __init__(self, view):
        BackgroundTaskThread.__init__(self, "", True)
        self.view = view
        self.gadgets = {}
        self.progress = "binjago: Searching for ROP gadgets..."
        self.threads = []
        self.ret_instrs = {
            "retn" : ["\xc3", "\xf2\xc3"],
            "retf" : ["\xcb",],
        }

    def run(self):
        """Locate ROP gadgets contain in executable sections of a binary
        """
        if not self.view.executable:
            return

        baseaddr = self.view.segments[0].start
        section  = self.view.get_section_by_name(".text")
        gadgets  = _find_gadgets_in_data(self.view, baseaddr, section)

        if gadgets != {}:
            _generate_markdown_report(self.view, gadgets, "ROP Gadgets")
        else:
            show_message_box("binjago: ROP Gadget Search", "Could not find any ROP gadgets")

        self.progress = ""

def run_headless():
    """Run as headless script
    """
    args = _parse_args()
    bv = BinaryViewType.get_view_of_file(args.file)
    bv.update_analysis_and_wait()
    if not bv.executable:
        print "! binary does not contain executable code"

    baseaddr = bv.segments[0].start
    section  = bv.get_section_by_name(".text")
    gadgets  = _find_gadgets_in_data(bv, baseaddr, section)
    if gadgets != {}:
        _print_gadgets(gadgets)

if __name__ == '__main__':
    run_headless()
