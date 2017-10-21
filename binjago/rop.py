"""rop.py: Calculates ROP gadgets contained in the executable sections 
of binaries
"""

from binaryninja import *
from operator import itemgetter
import binascii

class ROPSearch(BackgroundTaskThread):
    """Class that assists in locating ROP gadgets in exectable code segments
    """
    def __init__(self, view):
        BackgroundTaskThread.__init__(self, "", True)
        self.view = view
        self.PREV_BYTE_SIZE = 9
        self.gadgets = {}
        self.progress = "binjago: Searching for ROP gadgets..."
        self.threads = []
        self.ret_instrs = {
            "retn" : ["\xc3", "\xf2\xc3"],
            "retf" : ["\xcb",],
        }

    def _disas_all_instrs(self, start_addr, ret_addr):
        """Disassemble all instructions in chunk
        """
        instructions = []
        curr_addr = start_addr
        while curr_addr < ret_addr:
            instr = self.view.get_disassembly(curr_addr)

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
            if instr in self.ret_instrs.keys():
                return None

            instructions.append(instr)
            curr_addr += self.view.get_instruction_length(curr_addr)

        # ret opcode was included in last instruction calculation
        if curr_addr != ret_addr:
            return None

        return instructions

    def _calculate_gadget_from_ret(self, baseaddr, ret_addr):
        """Decrement index from ret instruction and calculate gadgets
        """
        ret_instr = self.view.get_disassembly(ret_addr)
        for i in range(1, self.PREV_BYTE_SIZE):
            instructions = self._disas_all_instrs(ret_addr - i, ret_addr)
            if instructions == None:
                continue 

            gadget_str = ""
            for instr in instructions:
                gadget_str += "{} ; ".format(instr)

            gadget_rva = ret_addr - i - baseaddr
            self.gadgets[gadget_rva] = "{}{}".format(gadget_str, ret_instr)

    def _find_gadgets_in_data(self, baseaddr, section):
        """Find ret instructions and spawn a thread to calculate gadgets
        for each hit
        """
        for ret_instr, bytecodes in self.ret_instrs.iteritems():
            for bytecode in bytecodes:
                next_start = section.start
                next_ret_addr = 0
                while next_start < section.start + section.length:
                    next_ret_addr = self.view.find_next_data(next_start, bytecode)
                    if next_ret_addr == None:
                        break

                    # TODO: thread this
                    self._calculate_gadget_from_ret(baseaddr, next_ret_addr)
                    next_start = next_ret_addr + len(bytecode)
    
    def _generate_markdown_report(self, title):
        """Display ROP gadgets
        """
        markdown = ""
        found = []
        for addr, gadget in sorted(self.gadgets.items(), key=itemgetter(1)):
            if gadget not in found:
                markdown += "**{:08x}** ```{}```\n\n".format(addr, gadget)
                found.append(gadget)

        self.view.show_markdown_report(title, markdown)

    def run(self):
        """Locate ROP gadgets contain in executable sections of a binary
        """
        if not self.view.executable:
            return

        baseaddr = self.view.segments[0].start
        section  = self.view.get_section_by_name(".text")
        gadgets  = self._find_gadgets_in_data(baseaddr, section)
        for thread in self.threads:
            thread.join()

        if self.gadgets != {}:
            self._generate_markdown_report("ROP Gadgets")
        else:
            show_message_box("binjago: ROP Gadget Search", "Could not find any ROP gadgets")

        self.progress = ""
