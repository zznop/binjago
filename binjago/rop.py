"""Includes functionality for locating ROP gadgets in binaries
"""

from binaryninja import *
from operator import itemgetter

class ROPSearch(BackgroundTaskThread):
    """Class that assists in locating ROP gadgets in exectable code segments
    """
    def __init__(self, view):
        BackgroundTaskThread.__init__(self, "", True)
        self.view = view
        self.MAX_INSTR_SIZE = 15
        self.gadgets = {}
        self.progress = None

    def _calculate_instrs_from_ret(self, baseaddr, ret_addr):
        ret_instr = self.view.get_disassembly(ret_addr)
        i = 1
        while (i < self.MAX_INSTR_SIZE):
            instr = self.view.get_disassembly(ret_addr - i)
            instr_size = self.view.get_instruction_length(ret_addr - i)
            if instr_size == i:
                gadget_rva = ret_addr - i - int(baseaddr)
                self.gadgets[gadget_rva] = "{} ; {}".format(instr, ret_instr)
            i = i + 1

    def _find_gadgets_in_data(self, baseaddr, section):
        rets = [
            "\xc3",                   # ret
            "\xcb",                   # retf
            "\xf2\xc3",               # ret
        ]

        self.progress = "Searching for ROP gadgets"
        for ret in rets:
            next_start = section.start
            next_ret_addr = 0
            while next_start < section.start + section.length:
                next_ret_addr = self.view.find_next_data(next_start, ret)
                if next_ret_addr == None:
                    break
                self._calculate_instrs_from_ret(baseaddr, next_ret_addr)
                next_start = next_ret_addr + len(ret)
    
    def _generate_markdown_report(self, title):
        markdown = ""
        found = []
        for addr, gadget in sorted(self.gadgets.items(), key=itemgetter(1)):
            if gadget not in found:
                markdown += "**0x{:x}** ```{}```\n\n".format(addr, gadget)
                found.append(gadget)

        self.view.show_markdown_report(title, markdown)

    def find_rop_gadgets(self):
        """```find_rop_gadgets``` Locate ROP gadgets in a binary
        """
        if not self.view.executable:
            print "! binary is not executable"
            return

        baseaddr = self.view.segments[0].start
        section  = self.view.get_section_by_name(".text")
        gadgets  = self._find_gadgets_in_data(baseaddr, section)
        if self.gadgets != {}:
            self._generate_markdown_report("ROP Gadgets")
        else:
            show_message_box("binjago: ROP Gadget Search", "Could not find any ROP gadgets")
