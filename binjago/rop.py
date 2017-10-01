"""Includes functionality for locating ROP gadgets in binaries
"""

from binaryninja import *

class ROPSearch(BackgroundTaskThread):
    """Class that aids in locating ROP gadgets in exectables
    """
    def __init__(self, view):
        BackgroundTaskThread.__init__(self, "", True)
        self.view = view
        self.MAX_INSTR_SIZE = 15

    def _calculate_instrs_from_ret(self, ret_addr):
        """Calculate all possible instructions from ret instruction
        """
        ret_instr = self.view.get_disassembly(ret_addr)
        start_addr = ret_addr - self.MAX_INSTR_SIZE
        for i in xrange(0, self.MAX_INSTR_SIZE):
            gadget = ""
            next_addr = start_addr + i
            good_gadget = True
            while next_addr < ret_addr:
                instr = self.view.get_disassembly(next_addr)
                if instr == None:
                    good_gadget = False
                    break

                gadget += "{} ; ".format(instr)
                next_addr += self.view.get_instruction_length(next_addr)

            if good_gadget:
                print "{:x}: {} {}".format(start_addr + i, gadget, ret_instr)


    def _find_gadgets_in_data(self, section):
        """Locate ret* instructions in binary and craft instructions
        """
        rets = [
            "\xc3",                   # ret
            "\xcb",                   # retf
            "\xf2\xc3",               # ret
        ]

        for ret in rets:
            next_start = section.start
            next_ret_addr = 0
            while next_start < section.start + section.length:
                next_ret_addr = self.view.find_next_data(next_start, ret)
                if next_ret_addr == None:
                    break
                self._calculate_instrs_from_ret(next_ret_addr)
                next_start = next_ret_addr + len(ret)

    def find_rop_gadgets(self):
        """Locate ROP gadgets in binary
        """
        if not self.view.executable:
            print "! binary is not executable"
            return

        section = self.view.get_section_by_name(".text")
        gadgets = self._find_gadgets_in_data(section)

        #bv.get_section_by_name
        #bv.find_next_data
        #bv.get_disassembly