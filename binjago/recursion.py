"""recursion.py: locate recursive functions in a binary
"""

from binaryninja import *

class RecursionSearch(BackgroundTaskThread):
    """Class that assists in finding recursive logic and attempts to check
    if it is unbounded
    """
    def __init__(self, view):
        BackgroundTaskThread.__init__(self, "", True)
        self.view = view
        self.progress = "binjago: Searching for recursive logic..."
        self.call_dests = {}
        self.markdown = ""

    def _check_callee_callback(self):
        """Check if any of the destination functions callback to a caller function
        """
        for caller_func, entries in self.call_dests.iteritems():
            for entry in entries:
                if not self.call_dests.has_key(entry['callee']):
                    continue

                for entry2 in self.call_dests[entry['callee']]:
                    if caller_func == entry2['callee']:
                        # add comments
                        func = self.view.get_function_at(caller_func)
                        func.set_comment(caller_func, "This function contains recursion (calls {})".format(self.view.get_symbol_at(entry['callee']).name))
                        func.set_comment(entry['caller'], "This instruction is part of recursive logic")

                        # craft markdown entry
                        self.markdown += "### {:08x} - {}\n\n".format(
                            caller_func, self.view.get_symbol_at(caller_func).name)
                        self.markdown += "**{:08x}**: ```{} (caller)```\n\n".format(
                            entry['caller'], self.view.get_disassembly(entry['caller']))
                        self.markdown += "**{:08x}**: ```{} (callee)```\n\n\n".format(
                            entry['callee'], self.view.get_symbol_at(entry['callee']).name) 

    def _enum_call_dests(self):
        """Iterate instructions, find calls, and populate call_dests dictionary
        """
        for func in self.view:
            func_addr = func.start
            for block in func.medium_level_il.ssa_form:
                for instr in block:
                    if instr.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                        if instr.dest.operation != MediumLevelILOperation.MLIL_CONST_PTR:
                            continue

                        if not self.call_dests.has_key(func_addr):
                            self.call_dests[func_addr] = [{'caller' : instr.address, 'callee' : instr.dest.constant},]
                        else:
                            self.call_dests[func_addr].append({'caller' : instr.address, 'callee' : instr.dest.constant})

    def run(self):
        self._enum_call_dests()
        self._check_callee_callback()
        if self.markdown != "":
            self.view.show_markdown_report("Recursive Function Search", self.markdown)
        else:
            show_message_box(
                "binjago: Recursion search", 
                "Could not find any recursive logic"
            )
        self.progress = ""
