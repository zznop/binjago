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
        found = []
        for caller_func, entries in self.call_dests.iteritems():
            for entry in entries:
                if not self.call_dests.has_key(entry['callee']):
                    continue

                for entry2 in self.call_dests[entry['callee']]:
                    if caller_func == entry2['callee']:

                        # if we've already reported this, don't report again
                        if entry['caller'] in found:
                            continue

                        # append to found list
                        found.append(entry['caller'])

                        # add function header comment
                        func = self.view.get_function_at(caller_func)
                        callee_symbol = self.view.get_symbol_at(entry['callee'])

                        # direct or indirect recursion?
                        direct_indirect = "direct"
                        if entry['callee'] != entry2['callee']:
                            direct_indirect = "indirect"

                        # set function header comment
                        if callee_symbol:
                            func.set_comment(caller_func, "Contains {} recursion (calls {})".format(direct_indirect, callee_symbol.name))
                        else:
                            func.set_comment(caller_func, "Contains {} recursion (calls {:08x})".format(direct_indirect, entry['callee']))

                        # add instruction comment
                        func.set_comment(entry['caller'], "Recursive call")

                        # craft markdown header
                        caller_func_symbol = self.view.get_symbol_at(caller_func)
                        if caller_func_symbol:
                            self.markdown += "### {:08x} - {}\n\n".format(caller_func, caller_func_symbol.name)
                        else:
                            self.markdown += "### {:08x}\n\n".format(caller_func)

                        # craft markdown type
                        self.markdown += "**type**: {}\n\n".format(direct_indirect)
                        
                        # craft markdown caller instruction
                        self.markdown += "**{:08x}**: ```{}```\n\n".format(
                            entry['caller'], self.view.get_disassembly(entry['caller']))

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
