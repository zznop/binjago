from binaryninja import *
from collections import OrderedDict

class VulnSearch(BackgroundTaskThread):
    """Helper class to aid in locating vulnerabilities in code
    """
    def __init__(self, view):
        BackgroundTaskThread.__init__(self, "", True)
        self.view = view

    def _find_memory_write_func(self, symbol_name, params):
        """Find memory write function references and display source,
        destination, and size information
        """
        symbol = self.view.get_symbol_by_raw_name(symbol_name)
        if symbol == None:
            return

        for ref in self.view.get_code_refs(symbol.address):
            function = ref.function
            addr     = ref.address
            print "{} - {:x}".format(symbol_name, addr)
            for name, position in params.iteritems():
                print "  {}: {}".format(name, function.get_parameter_at(addr, None, position))
            print "\n"

    def find_memory_writes(self):
        """Search for memcpy and memcpy-like functions
        """
        self._find_memory_write_func("memcpy", OrderedDict([('dst', 0), ('src',  1), ('n', 2)]))
        self._find_memory_write_func("strcpy", OrderedDict([('dst', 0), ('src', 1)]))
        self._find_memory_write_func("strncpy", OrderedDict([('dst', 0), ('src', 1), ('n', 2)]))
        self._find_memory_write_func("strncat", OrderedDict([('dst', 0), ('src', 1), ('n',  2)]))
        self._find_memory_write_func("sprintf", OrderedDict([('dst', 0), ('src', 1), ('arg1', 2)]))
        self._find_memory_write_func("snprintf", OrderedDict([('dst', 0), ('size', 1), ('format', 2)]))
        self._find_memory_write_func("strcat", OrderedDict([('dst', 0), ('src', 1)]))
        self._find_memory_write_func("vsprintf", OrderedDict([('dst', 0), ('src', 1), ('arg_list', 2)]))

    def _check_instr_for_uninit_ref(self, instr):
        """Check instruction for uninitialized local variable reference
        """
        if instr.operation == MediumLevelILOperation.MLIL_VAR_SSA:
            if instr.instr_index == 0:
                # exclude non-local variables
                if instr.src.var.identifier >= 0:
                    return

                if instr.src.var.source_type == VariableSourceType.StackVariableSourceType:
                    print "Uninitialized stack variable reference - {}".format(hex(instr.address))
                else:
                    print "Possibile uninitialized local variable reference - {}".format(hex(instr.address))
        else:
            for operand in instr.operands:
                if isinstance(operand, MediumLevelILInstruction):
                    self._check_instr_for_uninit_ref(operand)

    def find_uninitialized_var_refs(self):
        """Locate locations where an uninitialized variable may get referenced
        """
        for func in self.view.functions:
            for block in func.medium_level_il.ssa_form:
                for instr in block:
                    self._check_instr_for_uninit_ref(instr)