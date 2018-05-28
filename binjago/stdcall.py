"""stdcall.py: Includes functionality for identifying symbol referneces
for libc or Windows API calls
"""

from binaryninja import *
from collections import OrderedDict

class StdCallSearch(BackgroundTaskThread):
    """Helper class that assists in locating and applying comments where there
    are references to interesting standard calls
    """
    def __init__(self, view):
        BackgroundTaskThread.__init__(self, "", True)
        self.view = view
        self.markdown = ""
        self.progress = "binjago: Searching for standard function references..."

    def _find_func_symbol_refs(self, symbol_name, params):
        """Iterate function symbol references and gather information on 
        each function call
        """
        symbols_to_process = []
        symbols = self.view.get_symbols()
        for symbol in symbols:
            name = symbol.name.replace("@IAT", "")
            if len(name) < len(symbol_name):
                continue

            if name[len(symbol_name) * -1:] == symbol_name:
                symbols_to_process.append(symbol)

        if len(symbols_to_process) == 0:
            return

        md = ""
        for symbol in symbols_to_process:
            for ref in self.view.get_code_refs(symbol.address):
                function = ref.function
                addr     = ref.address
                md_entry = ""
                comment = ""
                for name, position in params.iteritems():
                    md_entry += "  **{}**: ```{}```\n\n".format(
                        name, function.get_parameter_at(addr, None, position))
                    comment += "  {}: {}\n".format(
                        name, function.get_parameter_at(addr, None, position))

                md += "### {:08x} - {}\n".format(addr, symbol.name)
                md += md_entry
                function.set_comment(ref.address, comment)

        if md != "":
            self.markdown += md

    def run(self):
        """Search for symbol references for standard function calls
        """
        self._find_func_symbol_refs("malloc", OrderedDict([('n', 0),]))
        self._find_func_symbol_refs("realloc", OrderedDict([('ptr', 0), ('n', 1)]))
        self._find_func_symbol_refs("calloc", OrderedDict([('num', 0), ('size', 1)]))
        self._find_func_symbol_refs("memcpy", OrderedDict([('dst', 0), ('src',  1), ('n', 2)]))
        self._find_func_symbol_refs("strcpy", OrderedDict([('dst', 0), ('src', 1)]))
        self._find_func_symbol_refs("strncpy", OrderedDict([('dst', 0), ('src', 1), ('n', 2)]))
        self._find_func_symbol_refs("strlcpy", OrderedDict([('dst', 0), ('src', 1), ('n', 2)]))
        self._find_func_symbol_refs("strncat", OrderedDict([('dst', 0), ('src', 1), ('n',  2)]))
        self._find_func_symbol_refs("sprintf", OrderedDict([('dst', 0), ('src', 1), ('arg1', 2)]))
        self._find_func_symbol_refs("snprintf", OrderedDict([('dst', 0), ('size', 1), ('format', 2)]))
        self._find_func_symbol_refs("strcat", OrderedDict([('dst', 0), ('src', 1)]))
        self._find_func_symbol_refs("strlcat", OrderedDict([('dst', 0), ('src', 1), ('n', 2)]))
        self._find_func_symbol_refs("vsprintf", OrderedDict([('dst', 0), ('src', 1), ('arg_list', 2)]))
        self._find_func_symbol_refs("fwrite", OrderedDict([('ptr', 0), ('n', 1), ('count',  2), ('stream',  3)]))
        self._find_func_symbol_refs("fread", OrderedDict([('ptr', 0), ('n', 1), ('count',  2), ('stream',  3)]))
        self._find_func_symbol_refs("strcmp", OrderedDict([('str1', 0), ('str2', 1)]))
        self._find_func_symbol_refs("strncmp", OrderedDict([('str1', 0), ('str2', 1), ('num', 2)]))
        self._find_func_symbol_refs("fgets", OrderedDict([('str', 0), ('num', 1), ('stream', 2)]))
        self._find_func_symbol_refs("strlen", OrderedDict([('str', 0)]))
        self._find_func_symbol_refs("mprotect", OrderedDict([('addr', 0), ('len', 1), ('prot', 2)]))
        self._find_func_symbol_refs("mmap", OrderedDict([('addr', 0), ('len', 1), ('prot', 2), ('flags', 3), ('fd', 4), ('offset', 5)]))
        self._find_func_symbol_refs("munmap", OrderedDict([('addr', 0), ('len', 1)]))

        if self.markdown != "":
            self.view.show_markdown_report("Standard Function Search", self.markdown)
        else:
            show_message_box(
                "binjago: Standard Function Search", 
                "Could not find any memory function symbol references"
            )

        self.progress = ""
