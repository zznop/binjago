"""triage.py: Includes functionality for automating the discovery of 
interesting segments of code in the current binary
"""

from binaryninja import *
from collections import OrderedDict

class BinTriage(BackgroundTaskThread):
    """Helper class that assists in triaging the binary to 
    identify sections of code worth analyzing.
    """
    def __init__(self, view):
        BackgroundTaskThread.__init__(self, "", True)
        self.view = view
        self.markdown = ""
        self.progress = "binjago: Triaging the binary..."

    def _find_memory_write_func(self, symbol_name, params):
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

                md += "### 0x{:x} - {}\n".format(addr, symbol.name)
                md += md_entry
                function.set_comment(ref.address, comment)

        if md != "":
            self.markdown += md

    def run(self):
        """Search for calls to functions that manipulate chunks of memory
        """
        self._find_memory_write_func("malloc", OrderedDict([('n', 0),]))
        self._find_memory_write_func("realloc", OrderedDict([('ptr', 0), ('n', 1)]))
        self._find_memory_write_func("memcpy", OrderedDict([('dst', 0), ('src',  1), ('n', 2)]))
        self._find_memory_write_func("strcpy", OrderedDict([('dst', 0), ('src', 1)]))
        self._find_memory_write_func("strncpy", OrderedDict([('dst', 0), ('src', 1), ('n', 2)]))
        self._find_memory_write_func("strlcpy", OrderedDict([('dst', 0), ('src', 1), ('n', 2)]))
        self._find_memory_write_func("strncat", OrderedDict([('dst', 0), ('src', 1), ('n',  2)]))
        self._find_memory_write_func("sprintf", OrderedDict([('dst', 0), ('src', 1), ('arg1', 2)]))
        self._find_memory_write_func("snprintf", OrderedDict([('dst', 0), ('size', 1), ('format', 2)]))
        self._find_memory_write_func("strcat", OrderedDict([('dst', 0), ('src', 1)]))
        self._find_memory_write_func("strlcat", OrderedDict([('dst', 0), ('src', 1), ('n', 2)]))
        self._find_memory_write_func("vsprintf", OrderedDict([('dst', 0), ('src', 1), ('arg_list', 2)]))
        self._find_memory_write_func("fwrite", OrderedDict([('ptr', 0), ('n', 1), ('count',  2), ('stream',  3)]))
        self._find_memory_write_func("fread", OrderedDict([('ptr', 0), ('n', 1), ('count',  2), ('stream',  3)]))

        if self.markdown != "":
            self.view.show_markdown_report("Memory Function References", self.markdown)
        else:
            show_message_box(
                "binjago: Memory Function Search", 
                "Could not find any memory function symbol references"
            )

        self.progress = ""
