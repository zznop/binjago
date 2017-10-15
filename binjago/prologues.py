"""prologues.py: identify function entry points in flat file binaries
"""

from binaryninja import *

class PrologSearch(BackgroundTaskThread):
    """Class that assists in locating function prologues in flat files binaries such as firmware
    """
    def __init__(self, view):
        BackgroundTaskThread.__init__(self, "", True)
        self.view = view
        self.signatures = {
            'Intel x86 function prologue' : ["\x55\x89\xE5\x83\xEC", "\x55\x89\xE5\x57\x56"],
            'Intel x86 NOP Instructions' : ["\x90\x90\x90\x90\x90\x90\x90\x90",],
        }
        self.max_sig_size = -8
        self.hits = {}

    def _search_chunk(self, startaddr, chunk):
        """Search chunk for signature
        """
        for key, values in self.signatures.iteritems():
            for signature in values:
                m = chunk.find(signature)
                if m >= 0:
                    self.hits[startaddr + m] = key

    def _search_for_func_prologues(self):
        """Iterate data a page at a time using BinaryReader and search for
        function prologue signatures
        """
        br = BinaryReader(self.view, Endianness.BigEndian)
        chunk = br.read(4096)
        startaddr = 0
        while True:
            self._search_chunk(startaddr, chunk)

            new_chunk = br.read(4096)
            if new_chunk == None:
                break

            chunk = chunk[self.max_sig_size:] + new_chunk
            startaddr += len(chunk) + self.max_sig_size

    def _display_report(self):
        """Generate and display the markdown report
        """
        md = ""
        for key, val in self.hits.iteritems():
            md += "**{:08x}** {}\n\n".format(key, val)

        self.view.show_markdown_report("Function Prologue Search", md)

    def run(self):
        """Locate prologues containined in binary
        """
        self._search_for_func_prologues()
        print self.hits
        if self.hits != {}:
            self._display_report()
        else:
            show_message_box(
                "binjago: Function Prologue Search", 
                "Could not find any function prologues"
            )


