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
            'ARM big-endian function prologue' : ["\xe9\x2d",],
            'ARM little-endian function prologue' : ["\x2d\xe9"],
        }
        self.max_sig_size = -8
        self.hits = {}

    def _search_for_func_prologues(self):
        """Iterate data a page at a time using BinaryReader and search for
        function prologue signatures
        """
        for desc, sigs in self.signatures.iteritems():
            for sig in sigs:
                nextaddr = 0
                while True:
                    nextaddr = self.view.find_next_data(nextaddr, sig)
                    if nextaddr == None:
                        break

                    self.hits[nextaddr] = desc
                    nextaddr = nextaddr + len(sig)

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
        if self.hits != {}:
            self._display_report()
        else:
            show_message_box(
                "binjago: Function Prologue Search", 
                "Could not find any function prologues"
            )
