from binaryninja import *
from binjago import *

def find_func_symbol_refs(view):
    bt = StdCallSearch(view)
    bt.start()

def find_rop_gadgets(view):
    rop_search = ROPSearch(view)
    rop_search.start()

def find_prologues(view):
    sig_search = PrologSearch(view)
    sig_search.start()

PluginCommand.register(
    "binjago: Find standard function references",
    "Locate and annotate symbol references for standard API calls",
    find_func_symbol_refs
)

PluginCommand.register(
    "binjago: Find ROP gadgets",
    "Search .text for ROP gadgets",
    find_rop_gadgets
)

PluginCommand.register(
    "binjago: Find function prologues",
    "Search binary files for function prologues",
    find_prologues
)
