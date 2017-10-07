from binaryninja import *
from binjago import *

def find_memory_func_calls(view):
    bt = BinTriage(view)
    bt.find_memory_func_calls()

def find_uninitialized_var_refs(view):
    bt = BinTriage(view)
    bt.find_uninitialized_var_refs()

def find_rop_gadgets(view):
    rop_search = ROPSearch(view)
    rop_search.find_rop_gadgets()
        
PluginCommand.register(
    "binjago: Find memory function calls",
    "Locate calls to *cpy and *printf functions",
    find_memory_func_calls
)

PluginCommand.register(
    "binjago: Find ROP gadgets",
    "Search .text for ROP gadgets",
    find_rop_gadgets
)
