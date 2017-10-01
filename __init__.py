from binaryninja import *
from binjago import *

def find_memory_writes(view):
    vuln_search = VulnSearch(view)
    vuln_search.find_memory_writes()

def find_uninitialized_var_refs(view):
    vuln_search = VulnSearch(view)
    vuln_search.find_uninitialized_var_refs()

def find_rop_gadgets(view):
    rop_search = ROPSearch(view)
    rop_search.find_rop_gadgets()
        
PluginCommand.register(
    "binjago: Find memory writes",
    "Locate calls to *cpy and *printf functions",
    find_memory_writes
)

PluginCommand.register(
    "binjago: Find uninitialized var ref's",
    "Locate addresses containing instructions that possibly reference unitialized local variables",
    find_uninitialized_var_refs
)

PluginCommand.register(
    "binjago: Find ROP gadgets",
    "Search .text for ROP gadgets",
    find_rop_gadgets
)