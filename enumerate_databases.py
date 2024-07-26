'''
Script to debug output a database filepath every time a read occurs in Signal
import with: `command script import <path to enumerate_databases.py>`
run with: `find_dbs`
'''

import lldb


def match_storage_adapter_function_name(module):
    for symbol in module:
        if symbol.name == "SignalServiceKit.GRDBDatabaseStorageAdapter.read<τ_0_0>(block: (SignalServiceKit.GRDBReadTransaction) throws -> τ_0_0) throws -> τ_0_0":
            return symbol
    return None


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand("command script add -f enumerate_databases.find_dbs find_dbs")


def find_dbs(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    if not target:
        result.PutCString("No target Selected.\n")
        return
    process = target.GetProcess()
    if not process:
        result.PutCString("No process running.\n")
        return

    mod = target.FindModule(lldb.SBFileSpec("SignalServiceKit"))
    if not mod:
        result.PutCString("Could not find module SSK.\n")
        return

    bp_addr = match_storage_adapter_function_name(mod)
    if bp_addr is None:
        result.PutCString("Could not find address of SignalServiceKit.GRDBDatabaseStorageAdapter.read.\n")
        return
    bp_addr = bp_addr.addr.GetLoadAddress(target)
    print(bp_addr)
    print("Setting breakpoint at " + hex(bp_addr))

    bp = target.BreakpointCreateByAddress(bp_addr)
    if not bp:
        result.PutCString("Not able to set breakpoint at " + hex(bp_addr) + ".\n")
        return

    bp.SetScriptCallbackFunction("enumerate_databases.callback")
    result.PutCString("Breakpoint set at " + hex(bp_addr) + ".\n")

    print("Ready to continue...")


def callback(frame, bp_loc, dict):
    process = frame.GetThread().GetProcess()

    GRDBDatabaseStorageAdapter = frame.FindRegister("x20").GetValueAsUnsigned()

    error = lldb.SBError()
    NSURL = process.ReadUnsignedFromMemory(GRDBDatabaseStorageAdapter + 0x18, 8, error)
    if error.Fail():
        print("Failed to read NSURL at address {0:x}: {1}".format(GRDBDatabaseStorageAdapter + 0x18,
                                                                  error.GetCString()))

    NSMutableString = process.ReadUnsignedFromMemory(NSURL + 0x18, 8, error)
    if error.Fail():
        print("Failed to read NSMutableString at address {0:x}: {1}".format(NSURL + 0x18,
                                                                            error.GetCString()))

    strlen = process.ReadUnsignedFromMemory(NSMutableString + 0x10, 1, error)
    if error.Fail():
        print("Failed to read string length at address {0:x}: {1}".format(NSMutableString + 0x10,
                                                                          error.GetCString()))

    path = process.ReadCStringFromMemory(NSMutableString + 0x11, strlen + 1, error)
    if error.Fail():
        print("Failed to read file path at address {0:x}: {1}".format(NSMutableString + 0x11,
                                                                      error.GetCString()))
    print("Reading from database at " + path)

    process.Continue()
