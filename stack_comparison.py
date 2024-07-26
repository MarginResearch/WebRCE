import lldb

# load in lldb with `command script import <path to stack_comparison.py>`
# run in lldb with `compare_stacks` after the app spawns


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand("command script add -f stack_comparison.compare_stacks compare_stacks")


def compare_stacks(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    if not target:
        result.PutCString("No target Selected.\n")
        return
    process = target.GetProcess()
    if not process:
        result.PutCString("No process running.\n")
        return
    dump_frame_pointers(process)


def dump_frame_pointers(process):
    threads = process.get_process_thread_list()

    # dict of {"TID": ["thread name", top_of_stack_addr]}
    thread_stacks = dict()
    for t in threads:
        f = t.GetNumFrames()
        tid = str(t.GetIndexID())
        name = t.GetName()
        if name is None and tid == "1":
            name = "main"
        for i in range(f):
            fp = t.GetFrameAtIndex(i).GetFP()
            if tid not in thread_stacks:
                thread_stacks[tid] = (name, fp)
            elif thread_stacks[tid][1] < fp:
                thread_stacks[tid] = (name, fp)
    thread_stacks = {k: v for k, v in sorted(thread_stacks.items(), key=lambda item: item[1][1])}
    for (k, v) in thread_stacks.items():
        if v[0] is None:
            continue
        print("{:08x}: {} - {}".format(v[1] - thread_stacks["1"][1], v[0], thread_stacks["1"][0]))
