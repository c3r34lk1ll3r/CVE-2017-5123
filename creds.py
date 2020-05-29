__AUTHOR__ = "c3r34lk1ll3r"
__VERSION__ = 0.1

import os, tempfile
import gdb

class CachedType:
    def __init__(self, name):
        self._type = None
        self._name = name

    def _new_objfile_handler(self, event):
        self._type = None
        gdb.events.new_objfile.disconnect(self._new_objfile_handler)

    def get_type(self):
        if self._type is None:
            self._type = gdb.lookup_type(self._name)
            if self._type is None:
                raise gdb.GdbError(
                    "cannot resolve type '{0}'".format(self._name))
            if hasattr(gdb, 'events') and hasattr(gdb.events, 'new_objfile'):
                gdb.events.new_objfile.connect(self._new_objfile_handler)
        return self._type


long_type = CachedType("long")

def get_long_type():
    global long_type
    return long_type.get_type()

def offset_of(typeobj, field):
    element = gdb.Value(0).cast(typeobj)
    return int(str(element[field].address).split()[0], 16)

def container_of(ptr, typeobj, member):
    return (ptr.cast(get_long_type()) -
            offset_of(typeobj, member)).cast(typeobj)

task_type = CachedType("struct task_struct")

v = gdb.lookup_type('struct task_struct').pointer()
# For KASLR
#offset = 0xe0f480 + 0xffffffff8a400000
#addr = gdb.Value(offset)
#init = addr.cast(v)
init = gdb.parse_and_eval("init_task").address
def task_lists():
    task_ptr_type = task_type.get_type().pointer()
    t = g = init
    while True:
        while True:
            yield t

            t = container_of(t['thread_group']['next'],
                               task_ptr_type, "thread_group")
            if t == g:
                break

        t = g = container_of(g['tasks']['next'],
                               task_ptr_type, "tasks")
        if t == init:
            return
# Store the address in a file
f = open("kasl1",'w')
for task in task_lists():
    #gdb.write("{address} {pid} {comm}\n".format(
    #    address=task,
    #    pid=task["pid"],
    #    comm=task["comm"].string()))
    comm = task["comm"].string()
    if comm == "exploit":
        print(task['cred'])
        f.write(str(task['cred']))
        f.write("\n")
f.close()
