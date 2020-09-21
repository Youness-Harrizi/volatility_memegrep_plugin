# parameters -p <pid>
# with parameters
import volatility.plugins.common as common
import volatility.utils as utils
import volatility.win32 as win32
from volatility.renderers import TreeGrid
from volatility.plugins.malware.malfind import BaseYaraScanner
from volatility.plugins.envars import Envars as envars
import volatility.obj as obj
import volatility.plugins.vadinfo as vadinfo

try:
    import re
    import struct
    has_re = True
except ImportError:
    has_re=False
    print "you need to get re and or struct  "

# handle parameters

# functions of locky to be changed : external functions
def read_bytes(address, a, length=4):
    return a.read(address, length)
def read_long(addr,a):
        string = self.read(addr, 4)
        longval, = a._long_struct.unpack(string)
        return longval


def deref(address, a, length=4):
    # a is address space
    try:
        d = struct.unpack("<I", a.read(address, length))[0]
        return d
    except struct.error:
        return None

# check an address space
# print many info about it

def check_addr_space(addr_space):
    if addr_space.base:
        print "addr_space.base"+str(addr_space.base)

    if addr_space.base.base:
        print "addr_space.base.base"+str(addr_space.base.base)
    # get the task PID
def get_task_pid( task):

    return task.UniqueProcessId

def getBaseAddress(addr_space):
    if addr_space.base:
        return addr_space.base
    else:
        print "This is already a physical kernel"
        return None

# def get Environment variables :




class project_v1(common.AbstractWindowsCommand):
    ''' My plugin '''
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('PID', short_option = 'p', default = None, help = 'type your pid',
            action = 'store')
        self._config.add_option('REGEX', short_option = 'r',
                      help = 'Dump dlls matching REGEX',
                      action = 'store', type = 'string')
        self._config.add_option( "IGNORE_CASE",short_option="I",action="store_true")
        # for Environment variables
        self_envars=envars( self._config, *args, **kwargs)
        global environment_variables
        environment_variables=self_envars._get_silent_vars()
        #print "environment variables : {}".format(environment_variables)

        # add a verbose parameter
    # get processes from a specific address space
    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows')
    def generateProcesses(self,addr_space):
        tasks = win32.tasks.pslist(addr_space)
        return tasks



    def compile_regex(self):
        # retur, the pattern
        if not self._config.REGEX:
            print 'you must give a string/regex as a parameter'
            exit(0)
        if self._config.IGNORE_CASE:
                print "IGNORE CASE IS PRESENT"
                mod_re = re.compile(self._config.REGEX, re.I)
        else:
                mod_re = re.compile(self._config.REGEX)
        print "SUCCESSFULL COMPILATION"
        return mod_re



    # FILTER processes if pid parameter is given
    def filter_tasks(self,tasks):
        if self._config.PID is not None:
            #print 'PID specified'
            try:
                pidlist = [int(p) for p in self._config.PID.split(',')]
            except ValueError:
                print "Invalid PID {0}".format(self._config.PID)

            pids = [t for t in tasks if get_task_pid(t) in pidlist]
            if len(pids) == 0:
                print "Cannot find PID {0}. If its terminated or unlinked, use psscan and then supply --offset=OFFSET".format(self._config.PID)
            return pids




    def calculate(self):
        #The returned data will be passed as data to render_text
        if not has_re:
            debug.error("Please install re ")

        addr_space = utils.load_as(self._config) ###????
        # maybe I should add kernel space ?????????
        if not self.is_valid_profile(addr_space.profile):
            debug.error("This command does not support the selected profile.")
        #check_addr_space(addr_space)
        base=getBaseAddress(addr_space)

        if not self.is_valid_profile(addr_space.profile):
            debug.error("This command does not support the selected profile.")
        # get a list of all all processes runing from the memory dump
        tasks = self.generateProcesses(addr_space)
        pids = self.filter_tasks(tasks) # HOW TO USE IT ???
        if self._config.PID is not None:
            return pids,addr_space
        print "type tasks"+str(type(tasks))
        # create a new generator : and add only the new elements

        return tasks,addr_space





    def generator(self, data):
        mod_re=self.compile_regex()

        tasks,addr_space=data[0],data[1]
        # initialised data
        # return [match,memory vs kernel]






        for task in tasks:
            kernel,allocated=0,1
            heapBool,stackBool,dllBool=0,0,0
            for var, val in task.environment_variables():
                x=re.findall(mod_re,str(val))
                y=re.findall(mod_re,str(var))
                if x or y :
                    print "MATCH IN ENVIRONMENT VARIABLES: "
                    print("environment variables {} : values :  {}".format(var,val))

                    yield (0, [
                                int(task.UniqueProcessId),
                                str(task.ImageFileName),
                                "Environment variable",
                                len(var),
                                "",
                                "",1,"",0
                            ]) # to be changed

            proc_address_space=task.get_process_address_space()


            for vad in task.VadRoot.traverse():
                # read the VAD content
                # shows only allocated memory segments for this project
                flag=0
                data_vad = proc_address_space.zread(vad.Start, vad.Length)
                matches =  re.findall(mod_re,data_vad)
                if matches:
                    print("\n==========")
                    print "{} matches found at task {} ".format(len(matches),task.ImageFileName)
                    #print "match[0] : "+str(matches[0])
                    #match_offset = vad.Start + matches[0].strings[0][0] # See the Yara-python documentation for this
                    match_offset = vad.Start
                    # as a first step, we try to get the physical offset of the
                        # _EPROCESS object using the process address space
                    physical_offset = proc_address_space.vtop(task.obj_offset)
                          # if this fails, we'll get its physical offset using kernel space
                    if physical_offset == None:
                            physical_offset = task.obj_vm.vtop(task.obj_offset)
                            kernel=1
                            print "kernel space!!!"
                    else :
                             print "Memory space !!!"
                          # if this fails we'll manually set the offset to 0

                    if physical_offset == None:
                            physical_offset = 0
                            print "unallocated Block : in disk"
                            allocated=0

                    # we should add to the offset the position of the string ???
                    offset = match_offset + 1 # The "??"s start one byte after 0xA1
                    print " Virtual match found at offset 0x{:x}!".format( offset)
                    print " PHYSICAL  match found at offset 0x{}!".format( hex(physical_offset))
                    #heaps = task.Peb.ProcessHeaps.dereference_as("_HEAP")
                    heaps = task.Peb.ProcessHeaps.dereference()
                    entry_size = task.obj_vm.profile.get_obj_size("_HEAP_ENTRY")
                    heapTexts=[]


                    # collect texts in heaps
                    #print("segments methods : {}".format([method_name for method_name in dir(heaps) if callable(getattr(heaps, method_name))]))
                    ## what is heaps.is_valid()






                    physical_heaps=[]
                    for heap in heaps:
                        physical_heaps.append(proc_address_space.vtop(heap.obj_offset))

                    modules = [mod.DllBase for mod in task.get_load_modules()]
                    stacks = []
                    for thread in task.ThreadListHead.list_of_type("_ETHREAD", "ThreadListEntry"):
                        teb = obj.Object("_TEB",
                                     offset = thread.Tcb.Teb,
                                     vm = task.get_process_address_space())
                    if teb:
                        stacks.append(teb.NtTib.StackBase)
                    protections=str(vadinfo.PROTECT_FLAGS.get(vad.VadFlags.Protection.v(), ""))
                    flag=0
                    if match_offset in heaps:
                        flag=1
                        print "The match is in : HEAP!!!"
                        print "Problem0"
                        yield (0, [
                                    int(task.UniqueProcessId),
                                    str(task.ImageFileName),
                                    str("HEAP"),
                                    int(len(matches)),
                                    str(physical_offset),
                                    str(offset),
                                    allocated,
                                    protections,
                                    kernel

                                ])

                    elif match_offset in stacks:
                        flag=1
                        print "The match is in : STACK!!!!"
                        print "Problem1"
                        yield (0, [
                                    int(task.UniqueProcessId),
                                    str(task.ImageFileName),
                                    str("STACKS"),
                                    int(len(matches)),
                                    str(physical_offset),
                                    str(offset),
                                    allocated,
                                    protections,
                                    kernel
                                ])
                    elif match_offset in modules:

                        flag=1
                        print "The match is in : DLL!!!"
                        print "Problem2"
                            #heapBool,stackBool,dllBool=0,0,1
                        yield (0, [int(task.UniqueProcessId),
                                        str(task.ImageFileName),
                                        str("DLL"),
                                        int(len(matches)),
                                        str(physical_offset),
                                        str(offset),
                                        allocated,
                                        protections,
                                        kernel
                                    ])
                    else :

                        try:
                            if  vad.FileObject.FileName:
                                flag=1
                                print "Problem3"
                                yield (0, [
                                        int(task.UniqueProcessId),
                                        str(task.ImageFileName),
                                        str("Mapped File"),
                                        int(len(matches)),
                                        str(physical_offset),
                                        str(offset),
                                        allocated,
                                        protections,
                                        kernel
                                    ])
                        except AttributeError:
                                pass
                    if not flag:
                        print "Problem4"
                        yield (0, [
                            int(task.UniqueProcessId),
                            str(task.ImageFileName),
                            str(" Data"), # the only thing left
                            int(len(matches)),
                            str(physical_offset),
                            str(offset),
                            allocated,
                            protections,
                            kernel
                        ])


                    # now dereference the pointer to the offset
                    # dereference variable containing pointer


                    # add the Protections

                    print("protections : {}".format(str(vadinfo.PROTECT_FLAGS.get(vad.VadFlags.Protection.v(), ""))))
                    ptr = deref(offset, proc_address_space)
                    if not ptr:
                        continue
                    print " pointer: 0x{:x}".format(ptr)






                    # kernel vs process memory
                    # use is_valid_address on either the kernal AS or process address spaces

                    # heap vs stack vs data sections
        print("==========")
        print "\nfinished Scanning\n "
        print "summary : \n"



    def unified_output(self, data):
        tree = [
            ("PID", int),
            ("Name", str),
            ("STATE",str),
            ("Number of matches",int),
            ("physical offset",str),
            ("virtual offset",str),
            ("Allocated ",int),
            ("protections",str),
            ("kernel",int)
            ]
        return TreeGrid(tree, self.generator(data))
