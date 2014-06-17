dbaf = {
    welcome = "welcome to use DBAF.",
	version = "0.1",
}

plugins = {
--	"SignalTesterPlugin"
--	"WindowsMonitor",
	"SimpleBundlePlugin",
--	"BasicBlockSignalPlugin",
--	"HookManager",
--	"Kernel32Hooker",
}
pluginsConfig = {
}
pluginsConfig.BasicBlockSignalPlugin ={
		so_path = "/home/wb/workspace/qemu-dbaf/publicbundles/simplebundle/simplebundle.so",--如果这个参数不为空，且文件存在，那么系统将首先将库文件加载进内存，并调用其init_bundle函数
								   --如果是卸载这个插件，则不会将其移除内存，而只是调用其disable_bundle函数
		filename = "logger.txt",
}
pluginsConfig.SimpleBundlePlugin ={
		so_path = "/home/wb/workspace/qemu-dbaf/publicbundles/simplebundle/simplebundle.so",--如果这个参数不为空，且文件存在，那么系统将首先将库文件加载进内存，并调用其init_bundle函数
								   --如果是卸载这个插件，则不会将其移除内存，而只是调用其disable_bundle函数
		filename = "logger.txt",
}
pluginsConfig.Kernel32Hooker ={
		so_path = "/home/wb/workspace/qemu-dbaf/publicbundles/simplebundle/simplebundle.so",--如果这个参数不为空，且文件存在，那么系统将首先将库文件加载进内存，并调用其init_bundle函数
								   --如果是卸载这个插件，则不会将其移除内存，而只是调用其disable_bundle函数
		filename = "logger.txt",
}
pluginsConfig.CorePlugin={
	trace_memory_access_code = false,
	trace_memory_access_data = true,
	trace_memory_access_kernel = false,
	trace_memory_access_user = false,
	trace_memory_access_ksmap = false,
	trace_memory_access_mmu = true,
	trace_memory_access_cmmu = false,
	trace_memory_read = true,
	trace_memory_write = true,
}
pluginsConfig.WindowsMonitor =
{
    version="XPSP3",
    ntmodulename = "ntoskrnl.exe",
    userMode= true,
    kernelMode= true,
    isASLR = false,
    monitorModuleLoad= true,
    monitorModuleUnload= true,
    monitorProcessUnload= true,
    monitorThreads= true,
    pointerSize = 4,
    KernelStart = 0x80000000,
    ntkernelNativeBase = 0x00400000,
    ntPspExitProcess = 0x004AB0E4,--// the  start pc of PspExitProcess function
    ntKeInitThread = 0x004b75fc,
    ntKeTerminateThread = 0x004214C9,
    ntIopDeleteDriverPc = 0x004EB33F,
    
    ntdllNativeBase = 0x7c920000,
    ntdllLoadBase = 0x0, --0x7c920000,
--	push    esi //winxp3 7C91E12A 7C93E12A //win7 77EE2817
--	call    _LdrpFinalizeAndDeallocateDataTableEntry@4 ; LdrpFinalizeAndDeallocateDataTableEntry(x)
--	cmp     esi, _LdrpGetModuleHandleCache
    LdrUnloadDllPc = 0x7C93E12A,
}
--pluginsConfig.WindowsMonitor =
--{
--    version="WIN7SP1",
--    ntmodulename = "ntoskrnl.exe",
--    userMode= true,
--    kernelMode= true,
--    isASLR = true,
--    monitorModuleLoad= true,
--    monitorModuleUnload= true,
--    monitorProcessUnload= true,
--    monitorThreads= true,
--    pointerSize = 4,
--    KernelStart = 0x80000000,
--    ntkernelNativeBase = 0x00400000,
--    ntPspExitProcess = 0x006205D1,--// the  start pc of PspExitProcess function
--    ntKeInitThread = 0x00714999,
--    ntKeTerminateThread = 0x004A5CDB,
--    ntIopDeleteDriverPc = 0x0059A326,
--    
--    ntdllNativeBase = 0x77EC0000,
--    ntdllLoadBase = 0x0, --0x7c920000,
----	push    esi //win7 77EE2817
----	call    _LdrpFinalizeAndDeallocateDataTableEntry@4 ; LdrpFinalizeAndDeallocateDataTableEntry(x)
----	cmp     esi, _LdrpGetModuleHandleCache
--    LdrUnloadDllPc = 0x77EE2817,
--}
function config_parsed(state,desc)--current execution state and some describe
	state:readMemory()
	state:writeMemory()
	desc:setValue("numone",911)
	print(desc:getValue("numone"))
	print("config_parsed。")
end