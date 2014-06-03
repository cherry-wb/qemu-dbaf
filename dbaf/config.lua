dbaf = {
    welcome = "welcome to use DBAF.",
	version = "0.1",
}

plugins = {
--	"SignalTesterPlugin"
	"SimpleBundlePlugin",
	"BasicBlockSignalPlugin",
}
plugins.BasicBlockSignalPlugin ={
		so_path = "/home/wb/workspace/qemu-dbaf/publicbundles/simplebundle/simplebundle.so",--如果这个参数不为空，且文件存在，那么系统将首先将库文件加载进内存，并调用其init_bundle函数
								   --如果是卸载这个插件，则不会将其移除内存，而只是调用其disable_bundle函数
		filename = "logger.txt",
}
plugins.SimpleBundlePlugin ={
		so_path = "/home/wb/workspace/qemu-dbaf/publicbundles/simplebundle/simplebundle.so",--如果这个参数不为空，且文件存在，那么系统将首先将库文件加载进内存，并调用其init_bundle函数
								   --如果是卸载这个插件，则不会将其移除内存，而只是调用其disable_bundle函数
		filename = "logger.txt",
}
function config_parsed(state,desc)--current execution state and some describe
	state:readMemory()
	state:writeMemory()
	desc:setValue("numone",911)
	print(desc:getValue("numone"))
	print("config_parsed。")
end