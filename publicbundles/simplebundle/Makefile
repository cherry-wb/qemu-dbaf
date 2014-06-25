include config-bundle.mak
include $(DBAF_BUILD_PATH)/$(TARGET_DIR)/config-target.mak
include $(DBAF_BUILD_PATH)/config-host.mak

LDFLAGS="-Wl,--warn-common -Wl,-z,relro -Wl,-z,now -pie -m64 -g -rdynamic"

DEFINES= -I. -I$(DBAF_SRC_PATH)/tcg -I$(DBAF_SRC_PATH)/tcg/i386 -I$(DBAF_SRC_PATH)/linux-headers 
DEFINES+= -I$(DBAF_BUILD_PATH)/linux-headers -I/usr/include -I/usr/include/lua5.1 
DEFINES+= -I$(DBAF_SRC_PATH)/target-$(TARGET_BASE_ARCH) -I$(DBAF_BUILD_PATH)/$(TARGET_DIR) -I$(DBAF_BUILD_PATH)/ -I$(DBAF_SRC_PATH)/include 
DEFINES+= -I$(DBAF_SRC_PATH)/dbaf -I$(DBAF_SRC_PATH)/ -I$(DBAF_SRC_PATH)/fpu  -I$(DBAF_BUILD_PATH)/$(TARGET_DIR) -I$(DBAF_SRC_PATH)/slirp
DEFINES+= -D__STDC_LIMIT_MACROS -fPIC -DPIE -m64 -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DNEED_CPU_H -MMD -MP -MT -O2
DEFINES+= -Wall -Wundef -Wwrite-strings -fno-strict-aliasing -fno-common -Wendif-labels -Wmissing-include-dirs -Wempty-body 
DEFINES+= -Wformat-security -Wformat-y2k -Winit-self -Wignored-qualifiers -Wtype-limits -fstack-protector-all -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 
DEFINES+= $(GLIB_CFLAGS)
CC=/home/wb/workspace/llvm/llvm3.2/llvm-native/Release/bin/clang
CPP=/home/wb/workspace/llvm/llvm3.2/llvm-native/Release/bin/clang++
CFLAGS=-Wall -O2 -g -fPIC 
LDFLAGS=-g -shared 
LIBS+=

OBJS+= simplebundle.o bundle_interface.o plugins/SimpleBundlePlugin.o
OBJS+= plugins/BasicBlockSignalPlugin.o
OBJS+= plugins/Kernel32Hooker.o
all: simplebundle.so

SHARED_LIBS+=

%.o: %.c 
	$(CC) $(CFLAGS) $(DEFINES) -c -o $@ $<

%.o: %.cpp
	$(CPP) $(CFLAGS) $(DEFINES) -c -o $@ $<
	
#simplebundle.o: CFLAGS+= --std=c99

simplebundle.so: $(SHARED_LIBS) $(OBJS)
	$(CPP) $(LDFLAGS) $^ -o $@ $(LIBS)
#	ar cru libsimplebundle.a $@

simplebundle-static.so: $(OBJS)
	$(CPP) -static-libgcc -Wl,-static $(LDFLAGS) $^ -o $@ $(LIBS)

clean:
	rm -f *.o *.d *.so *.a *~ plugins/*.o plugins/*.d

realclean:
	rm -f *.o  *.d *.so *.a *~ plugins/*.o plugins/*.d

# Include automatically generated dependency files
-include $(wildcard *.d)

