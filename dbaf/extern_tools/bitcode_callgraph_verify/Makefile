include config-tools.mak

TOOL_NAME=bitcode_callgraph_verifier

# Include files and lib from LLVM
CXXFLAGS+=$(LLVM_CXXFLAGS)
LIBS+=$(LLVMLIBS)

CC=$(CLANG_CC)
CXX=$(CLANG_CXX)

all: $(TOOL_NAME)

%.o: %.c 
	$(CC) $(CFLAGS) $(DEFINES) -c -o $@ $<

%.o: %.cpp
	$(CPP) $(CFLAGS) $(DEFINES) -c -o $@ $<
	

$(TOOL_NAME): $(TOOL_NAME).cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f *.o *.d *.so *.a

realclean:
	rm -f *.o  *.d *.so *.a

# Include automatically generated dependency files
-include $(wildcard *.d)