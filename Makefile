# Mac OS

export __MAC__=1
SWITCH64=-D__EA64__
TOOLCHAIN=/usr/local/Cellar/gcc/5.3.0/bin/
CXX=$(TOOLCHAIN)g++-5
CC=$(TOOLCHAIN)gcc-5
LD= $(CC)

#LDFLAGS=-static -L/dat
CFLAGS=-Wextra -Os -D__MAC__ -m32 -arch i386 -D__IDP__ -D__PLUGIN__ -I$(SDKPATH)/include 
CXXFLAGS= -D__MAC__ $(SWITCH64) -I$(SDKPATH)/include -I$(SDKDIR)/ldr
LDFLAGS=-dynamiclib -m32 -L/Users/surge/Desktop/SDK/idasdk66/lib -lida 

SDKPATH := /Users/surge/Desktop/SDK/idasdk66
LIBIDAPATH := /Users/surge/Desktop/SDK/idasdk66/lib

SRC= ida-mbn-sbl-loader.cpp
OBJS= ida-mbn-sbl-loader.o
PLUGIN := ida-mbn-sbl-loader.pmc

all: $(pmc) $(ldw)

pmc: $(SRC)

ida-mbn-sbl-loader.cpp: $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(PLUGIN) $(OBJS) $(LDFLAGS)

ida-mbn-sbl-loader.o: $(SRC)
	$(CXX) $(CFLAGS) $(SRC) -v -c

clean:
	rm $(PLUGIN) $(OBJS)
	

# WIN32
export __EA64__=1
export __WIN32__=1
SWITCH64=-D__NT__ 
TOOLCHAIN=/usr/local/Cellar/gcc/5.3.0/bin/
CXX=$(TOOLCHAIN)g++-5
CC=$(TOOLCHAIN)gcc-5
LD= $(CC)

CXXFLAGS2=-DWIN32 -D__NT__ -D__IDP__ -I$(SDKPATH)/include -I$(SDKPATH)/ldr -mrtd
CFLAGS+=-I/Users/surge/Downloads/tcc-0.9.25-my/win32/include -I$(SDKPATH)/include -I$(SDKDIR)/ldr
LFLAGS=/Users/surge/Desktop/SDK/idasdk66/lib/x86_win_gcc_32/ida.a -Wl, -dll -shared

SDKPATH := /Users/surge/Desktop/SDK/idasdk66
LIBIDAPATH := /Users/surge/Desktop/SDK/idasdk66/lib

SRC= ida-mbn-sbl-loader.cpp
OBJS= ida-mbn-sbl-loader.o
PLUGIN= ida-mbn-sbl-loader.ldw
 
ldw: $(SRC) 

ida-mbn-sbl-loader.cpp: $(OBJS)
	$(CXX) $(CXXFLAGS2) -o $(PLUGIN) $(OBJS) $(LDFLAGS)

ida-mbn-sbl-loader.o: $(SRC)
	$(CXX) $(CFLAGS) $(SRC) -v -c


clean:
	rm $(PLUGIN) $(OBJS)
	
	
