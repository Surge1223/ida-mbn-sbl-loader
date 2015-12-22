export __EA64__=1
export __MAC__=1
export PATH=/Users/surge/Desktop/SDK/idasdk66/bin:$PATH
SWITCH64=-D__EA64__
SDKPATH=/Users/surge/Desktop/SDK/idasdk66
LIBIDAPATH=/Users/surge/Desktop/SDK/idasdk66/lib
SRC=ida-mbn-sbl-loader.cpp
OBJS=ida-mbn-sbl-loader.o
PLUGIN=ida-mbn-sbl-loader.pmc
CC=/usr/local/Cellar/gcc49/4.9.3/bin/gcc-4.9
CXX=g++
LD=/usr/local/Cellar/gcc49/4.9.3/bin/g++-4.9

CFLAGS=-Wextra -Os -D__MAC__ -m32 -arch i386 -D__IDP__ -D__PLUGIN__ -I$(SDKPATH)/include 
CXXFLAGS= -D__MAC__ $(SWITCH64) -I$(SDKPATH)/include 
LDFLAGS=-dynamiclib -m32 -L/Users/surge/Desktop/SDK/idasdk66/lib -lida -Wl

all: ida-mbn-sbl-loader.o
	$(CXX) $(CXXFLAGS) -o $(PLUGIN) $(OBJS) $(LDFLAGS)

ida-mbn-sbl-loader.o:
	$(CXX) $(CFLAGS) $(SRC) -v -c

clean:
	rm $(OBJS) $(PLUGIN) 
	
	findcrypt
