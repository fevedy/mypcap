appname := forward_data

PWD := $(shell pwd)

CXX := g++
CXXFLAGS := -Wall -g -std=c++0x 


INC_DIRS += $(PWD)
INC_DIRS += /yszhang/thirdPartyLib/include
INC_DIRS += /yszhang/src/SocketUtils
INC_FLAGS := $(addprefix -I,$(INC_DIRS))
CXXFLAGS += $(INC_FLAGS)

srcfiles := $(shell find . -maxdepth 1 -name "*.cpp")
objects  := $(patsubst %.cpp, %.o, $(srcfiles))

LDFLAGS := -L/yszhang/thirdPartyLib/lib

#LDLIBS := -lfl
#LDLIBS += -lfl_pic
LDLIBS += -ljson_linux-gcc-4.4.7_libmt
LDLIBS += -lpcap
#LDLIBS += -ly

all: $(appname)

$(appname): $(objects)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(appname) $(objects) $(LDLIBS)

depend: .depend

.depend: $(srcfiles)
	rm -f ./.depend
	$(CXX) $(CXXFLAGS) -MM $^>>./.depend;

clean:
	rm -f $(objects)

distclean: clean
	rm -f *~ .depend

include .depend
