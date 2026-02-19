PLUGIN_NAME = matter-dissector

# Example for RasPi: CROSS_COMPILE=arm-linux-gnueabihf- make
CROSS_COMPILE ?=
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
CC  ?= $(CROSS_COMPILE)clang
CXX ?= $(CROSS_COMPILE)clang++
LD  ?= $(CXX)
AR  = $(CROSS_COMPILE)ar
else
CC  ?= $(CROSS_COMPILE)gcc
CXX ?= $(CROSS_COMPILE)g++
LD  ?= $(CXX)
AR  = $(CROSS_COMPILE)ar
endif

#CC  = $(CROSS_COMPILE)clang
#CXX = $(CROSS_COMPILE)clang++
#LD  = $(CROSS_COMPILE)ld
#AR  = $(CROSS_COMPILE)llvm-ar

WIRESHARK_SRC_DIR ?= ../wireshark-4.6.3
WIRESHARK_BUILD_DIR ?= $(WIRESHARK_SRC_DIR)/build
WIRESHARK_INCLUDE_DIR ?= $(WIRESHARK_SRC_DIR)/include
WIRESHARK_UTIL_DIR ?= $(WIRESHARK_SRC_DIR)/wsutil

WIRESHARK_CFLAGS = -I$(WIRESHARK_SRC_DIR) -I$(WIRESHARK_BUILD_DIR) -I$(WIRESHARK_INCLUDE_DIR) -I$(WIRESHARK_UTIL_DIR)

WIRESHARK_LDFLAGS =

MATTER_ROOT ?= MatterMinimal

MATTER_CFLAGS = -I$(MATTER_ROOT)/include -DHAVE_MALLOC -DHAVE_FREE

ifeq ($(MATTER_ROOT),MatterMinimal)
MATTER_SRCS =											\
	$(MATTER_ROOT)/src/lib/core/MatterTLVReader.cpp		\
	$(MATTER_ROOT)/src/lib/support/MatterNames.cpp		\
	$(MATTER_ROOT)/src/lib/support/ErrorStr.cpp			\
	$(MATTER_ROOT)/src/lib/support/StatusReportStr.cpp
else
MATTER_LDFLAGS = -L$(MATTER_ROOT)/x86_64-unknown-linux-gnu/lib -lMatter
endif

#PKG_CONFIG_FLAGS = \
#	PKG_CONFIG_SYSTEM_LIBRARY_PATH=/usr/lib/arm-linux-gnueabihf/lib \
#	PKG_CONFIG_SYSTEM_INCLUDE_PATH=/usr/lib/arm-linux-gnueabihf/include \
#	PKG_CONFIG_ALLOW_CROSS=1

GLIB_CFLAGS ?= $(shell pkg-config --cflags glib-2.0)
GLIB_LDFLAGS ?= $(shell pkg-config --libs  glib-2.0)

OPENSSL_CFLAGS ?= $(shell pkg-config --cflags openssl)
OPENSSL_LDFLAGS ?= $(shell pkg-config --libs openssl)

OPT_FLAGS ?= -g3 -O0

WARN_FLAGS ?= -Wall

CFLAGS = -ffunction-sections -fdata-sections $(GLIB_CFLAGS) $(OPENSSL_CFLAGS) $(WIRESHARK_CFLAGS) $(MATTER_CFLAGS) $(WARN_FLAGS) $(OPT_FLAGS) -fPIC -DPIC
CXXFLAGS = $(CFLAGS) -std=c++11

LDFLAGS = $(GLIB_LDFLAGS) $(WIRESHARK_LDFLAGS) $(MATTER_LDFLAGS) $(OPENSSL_LDFLAGS) $(OPT_FLAGS) -lstdc++

ifeq ($(UNAME_S),Darwin)
PLUGIN_OUT = matter-dissector.so
LDFLAGS += -Wl,-install_name,$(PLUGIN_NAME).so -Wl,-undefined,dynamic_lookup
else
PLUGIN_OUT = matter-dissector.so
LDFLAGS += -Wl,-soname=$(PLUGIN_NAME).so -Wl,-Map -Wl,$(PLUGIN_NAME).map -Wl,--cref -Wl,--exclude-libs=ALL -Wl,--gc-sections
endif

WIRESHARK_PLUGIN_VER ?= 4-6
ifeq ($(UNAME_S),Darwin)
INSTALL_PLUGIN_DIR ?= $(WIRESHARK_BUILD_DIR)/run/Wireshark.app/Contents/PlugIns/wireshark/$(WIRESHARK_PLUGIN_VER)/epan
else
INSTALL_PLUGIN_DIR ?= ~/.local/lib/wireshark/plugins/$(WIRESHARK_PLUGIN_VER)/epan
endif

DISSECTOR_SRCS := packet-matter.cpp packet-matter-decrypt.cpp packet-matter-echo.cpp packet-matter-common.cpp packet-matter-im.cpp packet-matter-security.cpp packet-matter-udc.cpp
SRCS := $(DISSECTOR_SRCS) $(MATTER_SRCS) TLVDissector.cpp MatterMessageTracker.cpp MessageEncryptionKey.cpp UserEncryptionKeyPrefs.cpp UserNodeIdPrefs.cpp HKDF.c
HEADERS = moduleinfo.h  packet-matter.h packet-matter-decrypt.h TLVDissector.h MatterMessageTracker.h MessageEncryptionKey.h UserEncryptionKeyPrefs.h UserNodeIdPrefs.h HKDF.h
OBJS := $(foreach src, $(SRCS), $(src:.c=.o))
OBJS := $(foreach src, $(OBJS), $(src:.cpp=.o))

TEST_INPUT ?= tests/chip_tool_test_TestCluster_22f09.pcapng
TEST_ECHO ?= tests/matter_echo.pcapng

TEST_SRCS := tests/test-packet-matter-decrypt.cpp
#TEST_SRCS  = $(shell find . -maxdepth 1 -name 'tests/*.c')
#TEST_SRCS += $(shell find . -maxdepth 1 -name 'tests/*.cpp')

TEST_OBJS := $(patsubst %.c, %.o,$(filter %.c,  $(TEST_SRCS)))
TEST_OBJS += $(patsubst %.cpp,%.o,$(filter %.cpp, $(TEST_SRCS)))

TEST_EXES := $(patsubst %.o, %.exe,$(filter %.o,  $(TEST_OBJS)))

.PHONY : all install clean test

all : $(PLUGIN_OUT)

$(PLUGIN_OUT) : $(OBJS) $(SRCS) $(HEADERS)
	$(CXX) -shared $(OBJS) $(LDFLAGS) -o $@

#$(TEST_EXES) : $(TEST_OBJS)
#	$(CC) $^ $(LDFLAGS) $(LIBS) -o $@

tests/test-packet-matter-decrypt.exe: tests/test-packet-matter-decrypt.o packet-matter-decrypt.o
	$(CC) -o $@ $^ $(LDFLAGS) -lpthread -ldl


install : $(PLUGIN_OUT)
	mkdir -p $(INSTALL_PLUGIN_DIR)
	cp $(PLUGIN_OUT) $(INSTALL_PLUGIN_DIR)

test : install
	WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1 $(WIRESHARK_BUILD_DIR)/run/wireshark $(TEST_INPUT)

testecho : install
	WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1 $(WIRESHARK_BUILD_DIR)/run/wireshark $(TEST_ECHO)

debug : install
	WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1 libtool --mode=execute gdb $(WIRESHARK_BUILD_DIR)/run/wireshark -ex "set args $(TEST_INPUT)"

debugecho : install
	WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1 libtool --mode=execute gdb $(WIRESHARK_BUILD_DIR)/run/wireshark -ex "set args $(TEST_ECHO)"

check: install $(TEST_EXES)
	tests/test-packet-matter-decrypt.exe

clean :
	rm -f $(OBJS) $(PLUGIN_NAME).so $(PLUGIN_NAME).dylib *.map tests/*.exe

### Generic rules based on extension
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

%.o: %.cc
	$(CXX) -c $(CXXFLAGS) $< -o $@

%.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $< -o $@
