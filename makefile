PROJ_NAME = mdbg
EXE_EXT = exe

# compiler/linker
CC = clang
LD = lld-link

# flags
CC_FLAGS_FILE = compile_flags.txt
CC_FLAGS = $(shell type $(CC_FLAGS_FILE))

CC_FLAGS_DEBUG_MODE = -g3 -O0 -fuse-ld=lld

CC_FLAGS_RELEASE_MODE = -g3 -O2 -fuse-ld=lld -flto -Wl,/LTCG

CC_FLAGS_DEBUG = $(CC_FLAGS_DEBUG_MODE) $(CC_FLAGS)
CC_FLAGS_RELEASE = $(CC_FLAGS_RELEASE_MODE) $(CC_FLAGS)

# directories
SRC_DIR = src
BIN_DIR = bin
BUILD_DIR = build

# normal source files
SRCS = $(SRC_DIR)/main_win32.c
# SRCS += $(wildcard $(SRC_DIR)/common/*.cpp)

# platform source files
# SRCS += $(wildcard $(SRC_DIR)/platform/windows/*.c)

DEBUG_OBJS = $(SRCS:src/%.c=$(BUILD_DIR)/debug/%.o)
DEBUG_DEPS = $(DEBUG_OBJS:%.o=%.d)

RELEASE_OBJS = $(SRCS:src/%.c=$(BUILD_DIR)/release/%.o)
RELEASE_DEPS = $(RELEASE_OBJS:%.o=%.d)

# output file names
DEBUG_FNAME 	:= debug.$(EXE_EXT)
RELEASE_FNAME 	:= release.$(EXE_EXT)

all: debug release

release: $(BIN_DIR)/$(RELEASE_FNAME)

$(BIN_DIR)/$(RELEASE_FNAME): $(RELEASE_OBJS)
	$(shell if not exist "$(@D)" mkdir "$(@D)")
	$(CC) -o $(BIN_DIR)/$(RELEASE_FNAME) $(CC_FLAGS_RELEASE) $(RELEASE_OBJS)

-include $(RELEASE_DEPS)

$(BUILD_DIR)/release/%.o: $(SRC_DIR)/%.c
	$(shell if not exist "$(@D)" mkdir "$(@D)")
	$(CC) -o $@ $(CC_FLAGS_RELEASE) -c $< -MMD

debug: $(BIN_DIR)/$(DEBUG_FNAME)

$(BIN_DIR)/$(DEBUG_FNAME): $(DEBUG_OBJS)
	$(shell if not exist "$(@D)" mkdir "$(@D)")
	$(CC) -o $(BIN_DIR)/$(DEBUG_FNAME) $(CC_FLAGS_DEBUG) $(DEBUG_OBJS)

-include $(DEBUG_DEPS)

$(BUILD_DIR)/debug/%.o: $(SRC_DIR)/%.c
	$(shell if not exist "$(@D)" mkdir "$(@D)")
	$(CC) -o $@ $(CC_FLAGS_DEBUG) -c $< -MMD

.PHONY: clean
clean:
	$(shell if exist "$(BIN_DIR)" rmdir /s /q "$(BIN_DIR)")
	$(shell if exist "$(BUILD_DIR)" rmdir /s /q "$(BUILD_DIR)")
