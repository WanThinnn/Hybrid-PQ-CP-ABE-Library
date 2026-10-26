# Usage: 
# make COMPILER=gcc (default on Linux/macOS)
# make COMPILER=msvc (default on Windows)
# Outputs: build/windows, build/linux, or build/macos

BUILD_ROOT = build

ifeq ($(OS),Windows_NT)
    PLATFORM = windows
    COMPILER ?= msvc
    SHELL = cmd.exe
    ifneq (,$(findstring msys,$(MAKE_HOST)))
        .SHELLFLAGS = //c
    endif
    ifneq (,$(findstring cygwin,$(MAKE_HOST)))
        .SHELLFLAGS = //c
    endif
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Darwin)
        PLATFORM = macos
    else
        PLATFORM = linux
    endif
    COMPILER ?= gcc
endif

ifeq ($(COMPILER),msvc)
    PLATFORM = windows
endif

BUILD_DIR = $(BUILD_ROOT)/$(PLATFORM)

# Directories
INC_DIR = include
VENDOR_SRC_INC_DIR = vendor
COMPAT_INC_DIR = vendor/include
DEPS_INC_DIR = build/deps/$(PLATFORM)/include
TKN20_INC_DIR = bindings/tkn20/include
SCHEMES_DIR = src/schemes
CORE_DIR = src/core
CRYPTO_DIR = src/crypto
LIB_STATIC_DIR = lib/static
LIB_DYNAMIC_DIR = lib/dynamic
TEST_DIR = tests/cpp
TEST_CASE_DIR = $(TEST_DIR)/cases

# Source files
SRCS = $(SCHEMES_DIR)/ac17.cpp \
       $(SCHEMES_DIR)/tkn20.cpp \
       $(CORE_DIR)/hybrid-cp-abe.cpp \
       $(CORE_DIR)/hybrid-oqs-abe.cpp \
       $(CRYPTO_DIR)/ml-dsa.cpp \
       $(CRYPTO_DIR)/aes-gcm.cpp

MAIN_SRC = src/main.cpp

ifeq ($(COMPILER),msvc)
    CXX = cl.exe
    CXXFLAGS = /MD /GS /O2 /Zi /EHsc /utf-8 /I$(INC_DIR) /I$(VENDOR_SRC_INC_DIR) /I$(DEPS_INC_DIR) /I$(TKN20_INC_DIR) /I$(COMPAT_INC_DIR)
    DLL_FLAGS = /LD /DBUILD_DLL
    
    # MSVC object files
    OBJS = $(notdir $(SRCS:.cpp=.obj))
    MAIN_OBJ = main.obj

    # Targets
    STATIC_LIB = $(BUILD_DIR)/libhybrid-pq-cp-abe.lib
    SHARED_LIB = $(BUILD_DIR)/libhybrid-pq-cp-abe.dll
    EXEC = $(BUILD_DIR)/main.exe
    
    # Libraries
    STATIC_LIBS = $(LIB_STATIC_DIR)/libcryptopp.lib $(LIB_STATIC_DIR)/liboqs.lib $(LIB_STATIC_DIR)/librabe_ffi.lib
    SHARED_LIBS = liboqs.lib libcryptopp.lib librabe_ffi.lib libcpabe_tkn20.lib bcrypt.lib advapi32.lib ntdll.lib
    
    LDFLAGS = /link /ignore:4099 /LIBPATH:$(subst /,\,$(LIB_STATIC_DIR)) /MACHINE:X64
else
    CXX = g++
    CXXFLAGS = -O2 -g -Wall -I$(INC_DIR) -I$(VENDOR_SRC_INC_DIR) -I$(DEPS_INC_DIR) -I$(TKN20_INC_DIR) -I$(COMPAT_INC_DIR) -fPIC

    # No intermediate objects needed, we compile inline to keep output clean

    # Targets
    STATIC_LIB = $(BUILD_DIR)/libhybrid-pq-cp-abe.a
    EXEC = $(BUILD_DIR)/main

    ifeq ($(PLATFORM),macos)
        DLL_FLAGS = -DBUILD_DLL -dynamiclib
        SHARED_LIB = $(BUILD_DIR)/libhybrid-pq-cp-abe.dylib
        LDFLAGS = -lpthread -lm
    else
        DLL_FLAGS = -DBUILD_DLL -shared
        SHARED_LIB = $(BUILD_DIR)/libhybrid-pq-cp-abe.so
        LDFLAGS = -lpthread -ldl -lm
    endif

    # Libraries
    STATIC_LIBS_GCC = $(LIB_STATIC_DIR)/libcryptopp.a $(LIB_STATIC_DIR)/librabe_ffi.a $(LIB_STATIC_DIR)/libcpabe_tkn20.a $(LIB_STATIC_DIR)/liboqs.a
endif

.PHONY: all clean deps deps-clean executable shared static help test

all: static shared executable
	@echo "================================================================"
	@echo " All targets built successfully!"
	@echo " Output files are located in $(BUILD_DIR)/"
	@echo " Built libraries were also copied to $(LIB_STATIC_DIR)/ and $(LIB_DYNAMIC_DIR)/"
	@echo "================================================================"

help:
	@echo "================================================================"
	@echo "             Hybrid CP-ABE Library Makefile"
	@echo "================================================================"
	@echo "Usage:"
	@echo "  make                 Build everything (static, shared, executable)"
	@echo "  make all             Same as above"
	@echo "  make deps            Build vendored third-party dependencies"
	@echo "  make deps-clean      Remove dependency build cache for this platform"
	@echo "  make static          Build only the static library"
	@echo "  make shared          Build only the shared library"
	@echo "  make executable      Build only the main executable"
	@echo "  make test            Run an automated test using the executable"
	@echo "  make clean           Remove core build artifacts and temporary files"
	@echo "  make help            Show this help message"
	@echo ""
	@echo "Environment variables:"
	@echo "  COMPILER=msvc        Force use of MSVC (default on Windows)"
	@echo "  COMPILER=gcc         Force use of GCC/Clang-compatible build (default on Linux/macOS)"
	@echo "================================================================"

ifeq ($(COMPILER),msvc)

deps:
	@powershell -NoProfile -ExecutionPolicy Bypass -File scripts\\build-deps.ps1

deps-clean:
	@if exist build\\deps\\windows rmdir /S /Q build\\deps\\windows

static: $(STATIC_LIB)

$(STATIC_LIB): | deps
	@if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)
	@echo Generating TKN20 import lib...
	lib.exe /NOLOGO /DEF:$(subst /,\,$(LIB_STATIC_DIR))\libcpabe_tkn20.def /OUT:$(subst /,\,$(LIB_STATIC_DIR))\libcpabe_tkn20.lib /MACHINE:X64
	@echo Compiling...
	$(CXX) $(CXXFLAGS) /c $(SRCS)
	@echo Archiving...
	lib.exe /OUT:$(STATIC_LIB) $(OBJS) $(STATIC_LIBS)
	@echo Cleaning up object files...
	del /Q *.obj
	@if not exist $(subst /,\,$(LIB_STATIC_DIR)) mkdir $(subst /,\,$(LIB_STATIC_DIR))
	copy /Y $(subst /,\,$(STATIC_LIB)) $(subst /,\,$(LIB_STATIC_DIR))\
	@echo Done! Output at $(STATIC_LIB) and copied to $(LIB_STATIC_DIR)

shared: $(SHARED_LIB)

$(SHARED_LIB): static
	@if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)
	@echo Compiling Shared Library...
	$(CXX) $(CXXFLAGS) $(DLL_FLAGS) /Fe:$(SHARED_LIB) $(SRCS) $(LDFLAGS) $(SHARED_LIBS) /IMPLIB:$(BUILD_DIR)\libhybrid-pq-cp-abe_dll.lib
	copy /Y $(subst /,\,$(LIB_DYNAMIC_DIR))\libcpabe_tkn20.dll $(BUILD_DIR)
	@if not exist $(subst /,\,$(LIB_DYNAMIC_DIR)) mkdir $(subst /,\,$(LIB_DYNAMIC_DIR))
	copy /Y $(subst /,\,$(SHARED_LIB)) $(subst /,\,$(LIB_DYNAMIC_DIR))\
	@del /Q *.obj *.pdb >nul 2>&1
	@del /Q $(BUILD_DIR)\*.exp $(BUILD_DIR)\*.ilk $(BUILD_DIR)\*.pdb $(BUILD_DIR)\*_dll.lib >nul 2>&1
	@echo Done! Output at $(SHARED_LIB) and copied to $(LIB_DYNAMIC_DIR)

executable: $(EXEC)

$(EXEC): $(MAIN_SRC) $(STATIC_LIB)
	@if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)
	@echo Compiling Executable...
	$(CXX) $(CXXFLAGS) /Fe:$(EXEC) $(MAIN_SRC) $(LDFLAGS) $(STATIC_LIB) $(SHARED_LIBS)
	copy /Y $(subst /,\,$(LIB_DYNAMIC_DIR))\libcpabe_tkn20.dll $(BUILD_DIR)
	@del /Q *.obj *.pdb >nul 2>&1
	@del /Q $(BUILD_DIR)\*.exp $(BUILD_DIR)\*.ilk $(BUILD_DIR)\*.pdb $(BUILD_DIR)\*_dll.lib >nul 2>&1
	@echo Done! Output at $(EXEC)

clean:
	@if exist $(BUILD_DIR) rmdir /S /Q $(BUILD_DIR)
	@if exist $(subst /,\\,$(TEST_CASE_DIR)) rmdir /S /Q $(subst /,\\,$(TEST_CASE_DIR))
	@del /Q *.obj *.pdb >nul 2>&1

test: $(EXEC)
	@echo ================================================================
	@echo  Running Tests...
	@if not exist $(TEST_CASE_DIR) mkdir $(TEST_CASE_DIR)
	@echo This is a secret message for testing Hybrid CP-ABE!> $(TEST_CASE_DIR)\plaintext.txt
	@$(subst /,\,$(TEST_DIR))\run_test.bat
	@echo Test completed! Check $(TEST_CASE_DIR)\recovertext.txt
else

deps:
	@bash scripts/build-deps.sh $(PLATFORM)

deps-clean:
	@rm -rf build/deps/$(PLATFORM)

static: $(STATIC_LIB)

$(STATIC_LIB): $(SRCS) | deps
	@mkdir -p $(BUILD_DIR)
	@rm -f $(STATIC_LIB)
	@echo Compiling...
	$(CXX) $(CXXFLAGS) -c $(SRCS)
	@echo Archiving...
	ar rcs $(STATIC_LIB) ac17.o tkn20.o hybrid-cp-abe.o hybrid-oqs-abe.o ml-dsa.o aes-gcm.o
	@echo "create $(BUILD_DIR)/libhybrid-pq-cp-abe_fat.a" > mri.mac
	@echo "addlib $(STATIC_LIB)" >> mri.mac
	@echo "addlib $(LIB_STATIC_DIR)/libcpabe_tkn20.a" >> mri.mac
	@echo "addlib $(LIB_STATIC_DIR)/librabe_ffi.a" >> mri.mac
	@echo "addlib $(LIB_STATIC_DIR)/liboqs.a" >> mri.mac
	@echo "addlib $(LIB_STATIC_DIR)/libcryptopp.a" >> mri.mac
	@echo "save" >> mri.mac
	@echo "end" >> mri.mac
	ar -M < mri.mac
	@rm -f mri.mac
	@mv $(BUILD_DIR)/libhybrid-pq-cp-abe_fat.a $(STATIC_LIB)
	@echo Cleaning up object files...
	@rm -f ac17.o tkn20.o hybrid-cp-abe.o hybrid-oqs-abe.o ml-dsa.o aes-gcm.o
	@mkdir -p $(LIB_STATIC_DIR)
	cp $(STATIC_LIB) $(LIB_STATIC_DIR)/
	@echo Done! Output at $(STATIC_LIB) and copied to $(LIB_STATIC_DIR)

shared: $(SHARED_LIB)

$(SHARED_LIB): $(SRCS) $(STATIC_LIBS_GCC)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(DLL_FLAGS) $(SRCS) -o $(SHARED_LIB) $(STATIC_LIBS_GCC)
	@mkdir -p $(LIB_DYNAMIC_DIR)
	cp $(SHARED_LIB) $(LIB_DYNAMIC_DIR)/
	@echo Done! Output at $(SHARED_LIB) and copied to $(LIB_DYNAMIC_DIR)

executable: $(EXEC)

$(EXEC): $(MAIN_SRC) $(STATIC_LIB)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(MAIN_SRC) -o $(EXEC) $(STATIC_LIB) $(LDFLAGS)
	@echo Done! Output at $(EXEC)

clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(TEST_CASE_DIR)

test: $(EXEC)
	@echo "================================================================"
	@echo " Running Tests..."
	@mkdir -p $(TEST_CASE_DIR)
	@chmod +x ./$(TEST_DIR)/run_test.sh
	@HCPABE_EXEC="./$(EXEC)" ./$(TEST_DIR)/run_test.sh
	@echo "Test completed! Check $(TEST_CASE_DIR)/"

endif