# Hybrid-CP-ABE-Library build
# Windows ABI: MSVC. TKN20 is isolated behind a C ABI DLL built with Go/MinGW.
# Linux ABI: GNU. macOS ABI: Clang.
#
# Common usage:
#   make -j8
#   make deps -j8
#   make test -j8

BUILD_ROOT = build

ifeq ($(OS),Windows_NT)
    PLATFORM = windows
    COMPILER ?= msvc
    SHELL = cmd.exe
    .SHELLFLAGS = /c
else
    UNAME_S := $(shell uname -s)
    ifneq (,$(filter MINGW% MSYS% CYGWIN%,$(UNAME_S)))
        PLATFORM = windows
        COMPILER ?= msvc
        SHELL = cmd.exe
        .SHELLFLAGS = //c
    else ifeq ($(UNAME_S),Darwin)
        PLATFORM = macos
        COMPILER ?= clang
    else
        PLATFORM = linux
        COMPILER ?= gcc
    endif
endif

ifeq ($(COMPILER),msvc)
    PLATFORM = windows
endif

BUILD_DIR = $(BUILD_ROOT)/$(PLATFORM)
DEPS_DIR = $(BUILD_ROOT)/deps/$(PLATFORM)
DEPS_LIB_DIR = $(DEPS_DIR)/lib
DEPS_READY = $(DEPS_LIB_DIR)/.ready
OBJ_DIR = $(BUILD_DIR)/obj

INC_DIR = include
DEPS_INC_DIR = $(DEPS_DIR)/include
OQS_INC_DIR = $(DEPS_INC_DIR)/liboqs
TKN20_INC_DIR = $(DEPS_INC_DIR)/tkn20
SCHEMES_DIR = src/schemes
CORE_DIR = src/core
CRYPTO_DIR = src/crypto
LIB_DIR = lib
TEST_DIR = tests/cpp
TEST_CASE_DIR = $(TEST_DIR)/cases

SRCS = $(SCHEMES_DIR)/ac17.cpp \
       $(SCHEMES_DIR)/tkn20.cpp \
       $(CORE_DIR)/hybrid-cp-abe.cpp \
       $(CORE_DIR)/hybrid-oqs-abe.cpp \
       $(CRYPTO_DIR)/ml-dsa.cpp \
       $(CRYPTO_DIR)/aes-gcm.cpp

MAIN_SRC = src/main.cpp
SOURCE_NAMES = $(notdir $(SRCS:.cpp=))

PROJECT_HEADERS = $(wildcard $(INC_DIR)/hybrid_pq_cp_abe/*.h)
RABE_HEADER = $(DEPS_INC_DIR)/rabe/rabe.h
OQS_HEADER = $(OQS_INC_DIR)/oqs/oqs.h
TKN20_HEADER = $(TKN20_INC_DIR)/cpabe_tkn20.h
CRYPTOPP_HEADERS = $(DEPS_INC_DIR)/cryptopp/aes.h $(DEPS_INC_DIR)/cryptopp/gcm.h $(DEPS_INC_DIR)/cryptopp/filters.h \
                   $(DEPS_INC_DIR)/cryptopp/osrng.h $(DEPS_INC_DIR)/cryptopp/sha.h $(DEPS_INC_DIR)/cryptopp/sha3.h \
                   $(DEPS_INC_DIR)/cryptopp/base64.h
GENERATED_HEADERS = $(RABE_HEADER) $(OQS_HEADER) $(TKN20_HEADER) $(CRYPTOPP_HEADERS)
COMMON_HEADERS = $(PROJECT_HEADERS) $(GENERATED_HEADERS)

vpath %.cpp $(SCHEMES_DIR) $(CORE_DIR) $(CRYPTO_DIR)

# Optional compiler cache.
# Avoid $(shell ...) discovery on Windows: GNU Make for Windows captures shell
# output through an internal pipe and can emit "nonexistent pipe" even for
# non-build targets such as clean. Set CXX_WRAPPER=sccache explicitly if wanted.
ifeq ($(PLATFORM),windows)
    CXX_WRAPPER ?=
else
    SCCACHE_FOUND := $(shell command -v sccache 2>/dev/null)
    ifneq ($(strip $(SCCACHE_FOUND)),)
        CXX_WRAPPER ?= sccache
    else
        CXX_WRAPPER ?=
    endif
endif

ifeq ($(COMPILER),msvc)
    CXX_BASE = cl.exe
    CXX = $(CXX_WRAPPER) $(CXX_BASE)
    CXXFLAGS = /nologo /MD /GS /O2 /Z7 /EHsc /utf-8 /I$(INC_DIR) /I$(DEPS_INC_DIR) /I$(OQS_INC_DIR) /I$(TKN20_INC_DIR)
    DLL_DEFINE = /DBUILD_DLL

    STATIC_OBJ_DIR = $(OBJ_DIR)/static
    SHARED_OBJ_DIR = $(OBJ_DIR)/shared
    MAIN_OBJ_DIR = $(OBJ_DIR)/main

    STATIC_OBJS = $(addprefix $(STATIC_OBJ_DIR)/,$(addsuffix .obj,$(SOURCE_NAMES)))
    SHARED_OBJS = $(addprefix $(SHARED_OBJ_DIR)/,$(addsuffix .obj,$(SOURCE_NAMES)))
    MAIN_OBJ = $(MAIN_OBJ_DIR)/main.obj

    STATIC_LIB = $(BUILD_DIR)/libhybrid-pq-cp-abe.lib
    SHARED_LIB = $(BUILD_DIR)/libhybrid-pq-cp-abe.dll
    EXEC = $(BUILD_DIR)/main.exe

    WIN_STATIC_DEPS = $(DEPS_LIB_DIR)/cryptopp/libcryptopp.lib $(DEPS_LIB_DIR)/liboqs/liboqs.lib $(DEPS_LIB_DIR)/rabe/librabe_ffi.lib
    TKN20_IMPORT_LIB = $(DEPS_LIB_DIR)/tkn20/libcpabe_tkn20.lib
    TKN20_DLL = $(DEPS_LIB_DIR)/tkn20/libcpabe_tkn20.dll
    WIN_LINK_DEPS = $(WIN_STATIC_DEPS) $(TKN20_IMPORT_LIB)
    WIN_SYSTEM_LIBS = bcrypt.lib advapi32.lib ntdll.lib
    LDFLAGS = /link /ignore:4099 /MACHINE:X64
else
    ifeq ($(PLATFORM),macos)
        CXX_BASE = clang++
        SHARED_FLAG = -DBUILD_DLL -dynamiclib
        SHARED_LIB = $(BUILD_DIR)/libhybrid-pq-cp-abe.dylib
        LDFLAGS = -lpthread -lm
    else
        CXX_BASE = g++
        SHARED_FLAG = -DBUILD_DLL -shared
        SHARED_LIB = $(BUILD_DIR)/libhybrid-pq-cp-abe.so
        LDFLAGS = -lpthread -ldl -lm
    endif

    CXX = $(CXX_WRAPPER) $(CXX_BASE)
    CXXFLAGS = -O2 -g -Wall -I$(INC_DIR) -I$(DEPS_INC_DIR) -I$(OQS_INC_DIR) -I$(TKN20_INC_DIR) -fPIC -MMD -MP

    CORE_OBJ_DIR = $(OBJ_DIR)/core
    MAIN_OBJ_DIR = $(OBJ_DIR)/main
    OBJS = $(addprefix $(CORE_OBJ_DIR)/,$(addsuffix .o,$(SOURCE_NAMES)))
    MAIN_OBJ = $(MAIN_OBJ_DIR)/main.o
    DEPFILES = $(OBJS:.o=.d) $(MAIN_OBJ:.o=.d)

    STATIC_LIB = $(BUILD_DIR)/libhybrid-pq-cp-abe.a
    CORE_ARCHIVE = $(BUILD_DIR)/libhybrid-pq-cp-abe_core.a
    EXEC = $(BUILD_DIR)/main

    CRYPTOPP_LIB = $(DEPS_LIB_DIR)/cryptopp/libcryptopp.a
    RABE_LIB = $(DEPS_LIB_DIR)/rabe/librabe_ffi.a
    TKN20_LIB = $(DEPS_LIB_DIR)/tkn20/libcpabe_tkn20.a
    OQS_LIB = $(DEPS_LIB_DIR)/liboqs/liboqs.a
    STATIC_LIBS_GCC = $(CRYPTOPP_LIB) $(RABE_LIB) $(TKN20_LIB) $(OQS_LIB)
endif

.PHONY: all clean deps deps-clean executable shared static help test abi-info

all: static shared executable
	@echo "================================================================"
	@echo " Native build complete"
	@echo " Platform : $(PLATFORM)"
	@echo " Compiler : $(COMPILER)"
	@echo "----------------------------------------------------------------"
	@echo " Project headers : include/hybrid_pq_cp_abe/"
	@echo " Dependency includes: build/deps/$(PLATFORM)/include/"
	@echo " Dependency libs    : build/deps/$(PLATFORM)/lib/"
	@echo "----------------------------------------------------------------"
ifeq ($(PLATFORM),windows)
	@echo " Native static : $(STATIC_LIB)"
	@echo " Native shared : $(SHARED_LIB)"
	@echo " CLI           : $(EXEC)"
	@echo " Runtime DLL   : $(BUILD_DIR)/libcpabe_tkn20.dll"
else
	@echo " Native static : $(STATIC_LIB)"
	@echo " Native shared : $(SHARED_LIB)"
	@echo " CLI           : $(EXEC)"
endif
	@echo " Published libraries: $(LIB_DIR)/"
	@echo "================================================================"

help:
	@echo "================================================================"
	@echo "             Hybrid CP-ABE Library Makefile"
	@echo "================================================================"
	@echo "  make -j8             Incremental parallel build"
	@echo "  make deps -j8        Build/check 4 vendored dependencies in parallel"
	@echo "  make deps-clean      Remove dependency build cache"
	@echo "  make static          Build only the static library"
	@echo "  make shared          Build only the shared library"
	@echo "  make executable      Build only the CLI"
	@echo "  make test -j8        Build incrementally and run tests"
	@echo "  make abi-info        Show platform ABI policy"
	@echo "  make clean           Remove core build outputs only"
	@echo ""
	@echo "sccache is used automatically when installed."
	@echo "================================================================"

abi-info:
ifeq ($(PLATFORM),windows)
	@echo Windows native ABI: MSVC x64
	@echo Rust target: x86_64-pc-windows-msvc
	@echo TKN20: Go/MinGW CGO DLL exposed through C ABI + MSVC import library
else ifeq ($(PLATFORM),macos)
	@echo macOS native ABI: Apple Clang
else
	@echo Linux native ABI: GNU
endif

# Dependency parallelism is orchestrated inside the platform script rather than
# by GNU Make's jobserver. This avoids stale jobserver pipe/file descriptors
# leaking into Cargo/sub-make/CMake/Go while still honoring make -jN.
ifeq ($(PLATFORM),windows)
deps:
	@powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build-deps.ps1 -Dependency all

$(DEPS_READY):
	@powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build-deps.ps1 -Dependency all

deps-clean:
	@if exist build\deps\windows rmdir /S /Q build\deps\windows
else
deps:
	@bash scripts/build-deps.sh $(PLATFORM) all

$(DEPS_READY):
	@bash scripts/build-deps.sh $(PLATFORM) all

deps-clean:
	@rm -rf $(DEPS_DIR)
endif

# These files are generated by dependency builds. The rule makes fresh clones
# valid Make graphs; the compiler itself will fail clearly if a build did not
# produce a required header.
ifeq ($(PLATFORM),windows)
$(GENERATED_HEADERS): | $(DEPS_READY)
	@if not exist "$(subst /,\,$@)" (echo Missing generated header: $@ & exit /b 1)
else
$(GENERATED_HEADERS): | $(DEPS_READY)
	@test -f "$@" || (echo "Missing generated header: $@" >&2; exit 1)
endif

ifeq ($(COMPILER),msvc)

# Dependency artifacts are produced by the order-only deps phase.
$(WIN_STATIC_DEPS) $(TKN20_IMPORT_LIB) $(TKN20_DLL): | $(DEPS_READY)

$(STATIC_OBJ_DIR)/%.obj: %.cpp $(COMMON_HEADERS) | $(DEPS_READY)
	@if not exist "$(subst /,\,$(STATIC_OBJ_DIR))" mkdir "$(subst /,\,$(STATIC_OBJ_DIR))"
	$(CXX) $(CXXFLAGS) /Fo"$(subst /,\,$@)" /c "$<"

$(SHARED_OBJ_DIR)/%.obj: %.cpp $(COMMON_HEADERS) | $(DEPS_READY)
	@if not exist "$(subst /,\,$(SHARED_OBJ_DIR))" mkdir "$(subst /,\,$(SHARED_OBJ_DIR))"
	$(CXX) $(CXXFLAGS) $(DLL_DEFINE) /Fo"$(subst /,\,$@)" /c "$<"

$(MAIN_OBJ): $(MAIN_SRC) $(COMMON_HEADERS) | $(DEPS_READY)
	@if not exist "$(subst /,\,$(MAIN_OBJ_DIR))" mkdir "$(subst /,\,$(MAIN_OBJ_DIR))"
	$(CXX) $(CXXFLAGS) /Fo"$(subst /,\,$@)" /c "$(MAIN_SRC)"

static: $(STATIC_LIB)

$(STATIC_LIB): $(STATIC_OBJS) $(WIN_STATIC_DEPS)
	@if not exist "$(subst /,\,$(BUILD_DIR))" mkdir "$(subst /,\,$(BUILD_DIR))"
	@if exist "$(subst /,\,$@)" del /Q "$(subst /,\,$@)"
	lib.exe /NOLOGO /OUT:"$(subst /,\,$@)" $(foreach o,$(STATIC_OBJS),"$(subst /,\,$(o))") $(foreach l,$(WIN_STATIC_DEPS),"$(subst /,\,$(l))")
	@if not exist "$(subst /,\,$(LIB_DIR))" mkdir "$(subst /,\,$(LIB_DIR))"
	@copy /Y "$(subst /,\,$@)" "$(subst /,\,$(LIB_DIR))\" >nul
	@echo Done! Static library: $@

shared: $(SHARED_LIB)

$(SHARED_LIB): $(SHARED_OBJS) $(WIN_STATIC_DEPS) $(TKN20_IMPORT_LIB) $(TKN20_DLL)
	@if not exist "$(subst /,\,$(BUILD_DIR))" mkdir "$(subst /,\,$(BUILD_DIR))"
	$(CXX) /nologo /LD /Fe:"$(subst /,\,$@)" $(foreach o,$(SHARED_OBJS),"$(subst /,\,$(o))") $(LDFLAGS) $(foreach l,$(WIN_LINK_DEPS),"$(subst /,\,$(l))") $(WIN_SYSTEM_LIBS) /IMPLIB:"$(subst /,\,$(BUILD_DIR))\libhybrid-pq-cp-abe_dll.lib"
	@copy /Y "$(subst /,\,$(TKN20_DLL))" "$(subst /,\,$(BUILD_DIR))\" >nul
	@if not exist "$(subst /,\,$(LIB_DIR))" mkdir "$(subst /,\,$(LIB_DIR))"
	@copy /Y "$(subst /,\,$@)" "$(subst /,\,$(LIB_DIR))\" >nul
	@del /Q "$(subst /,\,$(BUILD_DIR))\*.exp" "$(subst /,\,$(BUILD_DIR))\*_dll.lib" >nul 2>&1
	@echo Done! Shared library: $@

executable: $(EXEC)

$(EXEC): $(MAIN_OBJ) $(STATIC_LIB) $(TKN20_IMPORT_LIB) $(TKN20_DLL)
	@if not exist "$(subst /,\,$(BUILD_DIR))" mkdir "$(subst /,\,$(BUILD_DIR))"
	$(CXX) /nologo /Fe:"$(subst /,\,$@)" "$(subst /,\,$(MAIN_OBJ))" $(LDFLAGS) "$(subst /,\,$(STATIC_LIB))" $(foreach l,$(WIN_LINK_DEPS),"$(subst /,\,$(l))") $(WIN_SYSTEM_LIBS)
	@copy /Y "$(subst /,\,$(TKN20_DLL))" "$(subst /,\,$(BUILD_DIR))\" >nul
	@echo Done! Executable: $@

clean:
	@if exist "$(subst /,\,$(BUILD_DIR))" rmdir /S /Q "$(subst /,\,$(BUILD_DIR))"
	@if exist "$(subst /,\,$(TEST_CASE_DIR))" rmdir /S /Q "$(subst /,\,$(TEST_CASE_DIR))"

test: $(EXEC)
	@echo ================================================================
	@echo  Running Tests...
	@if not exist "$(subst /,\,$(TEST_CASE_DIR))" mkdir "$(subst /,\,$(TEST_CASE_DIR))"
	@echo This is a secret message for testing Hybrid CP-ABE!> "$(subst /,\,$(TEST_CASE_DIR))\plaintext.txt"
	@"$(subst /,\,$(TEST_DIR))\run_test.bat"
	@echo Test completed!

else

$(STATIC_LIBS_GCC): | $(DEPS_READY)

$(CORE_OBJ_DIR)/%.o: %.cpp $(COMMON_HEADERS) | $(DEPS_READY)
	@mkdir -p $(CORE_OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c "$<" -o "$@"

$(MAIN_OBJ): $(MAIN_SRC) $(COMMON_HEADERS) | $(DEPS_READY)
	@mkdir -p $(MAIN_OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c "$(MAIN_SRC)" -o "$@"

static: $(STATIC_LIB)

$(STATIC_LIB): $(OBJS) $(STATIC_LIBS_GCC)
	@mkdir -p $(BUILD_DIR)
	@rm -f $(CORE_ARCHIVE) $(STATIC_LIB)
	ar rcs $(CORE_ARCHIVE) $(OBJS)
ifeq ($(PLATFORM),macos)
	libtool -static -o $(STATIC_LIB) $(CORE_ARCHIVE) $(STATIC_LIBS_GCC)
else
	@printf '%s\n' \
	  "create $(STATIC_LIB)" \
	  "addlib $(CORE_ARCHIVE)" \
	  "addlib $(TKN20_LIB)" \
	  "addlib $(RABE_LIB)" \
	  "addlib $(OQS_LIB)" \
	  "addlib $(CRYPTOPP_LIB)" \
	  "save" "end" > $(BUILD_DIR)/merge.mri
	ar -M < $(BUILD_DIR)/merge.mri
	@rm -f $(BUILD_DIR)/merge.mri
endif
	@rm -f $(CORE_ARCHIVE)
	@mkdir -p $(LIB_DIR)
	@cp $(STATIC_LIB) $(LIB_DIR)/
	@echo Done! Static library: $(STATIC_LIB)

shared: $(SHARED_LIB)

$(SHARED_LIB): $(OBJS) $(STATIC_LIBS_GCC)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(SHARED_FLAG) $(OBJS) -o $(SHARED_LIB) $(STATIC_LIBS_GCC) $(LDFLAGS)
	@mkdir -p $(LIB_DIR)
	@cp $(SHARED_LIB) $(LIB_DIR)/
	@echo Done! Shared library: $(SHARED_LIB)

executable: $(EXEC)

$(EXEC): $(MAIN_OBJ) $(STATIC_LIB) $(STATIC_LIBS_GCC)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(MAIN_OBJ) -o $(EXEC) $(STATIC_LIB) $(STATIC_LIBS_GCC) $(LDFLAGS)
	@echo Done! Executable: $(EXEC)

clean:
	@rm -rf $(BUILD_DIR)
	@rm -rf $(TEST_CASE_DIR)

test: $(EXEC)
	@echo "================================================================"
	@echo " Running Tests..."
	@mkdir -p $(TEST_CASE_DIR)
	@chmod +x ./$(TEST_DIR)/run_test.sh
	@HCPABE_EXEC="./$(EXEC)" ./$(TEST_DIR)/run_test.sh
	@echo "Test completed!"

-include $(DEPFILES)

endif
