# Hybrid-CP-ABE-Library build
# Windows ABI: MSVC. TKN20 is isolated behind a C ABI DLL built with Go/MinGW.
# Linux ABI: GNU. macOS ABI: Clang.
#
# Common usage:
#   make -j8
#   make deps -j8
#   make test -j8

BUILD_ROOT = build
VERSION_HEADER = include/hybrid_pq_cp_abe/version.h

ifeq ($(OS),Windows_NT)
    PLATFORM = windows
    COMPILER ?= msvc
else
    UNAME_S := $(shell uname -s)
    ifneq (,$(filter MINGW% MSYS% CYGWIN%,$(UNAME_S)))
        PLATFORM = windows
        COMPILER ?= msvc
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

ifeq ($(PLATFORM),windows)
    SHELL = cmd.exe
    # MSYS/Cygwin also escapes embedded quotes when invoking cmd.exe directly.
    # Pass recipes through a batch file to preserve native Windows syntax.
    ifneq (,$(filter %msys %cygwin,$(MAKE_HOST)))
        SHELL = sh.exe
        .SHELLFLAGS = scripts/windows-shell.sh
    else
        .SHELLFLAGS = /c
    endif
endif

ifeq ($(PLATFORM),windows)
    LIB_VERSION := $(strip $(shell cmd.exe /d /c type VERSION))
else
    LIB_VERSION := $(strip $(shell cat VERSION))
endif
ifeq ($(LIB_VERSION),)
    $(error VERSION must contain the library version)
endif

BUILD_DIR = $(BUILD_ROOT)/artifacts/$(PLATFORM)
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
       $(SCHEMES_DIR)/covercrypt.cpp \
       src/hybrid-pq-cp-abe.cpp \
       $(CORE_DIR)/abe-setup.cpp \
       $(CORE_DIR)/abe-genkey.cpp \
       $(CORE_DIR)/abe-encrypt.cpp \
       $(CORE_DIR)/abe-decrypt.cpp \
       $(CRYPTO_DIR)/ml-dsa.cpp \
       $(CRYPTO_DIR)/aes-gcm.cpp

MAIN_SRC = src/main.cpp
SOURCE_NAMES = $(notdir $(SRCS:.cpp=))

PROJECT_HEADERS = $(wildcard $(INC_DIR)/hybrid_pq_cp_abe/*.h) $(VERSION_HEADER) $(CORE_DIR)/abe-internal.h
RABE_HEADER = $(DEPS_INC_DIR)/rabe/rabe.h
OQS_HEADER = $(OQS_INC_DIR)/oqs/oqs.h
TKN20_HEADER = $(TKN20_INC_DIR)/cpabe_tkn20.h
COVERCRYPT_HEADER = $(DEPS_INC_DIR)/covercrypt/covercrypt_ffi.h
COVERCRYPT_TEST_SRC = tests/cpp/covercrypt_test.cpp
# Core builds reuse staged dependencies. Only a missing ready marker triggers
# automatic dependency setup; changed dependency sources require make deps.
CRYPTOPP_HEADERS = $(DEPS_INC_DIR)/cryptopp/aes.h $(DEPS_INC_DIR)/cryptopp/gcm.h $(DEPS_INC_DIR)/cryptopp/filters.h \
                   $(DEPS_INC_DIR)/cryptopp/osrng.h $(DEPS_INC_DIR)/cryptopp/sha.h $(DEPS_INC_DIR)/cryptopp/sha3.h \
                   $(DEPS_INC_DIR)/cryptopp/base64.h
GENERATED_HEADERS = $(RABE_HEADER) $(OQS_HEADER) $(TKN20_HEADER) $(CRYPTOPP_HEADERS) $(COVERCRYPT_HEADER)
COMMON_HEADERS = $(PROJECT_HEADERS) $(GENERATED_HEADERS)

vpath %.cpp src $(SCHEMES_DIR) $(CORE_DIR) $(CRYPTO_DIR)

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
    SHARED_IMPORT_LIB = $(BUILD_DIR)/libhybrid-pq-cp-abe_dll.lib
    EXEC = $(BUILD_DIR)/main.exe
    COVERCRYPT_LIB = $(DEPS_LIB_DIR)/covercrypt/libcovercrypt_ffi.lib
    COVERCRYPT_TEST = $(BUILD_DIR)/covercrypt-test.exe

    WIN_STATIC_DEPS = $(DEPS_LIB_DIR)/cryptopp/libcryptopp.lib $(DEPS_LIB_DIR)/liboqs/liboqs.lib $(DEPS_LIB_DIR)/rabe/librabe_ffi.lib $(COVERCRYPT_LIB)
    TKN20_IMPORT_LIB = $(DEPS_LIB_DIR)/tkn20/libcpabe_tkn20.lib
    TKN20_DLL = $(DEPS_LIB_DIR)/tkn20/libcpabe_tkn20.dll
    PUBLISHED_TKN20_DLL = $(LIB_DIR)/libcpabe_tkn20.dll
    WIN_LINK_DEPS = $(WIN_STATIC_DEPS) $(TKN20_IMPORT_LIB)
    WIN_SYSTEM_LIBS = bcrypt.lib advapi32.lib ntdll.lib userenv.lib ws2_32.lib
    LDFLAGS = /link /ignore:4099 /MACHINE:X64
else
    ifeq ($(PLATFORM),macos)
        CXX_BASE = clang++
        SHARED_FLAG = -DBUILD_DLL -dynamiclib -Wl,-install_name,@rpath/libhybrid-pq-cp-abe.dylib
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
    COVERCRYPT_LIB = $(DEPS_LIB_DIR)/covercrypt/libcovercrypt_ffi.a
    COVERCRYPT_TEST = $(BUILD_DIR)/covercrypt-test

    CRYPTOPP_LIB = $(DEPS_LIB_DIR)/cryptopp/libcryptopp.a
    RABE_LIB = $(DEPS_LIB_DIR)/rabe/librabe_ffi.a
    TKN20_LIB = $(DEPS_LIB_DIR)/tkn20/libcpabe_tkn20.a
    OQS_LIB = $(DEPS_LIB_DIR)/liboqs/liboqs.a
    STATIC_LIBS_GCC = $(CRYPTOPP_LIB) $(RABE_LIB) $(TKN20_LIB) $(OQS_LIB) $(COVERCRYPT_LIB)
endif

.DEFAULT_GOAL := all

# Generated SDK header: bake VERSION into binaries without a runtime file lookup.
$(VERSION_HEADER): VERSION Makefile
ifeq ($(PLATFORM),windows)
	@> "$(subst /,\,$@)" echo // Generated from VERSION; do not edit.
	@>> "$(subst /,\,$@)" echo #ifndef HYBRID_CP_ABE_VERSION_H
	@>> "$(subst /,\,$@)" echo #define HYBRID_CP_ABE_VERSION_H
	@>> "$(subst /,\,$@)" echo #define HCPABE_LIB_VERSION "$(LIB_VERSION)"
	@>> "$(subst /,\,$@)" echo #endif
else
	@printf '%s\n' '// Generated from VERSION; do not edit.' '#ifndef HYBRID_CP_ABE_VERSION_H' '#define HYBRID_CP_ABE_VERSION_H' '#define HCPABE_LIB_VERSION "$(LIB_VERSION)"' '#endif' > "$@"
endif

.PHONY: all clean deps deps-clean executable shared static help test tests abi-info

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

tests: test

help:
	@echo "================================================================"
	@echo "             Hybrid CP-ABE Library Makefile"
	@echo "================================================================"
	@echo "  make -j8             Incremental parallel build"
	@echo "  make deps -j8        Build/check 5 native dependencies in parallel"
	@echo "  make deps-clean      Remove dependency build cache"
	@echo "  make static          Build only the static library"
	@echo "  make shared          Build only the shared library"
	@echo "  make executable      Build only the CLI"
	@echo "  make test -j8        Build incrementally and run tests"
	@echo "  make tests -j8       Alias for make test -j8"
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
deps: SHELL = sh.exe
deps: .SHELLFLAGS = -c
deps:
	@powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/build-deps.ps1 -Dependency all

$(DEPS_READY): SHELL = sh.exe
$(DEPS_READY): .SHELLFLAGS = -c
$(DEPS_READY):
	@powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/build-deps.ps1 -Dependency all

deps-clean: SHELL = sh.exe
deps-clean: .SHELLFLAGS = -c
deps-clean:
	@echo Cleaning dependency cache: $(DEPS_DIR)
	@rm -rf build/deps/windows
	@echo Done! Dependency cache cleared.
else
deps:
	@bash scripts/build-deps.sh $(PLATFORM) all

$(DEPS_READY):
	@bash scripts/build-deps.sh $(PLATFORM) all

deps-clean:
	@echo "Cleaning dependency cache: $(DEPS_DIR)"
	@rm -rf $(DEPS_DIR)
	@echo "Done! Dependency cache cleared."
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

$(COVERCRYPT_TEST): $(COVERCRYPT_TEST_SRC) $(PROJECT_HEADERS) $(STATIC_LIB) $(COVERCRYPT_HEADER) $(TKN20_IMPORT_LIB) $(TKN20_DLL) | $(BUILD_DIR) $(MAIN_OBJ_DIR)
	$(CXX) $(CXXFLAGS) /Fo"$(subst /,\,$(MAIN_OBJ_DIR))\\" /Fe:"$(subst /,\,$@)" $(COVERCRYPT_TEST_SRC) $(LDFLAGS) "$(subst /,\,$(STATIC_LIB))" "$(subst /,\,$(TKN20_IMPORT_LIB))" $(WIN_SYSTEM_LIBS)
	@copy /Y "$(subst /,\,$(TKN20_DLL))" "$(subst /,\,$(BUILD_DIR))\" >nul

# Dependency artifacts are produced by the order-only deps phase.
$(WIN_STATIC_DEPS) $(TKN20_IMPORT_LIB) $(TKN20_DLL): | $(DEPS_READY)

$(BUILD_DIR) $(LIB_DIR):
	@if not exist "$(subst /,\,$@)" mkdir "$(subst /,\,$@)"

# Keep the runtime beside the public DLL even on an otherwise up-to-date build.
$(PUBLISHED_TKN20_DLL): $(TKN20_DLL) | $(LIB_DIR)
	@copy /Y "$(subst /,\,$<)" "$(subst /,\,$@)" >nul

$(OBJ_DIR): | $(BUILD_DIR)
	@if not exist "$(subst /,\,$@)" mkdir "$(subst /,\,$@)"

$(STATIC_OBJ_DIR) $(SHARED_OBJ_DIR) $(MAIN_OBJ_DIR): | $(OBJ_DIR)
	@if not exist "$(subst /,\,$@)" mkdir "$(subst /,\,$@)"

$(STATIC_OBJ_DIR)/%.obj: %.cpp $(COMMON_HEADERS) | $(DEPS_READY) $(STATIC_OBJ_DIR)
	$(CXX) $(CXXFLAGS) /Fo"$(subst /,\,$@)" /c "$<"

$(SHARED_OBJ_DIR)/%.obj: %.cpp $(COMMON_HEADERS) | $(DEPS_READY) $(SHARED_OBJ_DIR)
	$(CXX) $(CXXFLAGS) $(DLL_DEFINE) /Fo"$(subst /,\,$@)" /c "$<"

$(MAIN_OBJ): $(MAIN_SRC) $(COMMON_HEADERS) | $(DEPS_READY) $(MAIN_OBJ_DIR)
	$(CXX) $(CXXFLAGS) /Fo"$(subst /,\,$@)" /c "$(MAIN_SRC)"

static: $(STATIC_LIB) $(PUBLISHED_TKN20_DLL)

$(STATIC_LIB): $(STATIC_OBJS) $(WIN_STATIC_DEPS) Makefile scripts/normalize-msvc-library.ps1 | $(BUILD_DIR) $(LIB_DIR)
	@if exist "$(subst /,\,$@)" del /Q "$(subst /,\,$@)"
	@rem Rust static libraries share runtime objects. Deduplicate identical members after merging.
	lib.exe /NOLOGO /IGNORE:4006 /OUT:"$(subst /,\,$@).merged" $(foreach o,$(STATIC_OBJS),"$(subst /,\,$(o))") $(foreach l,$(WIN_STATIC_DEPS),"$(subst /,\,$(l))")
	powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/normalize-msvc-library.ps1 -InputLib "$(subst /,\,$@).merged" -OutputLib "$(subst /,\,$@)"
	@del /Q "$(subst /,\,$@).merged"
	@copy /Y "$(subst /,\,$@)" "$(subst /,\,$(LIB_DIR))\" >nul
	@echo Done! Static library: $@

shared: $(SHARED_LIB) $(PUBLISHED_TKN20_DLL)

$(SHARED_LIB): $(SHARED_OBJS) $(WIN_STATIC_DEPS) $(TKN20_IMPORT_LIB) $(TKN20_DLL) Makefile | $(BUILD_DIR) $(LIB_DIR)
	$(CXX) /nologo /LD /Fe:"$(subst /,\,$@)" $(foreach o,$(SHARED_OBJS),"$(subst /,\,$(o))") $(LDFLAGS) $(foreach l,$(WIN_LINK_DEPS),"$(subst /,\,$(l))") $(WIN_SYSTEM_LIBS) /IMPLIB:"$(subst /,\,$(BUILD_DIR))\libhybrid-pq-cp-abe_dll.lib"
	@copy /Y "$(subst /,\,$(TKN20_DLL))" "$(subst /,\,$(BUILD_DIR))\" >nul
	@copy /Y "$(subst /,\,$@)" "$(subst /,\,$(LIB_DIR))\" >nul
	@copy /Y "$(subst /,\,$(SHARED_IMPORT_LIB))" "$(subst /,\,$(LIB_DIR))\" >nul
	@del /Q "$(subst /,\,$(BUILD_DIR))\*.exp" >nul 2>&1
	@echo Done! Shared library: $@

executable: $(EXEC) $(PUBLISHED_TKN20_DLL)

$(EXEC): $(MAIN_OBJ) $(STATIC_LIB) $(TKN20_IMPORT_LIB) $(TKN20_DLL) | $(BUILD_DIR)
	$(CXX) /nologo /Fe:"$(subst /,\,$@)" "$(subst /,\,$(MAIN_OBJ))" $(LDFLAGS) "$(subst /,\,$(STATIC_LIB))" $(foreach l,$(WIN_LINK_DEPS),"$(subst /,\,$(l))") $(WIN_SYSTEM_LIBS)
	@copy /Y "$(subst /,\,$(TKN20_DLL))" "$(subst /,\,$(BUILD_DIR))\" >nul
	@echo Done! Executable: $@

clean:
	@echo Cleaning core build outputs: $(BUILD_DIR)
	@if exist "$(subst /,\,$(BUILD_DIR))" rmdir /S /Q "$(subst /,\,$(BUILD_DIR))"
	@echo Cleaning test cases: $(TEST_CASE_DIR)
	@if exist "$(subst /,\,$(TEST_CASE_DIR))" rmdir /S /Q "$(subst /,\,$(TEST_CASE_DIR))"
	@echo Done! Core build outputs cleared.

test: $(EXEC) $(COVERCRYPT_TEST) $(PUBLISHED_TKN20_DLL)
	@"$(COVERCRYPT_TEST)"
	@echo ================================================================
	@echo  Running Tests...
	@if not exist "$(subst /,\,$(TEST_CASE_DIR))" mkdir "$(subst /,\,$(TEST_CASE_DIR))"
	@echo This is a secret message for testing Hybrid CP-ABE!> "$(subst /,\,$(TEST_CASE_DIR))\plaintext.txt"
	@"$(subst /,\,$(TEST_DIR))\run_test.bat"
	@echo Test completed!

else

$(COVERCRYPT_TEST): $(COVERCRYPT_TEST_SRC) $(PROJECT_HEADERS) $(STATIC_LIB) $(COVERCRYPT_HEADER)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(COVERCRYPT_TEST_SRC) $(STATIC_LIB) -o "$@" $(LDFLAGS)

$(STATIC_LIBS_GCC): | $(DEPS_READY)

$(CORE_OBJ_DIR)/%.o: %.cpp $(COMMON_HEADERS) | $(DEPS_READY)
	@mkdir -p $(CORE_OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c "$<" -o "$@"

$(MAIN_OBJ): $(MAIN_SRC) $(COMMON_HEADERS) | $(DEPS_READY)
	@mkdir -p $(MAIN_OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c "$(MAIN_SRC)" -o "$@"

static: $(STATIC_LIB)

$(STATIC_LIB): $(OBJS) $(STATIC_LIBS_GCC) Makefile
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
	  "addlib $(COVERCRYPT_LIB)" \
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
	@echo "Cleaning core build outputs: $(BUILD_DIR)"
	@rm -rf $(BUILD_DIR)
	@echo "Cleaning test cases: $(TEST_CASE_DIR)"
	@rm -rf $(TEST_CASE_DIR)
	@echo "Done! Core build outputs cleared."

test: $(EXEC) $(COVERCRYPT_TEST)
	@"$(COVERCRYPT_TEST)"
	@echo "================================================================"
	@echo " Running Tests..."
	@mkdir -p $(TEST_CASE_DIR)
	@chmod +x ./$(TEST_DIR)/run_test.sh
	@HCPABE_EXEC="./$(EXEC)" ./$(TEST_DIR)/run_test.sh
	@echo "Test completed!"

-include $(DEPFILES)

endif
