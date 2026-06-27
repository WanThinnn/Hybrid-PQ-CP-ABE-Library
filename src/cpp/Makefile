# Usage: 
# make COMPILER=gcc (default on Linux)
# make COMPILER=msvc (default on Windows)

ifeq ($(OS),Windows_NT)
    COMPILER ?= msvc
    SHELL = cmd.exe
    ifneq (,$(findstring msys,$(MAKE_HOST)))
        .SHELLFLAGS = //c
    endif
    ifneq (,$(findstring cygwin,$(MAKE_HOST)))
        .SHELLFLAGS = //c
    endif
else
    COMPILER ?= gcc
endif

# Directories
INC_DIR = include
SCHEMES_DIR = schemes
CORE_DIR = core
CRYPTO_DIR = crypto
LIB_STATIC_DIR = lib/static

# Source files
SRCS = $(SCHEMES_DIR)/ac17.cpp \
       $(SCHEMES_DIR)/tkn20.cpp \
       $(CORE_DIR)/hybrid-cp-abe.cpp \
       $(CORE_DIR)/hybrid-oqs-abe.cpp \
       $(CRYPTO_DIR)/ml-dsa.cpp \
       $(CRYPTO_DIR)/aes-gcm.cpp

MAIN_SRC = main.cpp

ifeq ($(COMPILER),msvc)
    BUILD_DIR = build
    CXX = cl.exe
    CXXFLAGS = /MD /GS /O2 /Zi /EHsc /utf-8 /I$(INC_DIR)
    DLL_FLAGS = /LD /DBUILD_DLL
    
    # MSVC object files
    OBJS = $(notdir $(SRCS:.cpp=.obj))
    MAIN_OBJ = main.obj

    # Targets
    STATIC_LIB = $(BUILD_DIR)/libhybrid-pq-cp-abe.lib
    SHARED_LIB = $(BUILD_DIR)/libhybrid-pq-cp-abe.dll
    EXEC = $(BUILD_DIR)/main.exe
    
    # Libraries
    STATIC_LIBS = $(LIB_STATIC_DIR)/cryptlib.lib $(LIB_STATIC_DIR)/liboqs.lib $(LIB_STATIC_DIR)/librabe_ffi.lib
    SHARED_LIBS = liboqs.lib cryptlib.lib librabe_ffi.lib libcpabe_tkn20.lib bcrypt.lib advapi32.lib ntdll.lib
    
    LDFLAGS = /link /ignore:4099 /LIBPATH:$(LIB_STATIC_DIR) /MACHINE:X64
else
    BUILD_DIR = build_linux
    CXX = g++
    CXXFLAGS = -O2 -g -Wall -I$(INC_DIR) -fPIC
    DLL_FLAGS = -DBUILD_DLL -shared
    
    # GCC object files
    VPATH = $(SCHEMES_DIR) $(CORE_DIR) $(CRYPTO_DIR)
    OBJS = $(addprefix $(BUILD_DIR)/, $(notdir $(SRCS:.cpp=.o)))
    MAIN_OBJ = $(BUILD_DIR)/main.o
    
    # Targets
    STATIC_LIB = $(BUILD_DIR)/libhybrid-pq-cp-abe.a
    SHARED_LIB = $(BUILD_DIR)/libhybrid-pq-cp-abe.so
    EXEC = $(BUILD_DIR)/main
    
    # Libraries
    STATIC_LIBS_GCC = $(LIB_STATIC_DIR)/libcryptopp.a $(LIB_STATIC_DIR)/librabe_ffi.a $(LIB_STATIC_DIR)/libcpabe_tkn20.a $(LIB_STATIC_DIR)/liboqs.a
    LDFLAGS = -lpthread -ldl -lm
endif

.PHONY: all clean executable shared static help

all: static shared executable
	@echo "================================================================"
	@echo " All targets built successfully!"
	@echo " Output files are located in $(BUILD_DIR)/"
	@echo "================================================================"

help:
	@echo "================================================================"
	@echo "             Hybrid CP-ABE Library Makefile"
	@echo "================================================================"
	@echo "Usage:"
	@echo "  make                 Build everything (static, shared, executable)"
	@echo "  make all             Same as above"
	@echo "  make static          Build only the static library"
	@echo "  make shared          Build only the shared library"
	@echo "  make executable      Build only the main executable"
	@echo "  make clean           Remove all build artifacts and temporary files"
	@echo "  make help            Show this help message"
	@echo ""
	@echo "Environment variables:"
	@echo "  COMPILER=msvc        Force use of MSVC (default on Windows)"
	@echo "  COMPILER=gcc         Force use of GCC (default on Linux)"
	@echo "================================================================"

ifeq ($(COMPILER),msvc)

static: $(STATIC_LIB)

$(STATIC_LIB):
	@if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)
	@echo Generating TKN20 import lib...
	lib.exe /NOLOGO /DEF:$(LIB_STATIC_DIR)/libcpabe_tkn20.def /OUT:$(LIB_STATIC_DIR)/libcpabe_tkn20.lib /MACHINE:X64
	@echo Compiling...
	$(CXX) $(CXXFLAGS) /c $(SRCS)
	@echo Archiving...
	lib.exe /OUT:$(STATIC_LIB) $(OBJS) $(STATIC_LIBS)
	@echo Cleaning up object files...
	del /Q *.obj
	@echo Done! Output at $(STATIC_LIB)

shared: $(SHARED_LIB)

$(SHARED_LIB): static
	@if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)
	@echo Compiling Shared Library...
	$(CXX) $(CXXFLAGS) $(DLL_FLAGS) /Fe:$(SHARED_LIB) $(SRCS) $(LDFLAGS) $(SHARED_LIBS)
	copy /Y lib\dynamic\libcpabe_tkn20.dll $(BUILD_DIR)
	@del /Q *.obj *.pdb >nul 2>&1
	@del /Q $(BUILD_DIR)\*.exp $(BUILD_DIR)\*.ilk $(BUILD_DIR)\*.pdb >nul 2>&1
	@echo Done! Output at $(SHARED_LIB)

executable: $(EXEC)

$(EXEC): static
	@if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)
	@echo Compiling Executable...
	$(CXX) $(CXXFLAGS) /Fe:$(EXEC) $(MAIN_SRC) $(LDFLAGS) $(STATIC_LIB) $(SHARED_LIBS)
	copy /Y lib\dynamic\libcpabe_tkn20.dll $(BUILD_DIR)
	@del /Q *.obj *.pdb >nul 2>&1
	@del /Q $(BUILD_DIR)\*.exp $(BUILD_DIR)\*.ilk $(BUILD_DIR)\*.pdb >nul 2>&1
	@echo Done! Output at $(EXEC)

clean:
	@if exist $(BUILD_DIR) rmdir /S /Q $(BUILD_DIR)
	@del /Q *.obj *.pdb >nul 2>&1

else

static: $(STATIC_LIB)

$(STATIC_LIB): $(OBJS)
	@mkdir -p $(BUILD_DIR)
	@rm -f $(STATIC_LIB)
	ar rcs $(STATIC_LIB) $(OBJS)
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
	@rm -f $(OBJS)
	@echo Done! Output at $(STATIC_LIB)

shared: $(SHARED_LIB)

$(SHARED_LIB): static
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(DLL_FLAGS) $(SRCS) -o $(SHARED_LIB) $(STATIC_LIBS_GCC)
	@echo Done! Output at $(SHARED_LIB)

executable: $(EXEC)

$(EXEC): static
	@mkdir -p $(BUILD_DIR)
	$(CXX) -O2 -g -Wall -I$(INC_DIR) $(MAIN_SRC) -o $(EXEC) $(STATIC_LIB) $(LDFLAGS)
	@echo Done! Output at $(EXEC)

$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)

endif
