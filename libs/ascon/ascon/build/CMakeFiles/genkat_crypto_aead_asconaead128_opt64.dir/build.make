# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.30

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/ryuzaou/Desktop/allt/dev/Thesis/libs/ascon/ascon

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ryuzaou/Desktop/allt/dev/Thesis/libs/ascon/ascon/build

# Include any dependencies generated for this target.
include CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/flags.make

CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/tests/genkat_aead.c.o: CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/flags.make
CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/tests/genkat_aead.c.o: /home/ryuzaou/Desktop/allt/dev/Thesis/libs/ascon/ascon/tests/genkat_aead.c
CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/tests/genkat_aead.c.o: CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/ryuzaou/Desktop/allt/dev/Thesis/libs/ascon/ascon/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/tests/genkat_aead.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/tests/genkat_aead.c.o -MF CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/tests/genkat_aead.c.o.d -o CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/tests/genkat_aead.c.o -c /home/ryuzaou/Desktop/allt/dev/Thesis/libs/ascon/ascon/tests/genkat_aead.c

CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/tests/genkat_aead.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/tests/genkat_aead.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ryuzaou/Desktop/allt/dev/Thesis/libs/ascon/ascon/tests/genkat_aead.c > CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/tests/genkat_aead.c.i

CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/tests/genkat_aead.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/tests/genkat_aead.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ryuzaou/Desktop/allt/dev/Thesis/libs/ascon/ascon/tests/genkat_aead.c -o CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/tests/genkat_aead.c.s

# Object files for target genkat_crypto_aead_asconaead128_opt64
genkat_crypto_aead_asconaead128_opt64_OBJECTS = \
"CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/tests/genkat_aead.c.o"

# External object files for target genkat_crypto_aead_asconaead128_opt64
genkat_crypto_aead_asconaead128_opt64_EXTERNAL_OBJECTS =

genkat_crypto_aead_asconaead128_opt64: CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/tests/genkat_aead.c.o
genkat_crypto_aead_asconaead128_opt64: CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/build.make
genkat_crypto_aead_asconaead128_opt64: libcrypto_aead_asconaead128_opt64.a
genkat_crypto_aead_asconaead128_opt64: CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/home/ryuzaou/Desktop/allt/dev/Thesis/libs/ascon/ascon/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable genkat_crypto_aead_asconaead128_opt64"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/build: genkat_crypto_aead_asconaead128_opt64
.PHONY : CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/build

CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/cmake_clean.cmake
.PHONY : CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/clean

CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/depend:
	cd /home/ryuzaou/Desktop/allt/dev/Thesis/libs/ascon/ascon/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ryuzaou/Desktop/allt/dev/Thesis/libs/ascon/ascon /home/ryuzaou/Desktop/allt/dev/Thesis/libs/ascon/ascon /home/ryuzaou/Desktop/allt/dev/Thesis/libs/ascon/ascon/build /home/ryuzaou/Desktop/allt/dev/Thesis/libs/ascon/ascon/build /home/ryuzaou/Desktop/allt/dev/Thesis/libs/ascon/ascon/build/CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/genkat_crypto_aead_asconaead128_opt64.dir/depend

