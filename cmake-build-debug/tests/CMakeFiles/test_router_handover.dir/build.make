# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.13

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/somdoron/.local/share/JetBrains/Toolbox/apps/CLion/ch-0/183.5153.40/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /home/somdoron/.local/share/JetBrains/Toolbox/apps/CLion/ch-0/183.5153.40/bin/cmake/linux/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/somdoron/git/libzmq

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/somdoron/git/libzmq/cmake-build-debug

# Include any dependencies generated for this target.
include tests/CMakeFiles/test_router_handover.dir/depend.make

# Include the progress variables for this target.
include tests/CMakeFiles/test_router_handover.dir/progress.make

# Include the compile flags for this target's objects.
include tests/CMakeFiles/test_router_handover.dir/flags.make

tests/CMakeFiles/test_router_handover.dir/test_router_handover.cpp.o: tests/CMakeFiles/test_router_handover.dir/flags.make
tests/CMakeFiles/test_router_handover.dir/test_router_handover.cpp.o: ../tests/test_router_handover.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/somdoron/git/libzmq/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object tests/CMakeFiles/test_router_handover.dir/test_router_handover.cpp.o"
	cd /home/somdoron/git/libzmq/cmake-build-debug/tests && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/test_router_handover.dir/test_router_handover.cpp.o -c /home/somdoron/git/libzmq/tests/test_router_handover.cpp

tests/CMakeFiles/test_router_handover.dir/test_router_handover.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_router_handover.dir/test_router_handover.cpp.i"
	cd /home/somdoron/git/libzmq/cmake-build-debug/tests && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/somdoron/git/libzmq/tests/test_router_handover.cpp > CMakeFiles/test_router_handover.dir/test_router_handover.cpp.i

tests/CMakeFiles/test_router_handover.dir/test_router_handover.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_router_handover.dir/test_router_handover.cpp.s"
	cd /home/somdoron/git/libzmq/cmake-build-debug/tests && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/somdoron/git/libzmq/tests/test_router_handover.cpp -o CMakeFiles/test_router_handover.dir/test_router_handover.cpp.s

# Object files for target test_router_handover
test_router_handover_OBJECTS = \
"CMakeFiles/test_router_handover.dir/test_router_handover.cpp.o"

# External object files for target test_router_handover
test_router_handover_EXTERNAL_OBJECTS =

bin/test_router_handover: tests/CMakeFiles/test_router_handover.dir/test_router_handover.cpp.o
bin/test_router_handover: tests/CMakeFiles/test_router_handover.dir/build.make
bin/test_router_handover: lib/libtestutil.a
bin/test_router_handover: /usr/lib64/librt.so
bin/test_router_handover: lib/libzmq.so.5.2.2
bin/test_router_handover: lib/libunity.a
bin/test_router_handover: tests/CMakeFiles/test_router_handover.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/somdoron/git/libzmq/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ../bin/test_router_handover"
	cd /home/somdoron/git/libzmq/cmake-build-debug/tests && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_router_handover.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tests/CMakeFiles/test_router_handover.dir/build: bin/test_router_handover

.PHONY : tests/CMakeFiles/test_router_handover.dir/build

tests/CMakeFiles/test_router_handover.dir/clean:
	cd /home/somdoron/git/libzmq/cmake-build-debug/tests && $(CMAKE_COMMAND) -P CMakeFiles/test_router_handover.dir/cmake_clean.cmake
.PHONY : tests/CMakeFiles/test_router_handover.dir/clean

tests/CMakeFiles/test_router_handover.dir/depend:
	cd /home/somdoron/git/libzmq/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/somdoron/git/libzmq /home/somdoron/git/libzmq/tests /home/somdoron/git/libzmq/cmake-build-debug /home/somdoron/git/libzmq/cmake-build-debug/tests /home/somdoron/git/libzmq/cmake-build-debug/tests/CMakeFiles/test_router_handover.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/CMakeFiles/test_router_handover.dir/depend

