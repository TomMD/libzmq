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
include unittests/CMakeFiles/unittest_radix_tree.dir/depend.make

# Include the progress variables for this target.
include unittests/CMakeFiles/unittest_radix_tree.dir/progress.make

# Include the compile flags for this target's objects.
include unittests/CMakeFiles/unittest_radix_tree.dir/flags.make

unittests/CMakeFiles/unittest_radix_tree.dir/unittest_radix_tree.cpp.o: unittests/CMakeFiles/unittest_radix_tree.dir/flags.make
unittests/CMakeFiles/unittest_radix_tree.dir/unittest_radix_tree.cpp.o: ../unittests/unittest_radix_tree.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/somdoron/git/libzmq/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object unittests/CMakeFiles/unittest_radix_tree.dir/unittest_radix_tree.cpp.o"
	cd /home/somdoron/git/libzmq/cmake-build-debug/unittests && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/unittest_radix_tree.dir/unittest_radix_tree.cpp.o -c /home/somdoron/git/libzmq/unittests/unittest_radix_tree.cpp

unittests/CMakeFiles/unittest_radix_tree.dir/unittest_radix_tree.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/unittest_radix_tree.dir/unittest_radix_tree.cpp.i"
	cd /home/somdoron/git/libzmq/cmake-build-debug/unittests && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/somdoron/git/libzmq/unittests/unittest_radix_tree.cpp > CMakeFiles/unittest_radix_tree.dir/unittest_radix_tree.cpp.i

unittests/CMakeFiles/unittest_radix_tree.dir/unittest_radix_tree.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/unittest_radix_tree.dir/unittest_radix_tree.cpp.s"
	cd /home/somdoron/git/libzmq/cmake-build-debug/unittests && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/somdoron/git/libzmq/unittests/unittest_radix_tree.cpp -o CMakeFiles/unittest_radix_tree.dir/unittest_radix_tree.cpp.s

# Object files for target unittest_radix_tree
unittest_radix_tree_OBJECTS = \
"CMakeFiles/unittest_radix_tree.dir/unittest_radix_tree.cpp.o"

# External object files for target unittest_radix_tree
unittest_radix_tree_EXTERNAL_OBJECTS =

bin/unittest_radix_tree: unittests/CMakeFiles/unittest_radix_tree.dir/unittest_radix_tree.cpp.o
bin/unittest_radix_tree: unittests/CMakeFiles/unittest_radix_tree.dir/build.make
bin/unittest_radix_tree: lib/libtestutil-static.a
bin/unittest_radix_tree: /usr/lib64/librt.so
bin/unittest_radix_tree: lib/libzmq.a
bin/unittest_radix_tree: lib/libunity.a
bin/unittest_radix_tree: unittests/CMakeFiles/unittest_radix_tree.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/somdoron/git/libzmq/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ../bin/unittest_radix_tree"
	cd /home/somdoron/git/libzmq/cmake-build-debug/unittests && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/unittest_radix_tree.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
unittests/CMakeFiles/unittest_radix_tree.dir/build: bin/unittest_radix_tree

.PHONY : unittests/CMakeFiles/unittest_radix_tree.dir/build

unittests/CMakeFiles/unittest_radix_tree.dir/clean:
	cd /home/somdoron/git/libzmq/cmake-build-debug/unittests && $(CMAKE_COMMAND) -P CMakeFiles/unittest_radix_tree.dir/cmake_clean.cmake
.PHONY : unittests/CMakeFiles/unittest_radix_tree.dir/clean

unittests/CMakeFiles/unittest_radix_tree.dir/depend:
	cd /home/somdoron/git/libzmq/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/somdoron/git/libzmq /home/somdoron/git/libzmq/unittests /home/somdoron/git/libzmq/cmake-build-debug /home/somdoron/git/libzmq/cmake-build-debug/unittests /home/somdoron/git/libzmq/cmake-build-debug/unittests/CMakeFiles/unittest_radix_tree.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : unittests/CMakeFiles/unittest_radix_tree.dir/depend

