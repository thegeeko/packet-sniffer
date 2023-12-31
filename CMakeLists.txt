# Project
cmake_minimum_required(VERSION 3.25)
project(Packet-Sniffer)

# Setup
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/modules")
set(CMAKE_BUILD_TYPE Debug)

# Compiler Flags
set(GCC_COVERAGE_COMPILE_FLAGS "")
set(MSVC_COVERAGE_COMPILE_FLAGS "/MP")

if(NOT MSVC)
	set(CMAKE_CXX_FLAGS	"${CMAKE_CXX_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS}")
else()
	set(CMAKE_CXX_FLAGS	"${CMAKE_CXX_FLAGS} ${MSVC_COVERAGE_COMPILE_FLAGS}")
endif()

# Adding Executable
file(
	GLOB_RECURSE # recursive
	SRC # variable to store the source files and headers
	CONFIGURE_DEPENDS # make a dependency
	"src/*.hpp"
	"src/*.cpp"
)

add_executable(packet-sniffer ${SRC})

# Adding Libraries
add_subdirectory("libs/libpcap")
add_subdirectory("libs/spdlog")

target_link_libraries(packet-sniffer PRIVATE pcap)
target_link_libraries(packet-sniffer PRIVATE spdlog::spdlog)

# Link compile commands in root if it's not visual studio
# for lsp in vscode and neovim
if (NOT CMAKE_GENERATOR MATCHES "Visual Studio")
  execute_process(
  	COMMAND ${CMAKE_COMMAND} -E create_symlink
  		${CMAKE_BINARY_DIR}/compile_commands.json
  		${CMAKE_SOURCE_DIR}/compile_commands.json
  )
endif()
