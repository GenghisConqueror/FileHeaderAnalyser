cmake_minimum_required(VERSION 3.10)
project(FileAnalyzer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(LIEF REQUIRED)

add_executable(FileAnalyzer
    src/main.cpp
    src/analyzer.cpp
    src/utils/hash.cpp
    src/utils/json_output.cpp
)

target_include_directories(FileAnalyzer PRIVATE src)
target_link_libraries(FileAnalyzer PRIVATE LIEF::LIEF)
