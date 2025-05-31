cmake_minimum_required(VERSION 3.12)
project(moqt_validator LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

add_executable(moqt_validator
    src/main.cpp
    src/common.cpp
    src/control_parser.cpp
    src/validator.cpp
)

add_executable(moqt_validator_test
    test/test_validator.cpp
    src/common.cpp
    src/control_parser.cpp
    src/validator.cpp
)

target_include_directories(moqt_validator_test PRIVATE include)

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(moqt_validator PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(moqt_validator_test PRIVATE -Wall -Wextra -Wpedantic)
endif()

install(TARGETS moqt_validator DESTINATION bin)
install(TARGETS moqt_validator_test DESTINATION bin)
