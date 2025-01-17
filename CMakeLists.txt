cmake_minimum_required(VERSION 3.10)
project(secure_file_encryption)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include(FetchContent)

FetchContent_Declare(
    catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.8.0
)
FetchContent_MakeAvailable(catch2)

find_package(OpenSSL REQUIRED)

# Define the sources and headers
set(SOURCES src/merkletree.cpp)
set(HEADERS src/merkletree.h)

add_executable(irow src/main.cpp ${SOURCES} ${HEADERS})
target_link_libraries(irow OpenSSL::SSL OpenSSL::Crypto)

option(BUILD_TESTS "Build tests" ON)
if(BUILD_TESTS)
    message(STATUS "Building tests")
    add_executable(tests src/merkletree_test.cpp ${SOURCES} ${HEADERS})

    # Include Catch2 headers for the test target
    target_include_directories(tests PRIVATE ${catch2_SOURCE_DIR}/src)

    # Link dependencies to the test executable
    target_link_libraries(tests PRIVATE
        Catch2::Catch2
        OpenSSL::SSL
        OpenSSL::Crypto
    )
    
    # Enable testing
    enable_testing()
    add_test(NAME tests COMMAND tests)
endif()
