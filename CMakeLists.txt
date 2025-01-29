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
set(SOURCES
  src/crypto_engine.cpp
  src/file_handler.cpp
  src/tpm_manager.cpp
)

add_executable(sfe src/main.cpp ${SOURCES})
target_link_libraries(sfe OpenSSL::SSL OpenSSL::Crypto)
