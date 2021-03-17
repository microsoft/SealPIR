cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(SealPIR VERSION 2.1 LANGUAGES CXX)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

add_executable(main main.cpp pir.cpp pir_client.cpp pir_server.cpp
)

add_executable(encoding_test encoding_test.cpp pir.cpp)

find_package(SEAL 3.6 REQUIRED)

target_link_libraries(main SEAL::seal)

target_link_libraries(encoding_test SEAL::seal)
