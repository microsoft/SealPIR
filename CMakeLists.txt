cmake_minimum_required(VERSION 3.10)

project(SealPIR VERSION 2.1 LANGUAGES CXX)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

add_executable(sealpir 
	main.cpp
	pir.cpp
	pir_client.cpp
	pir_server.cpp
)

find_package(SEAL 3.2.0 EXACT REQUIRED)

target_link_libraries(sealpir SEAL::seal
)
