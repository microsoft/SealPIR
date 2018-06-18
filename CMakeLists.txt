cmake_minimum_required(VERSION 3.10)

project(SealPIR VERSION 1.1 LANGUAGES CXX)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

add_executable(sealpir 
	main.cpp
	pir.cpp
	pir_client.cpp
	pir_server.cpp
)

find_package(SEAL 2.3.1 EXACT REQUIRED)
find_package(Threads REQUIRED)

target_link_libraries(sealpir 
	SEAL::seal
	Threads::Threads
)
