cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(SealPIR VERSION 2.1 LANGUAGES CXX)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_executable(main
	main.cpp
)

add_library(sealpir STATIC
  pir.cpp
  pir_client.cpp
  pir_server.cpp
)

find_package(SEAL 3.2.0 EXACT REQUIRED)

target_link_libraries(main sealpir SEAL::seal)

install(TARGETS sealpir ARCHIVE DESTINATION lib LIBRARY DESTINATION lib)
install(FILES pir.hpp pir_client.hpp pir_server.hpp DESTINATION include/sealpir)
