include_directories (${SealPIR_SOURCE_DIR}/src)

add_executable(expand_test expand_test.cpp)
target_link_libraries(expand_test sealpir)
add_test(NAME expand_test COMMAND expand_test)

add_executable(query_test query_test.cpp)
target_link_libraries(query_test sealpir)
add_test(NAME query_test COMMAND query_test)

add_executable(simple_query_test simple_query_test.cpp)
target_link_libraries(simple_query_test sealpir)
add_test(NAME simple_query_test COMMAND simple_query_test)
