cmake_minimum_required (VERSION 3.5 FATAL_ERROR)

add_definitions (-DMCTP_LOG_STDERR)
add_definitions (-DMCTP_HAVE_FILEIO)
add_definitions (-DMCTP_HAVE_STDIO)
add_definitions (-DMCTP_DEFAULT_ALLOC)

add_library (mctp STATIC alloc.c core.c log.c libmctp.h serial.c)

target_include_directories (mctp PUBLIC
                            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
                            $<INSTALL_INTERFACE:include/libmctp)

enable_testing ()

add_executable (test_eid tests/test_eid.c tests/test-utils.c)
target_link_libraries (test_eid mctp)

add_executable (test_seq tests/test_seq.c tests/test-utils.c)
target_link_libraries (test_seq mctp)

install (TARGETS mctp DESTINATION lib)
install (FILES libmctp.h DESTINATION include)

