cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

add_definitions(-DMCTP_LOG_STDERR)
add_definitions(-DMCTP_FILEIO)

add_library(libmctp STATIC alloc.c core.c libmctp.h serial.c)

target_include_directories(libmctp
                           PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
                                  $<INSTALL_INTERFACE:include/libmctp)

enable_testing()

add_executable(mctp-in-test tests/mctp-in.c)
target_link_libraries(mctp-in-test libmctp)

add_executable(mctp-pipe-test tests/mctp-pipe.c)
target_link_libraries(mctp-pipe-test libmctp)

install(TARGETS libmctp DESTINATION lib)
install(FILES libmctp.h DESTINATION include)