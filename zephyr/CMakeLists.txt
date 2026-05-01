# Copyright (c) 2024 Intel Corporation.
#
# SPDX-License-Identifier: BSD-3-Clause

if(CONFIG_MCTP)
  set(MCTP_SRC ${CMAKE_CURRENT_SOURCE_DIR}/..)

  zephyr_interface_library_named(mctp)
  target_link_libraries(zephyr_interface INTERFACE mctp)
  target_include_directories(mctp INTERFACE ${MCTP_SRC})

  zephyr_library_named(modules_mctp)
  zephyr_library_link_libraries(mctp)

  zephyr_library_sources_ifdef(
  	CONFIG_MCTP
  	${MCTP_SRC}/alloc.c
  	${MCTP_SRC}/crc32.c
  	${MCTP_SRC}/core.c
  	${MCTP_SRC}/log.c
  	${MCTP_SRC}/libmctp.h
  	${MCTP_SRC}/crc-16-ccitt.c
  )
endif() 
