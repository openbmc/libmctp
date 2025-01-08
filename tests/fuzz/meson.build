if get_option('bindings').contains('i2c')
    executable(
        'i2c-fuzz',
        'i2c-fuzz.c',
        # for __AFL_LOOP
        cpp_args: ['-Wno-gnu-statement-expression-from-macro-expansion'],
        include_directories: test_include_dirs,
        dependencies: [libmctp_dep],
        )
endif
