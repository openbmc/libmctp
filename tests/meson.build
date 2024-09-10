
tests = [
    'test_eid',
    'test_seq',
    'test_bridge',
    'test_cmds',
    'test_core',
    ]

if get_option('bindings').contains('serial')
    tests += 'test_serial'
endif
if get_option('bindings').contains('astlpc')
    tests += 'test_astlpc'
endif

test_include_dirs = [include_directories('.'), libmctp_include_dir]
foreach t : tests
    test(
        t,
        executable(
            t,
            [t + '.c', 'test-utils.c'],
            include_directories: test_include_dirs,
            dependencies: [libmctp_dep],
        ),
    )
endforeach
