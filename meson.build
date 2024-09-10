project(
    'libmctp', 'c',
    meson_version: '>= 1.1',
    version: '0.11',
    default_options: [
        'debug=true',
        'optimization=g',
        'warning_level=2',
        'werror=true',
        'tests=' + (meson.is_subproject() ? 'disabled' : 'enabled'),
    ],
)

sources = [
     'core.c',
     'alloc.c',
     'log.c',
]

headers = [
    'libmctp.h',
]

serial_sources = [
    'serial.c',
    'crc-16-ccitt.c',
]

serial_headers = [
    'libmctp-serial.h'
]

astlpc_sources = [
    'astlpc.c',
    'crc32.c',
]

astlpc_headers = [
    'libmctp-astlpc.h',
]

libmctp_sources = sources
libmctp_headers = headers

if get_option('bindings').contains('serial')
    libmctp_sources += serial_sources
    libmctp_headers += serial_headers
endif
if get_option('bindings').contains('astlpc')
    libmctp_sources += astlpc_sources
    libmctp_headers += astlpc_headers
endif

compiler = meson.get_compiler('c')

if get_option('default_alloc').require(
    compiler.links('''
        #include <stdlib.h>
        void main()
        {
            free(malloc(4096));
        }
    ''')).allowed()
    add_project_arguments('-DMCTP_DEFAULT_ALLOC', language : 'c')
endif

if get_option('fileio').require(
    compiler.check_header('unistd.h') and compiler.check_header('fcntl.h')
    ).allowed()
    add_project_arguments('-DMCTP_HAVE_FILEIO', language : 'c')
endif

if get_option('syslog').require(
    compiler.links('''
        #include <stdarg.h>
        #include <syslog.h>
        void check_vsyslog(int level, const char *fmt, ...)
        {
            va_list ap;
            va_start(ap, fmt);
            vsyslog(0, fmt, ap);
            va_end(ap);
        }
        void main()
        {
            check_vsyslog(0, "\n");
        }
        ''')).allowed()
    add_project_arguments('-DMCTP_HAVE_SYSLOG', language : 'c')
endif

if get_option('stdio').require(
    compiler.links('''
        #include <stdarg.h>
        #include <stdio.h>
        void check_vsyslog(const char *fmt, ...)
        {
            va_list ap;
            va_start(ap, fmt);
            vprintf(fmt, ap);
            va_end(ap);
        }
        void main()
        {
            check_vsyslog("\n");
        }
        ''')).allowed()
    add_project_arguments('-DMCTP_HAVE_STDIO', language : 'c')
endif

# pcap is necessary for mctp-demux-daemon to be functional
pcap_dep = dependency('libpcap', required: false)

systemd_dep = dependency('systemd', required: false)
libsystemd_dep = dependency('libsystemd', required: false)

libmctp_include_dir = include_directories('.', is_system: true)
libmctp = library('mctp',
    libmctp_sources,
    include_directories: libmctp_include_dir,
    version: meson.project_version(),
    install: true,
)
install_headers(libmctp_headers)

if systemd_dep.found()
    unitdir = systemd_dep.get_variable(pkgconfig: 'systemdsystemunitdir')
    install_data('systemd/system/mctp-demux.service', install_dir: unitdir)
    install_data('systemd/system/mctp-demux.socket', install_dir: unitdir)
endif

import('pkgconfig').generate(libmctp,
    name: 'libmctp',
    description: 'MCTP protocol implementation',
    version: meson.project_version(),
)

libmctp_dep = declare_dependency(
    include_directories: libmctp_include_dir,
    link_with: libmctp,
)

subdir('utils')

if get_option('tests').allowed()
    subdir('tests')
endif
