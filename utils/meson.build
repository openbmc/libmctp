demux_sources = ['mctp-demux-daemon.c']
demux_args = []
demux_dep = [libmctp_dep, pcap_dep, libsystemd_dep]
# While mctp-demux-daemon will build without pcap, it won't
# be functional.
# TODO only build mctp-demux-daemon when pcap is available.
if pcap_dep.found()
    demux_args += '-DHAVE_PCAP'
    demux_sources += 'mctp-capture.c'
endif

demux = executable(
    'mctp-demux-daemon',
    demux_sources,
    include_directories: libmctp_include_dir,
    dependencies: demux_dep,
    c_args: demux_args,
    install: true,
)

pipe = executable(
    'mctp-pipe',
    'mctp-pipe.c',
    include_directories: libmctp_include_dir,
    dependencies: [libmctp_dep],
    install: false,
)

mctp_in = executable(
    'mctp-in',
    'mctp-in.c',
    include_directories: libmctp_include_dir,
    dependencies: [libmctp_dep],
    install: false,
)
