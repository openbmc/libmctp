#!/bin/sh

set -eu

autoreconf -f -i


BOOTSTRAP_MODE=""

if [ $# -gt 0 ];
then
    BOOTSTRAP_MODE="${1}"
    shift 1
fi

case "${BOOTSTRAP_MODE}" in
    dev)
        FLAGS="-fsanitize=address,leak,undefined -Wformat -Werror=format-security -Werror=array-bounds -ggdb"
        ./configure \
            CFLAGS="${FLAGS}" \
            CXXFLAGS="${FLAGS}" \
            --enable-code-coverage \
            "$@"
        ;;
    *)
        echo 'Run "./configure ${CONFIGURE_FLAGS} && make"'
        ;;
esac
