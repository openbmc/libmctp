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
        FLAGS="-Wformat -Werror=format-security"
        FLAGS="${FLAGS} -Werror=array-bounds"
        FLAGS="${FLAGS} -Werror=implicit-function-declaration"
        FLAGS="${FLAGS} -fsanitize=address,leak,undefined"
        FLAGS="${FLAGS} -ggdb"
        ./configure \
            CFLAGS="${FLAGS}" \
            --enable-code-coverage \
            "$@"
        ;;
    *)
        echo 'Run "./configure ${CONFIGURE_FLAGS} && make"'
        ;;
esac
