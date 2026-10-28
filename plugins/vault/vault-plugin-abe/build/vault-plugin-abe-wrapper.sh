#!/bin/sh
env > /tmp/plugin-env.log
/vault/plugins/vault-plugin-abe.bin "$@" > /tmp/plugin-out.log 2> /tmp/plugin-err.log
exit_code=$?
cat /tmp/plugin-out.log
cat /tmp/plugin-err.log >&2
exit $exit_code
