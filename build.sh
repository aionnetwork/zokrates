#!/bin/bash

# Exit if any subcommand fails
set -e

# Disable building with libsnark in this script, until PGHR13 and GM17 verifier generation is implemented.  

#if [ -n "$WITH_LIBSNARK" ]; then
#	echo "building zokrates with libsnark"
#	cargo +nightly -Z package-features build --package zokrates_cli --features="libsnark"
#else
	echo "building zokrates without libsnark"
	cargo +nightly build
#fi
