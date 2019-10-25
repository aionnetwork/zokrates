#!/usr/bin/env bash

if [ $# -ne 4 ]
  then
    echo "input arguments missing!"
    echo "argument 1: {pghr13 | g16 | gm17}"
    echo "argument 2: .code file"
    echo "argument 3: arguments to compute witness for"
    echo "argument 4: {debug | release}"
    exit 1
fi

if ! [[ $1 == "pghr13" || $1 ==  "g16" || $1 == "gm17" ]] ; then
    echo "[invalid argument 1] must be one of {pghr13 | g16 | gm17}!"
    exit 1
fi

if ! [[ -f $2 ]]; then
    echo "[invalid argument 2] file not found!"
fi

if ! [[ $4 == "debug" || $4 ==  "release" ]] ; then
    echo "[invalid argument 4] must be one of {debug | release}!"
    exit 1
fi

code_file=$2
proof_system=$1
witness_args=$3

script=$(readlink -f "$0")
basedir=$(dirname $(readlink -f "$0"))
zokrates="$basedir/target/debug/zokrates"
if [ $4 == "release" ]; then
    zokrates="$basedir/target/release/zokrates"
fi

echo $zokrates

# compile
eval "$zokrates compile -i $code_file"

# perform the setup phase
eval "$zokrates setup --proving-scheme $proof_system"

# execute the program
eval "$zokrates compute-witness -a $witness_args"

# generate a proof of computation
eval "$zokrates generate-proof --proving-scheme $proof_system"

# export a solidity verifier
eval "$zokrates export-avm-verifier --proving-scheme $proof_system"






















