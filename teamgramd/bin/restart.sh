#!/usr/bin/env bash

if [ "$#" -eq 0 ]; then
    echo "provide service name" && exit 1
fi

(
    cd ../..
    make "$1"
)

killall "$1"
nohup ./"$1" -f=../etc/"$1".yaml >>../logs/"$1".log 2>&1 &
