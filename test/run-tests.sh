#!/bin/bash

COLOR_Black='\033[0;30m'
COLOR_Red='\033[0;31m'
COLOR_Green='\033[0;32m'
COLOR_Yellow='\033[0;33m'
COLOR_Blue='\033[0;34m'
COLOR_Purple='\033[0;35m'
COLOR_Cyan='\033[0;36m'
COLOR_White='\033[0;37m'
COLOR_RESET='\033[0m'

bin=$1

for testfile in *.tn
do
    testfile=$(echo -n $testfile | head -c -3)
    echo Running test "'$testfile'":
    echo
    $bin test $testfile.tn
    st=$?
    echo
    if [[ $st == 0 ]]
    then
        echo -e All tests in "'$testfile'"$COLOR_Green passed $COLOR_RESET
    else
        echo -e Some tests in "'$testfile'"$COLOR_Red failed $COLOR_RESET
        code=1
    fi
    echo
done

exit $code