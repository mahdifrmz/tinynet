#!/bin/bash
if [[ ! -d /run/tinynet/sim ]]
then
    exit 1
fi
cd /run/tinynet/sim
for dir in $(ls)
do
    cd $dir/hosts
    for f in $(ls)
    do
        umount $f
        rm $f
    done
    cd ../..
    rm -rf $dir
done