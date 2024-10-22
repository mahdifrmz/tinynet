#!/bin/bash
if [[ ! -d /var/run/netns ]]
then
    exit 1
fi
cd /var/run/netns
for f in $(ls)
do
    umount $f
    rm $f
done