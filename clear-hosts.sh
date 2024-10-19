#!/bin/bash
cd /var/run/netns
for f in *
do
    umount $f
    rm $f
done