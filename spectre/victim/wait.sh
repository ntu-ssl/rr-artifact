#!/bin/bash
GUEST_DIR="/root"
THISPID=$$
while true
do
	var=$(cat $GUEST_DIR/rr-artifact/spectre/victim/flag)
	if [[ $var = "1" ]]
	then
		exit
	fi
done
