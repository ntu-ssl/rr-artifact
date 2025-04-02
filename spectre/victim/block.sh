#!/bin/bash

PID_FILE="/root/rr-artifact/spectre/victim/pid"
PID=$(cat "$PID_FILE")

while kill -0 "$PID" > /dev/null 2>&1; do :; done
