#!/bin/bash

qemu_pid=$(ps aux | grep qemu-system | awk 'NR==3 {print $2}')

thread_ids=$(ps -T -p $qemu_pid | awk 'NR>1 {print $2}')

thread_array=($thread_ids)

fourth_thread_id=${thread_array[4]}

echo "vCPU thread id: $fourth_thread_id"

taskset -pc 0 $fourth_thread_id

