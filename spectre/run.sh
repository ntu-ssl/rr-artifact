#!/bin/bash
function run(){

cd attacker
make clean > /dev/null 2>&1 ;
make > /dev/null 2>&1 ;
cd ..

# Run the victim.
taskset -c 8 ssh -p 2222 root@localhost "
cd /root/rr-artifact/spectre/victim/; \
make clean > /dev/null 2>&1; \
make > /dev/null 2>&1; \
echo 1 > /proc/sys/vm/nr_hugepages; \
echo 0 > /root/rr-artifact/spectre/victim/flag; \
nohup /root/rr-artifact/spectre/victim/victim > /dev/null 2>&1 & \
/root/rr-artifact/spectre/victim/wait.sh; \
cat /root/rr-artifact/spectre/victim/address" > ./gpas/address

# Run the attacker.
sudo taskset -c 1 ./attacker/attacker

# Wait until the victim finishes.
taskset -c 8 ssh -p 2222 root@localhost "/root/rr-artifact/spectre/victim/block.sh > /dev/null 2>&1;"
}

json_data=$(cat ../config.json)
export CONFIG=$(echo "$json_data" | jq -r '."root-directory"')

truncate -s 0 ./results/recovered_secrets
truncate -s 0 ./results/time

echo "Testing the Spectre attack..."
run

# Get evaluation data.
taskset -c 8 python3 ./analysis-utils/analyze.py
