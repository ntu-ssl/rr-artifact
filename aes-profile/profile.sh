function run(){
local Te=$1
local N_profile=$2
local SAMPLE_N=$3
local NOCACHE=$4

# Compile the attacker
cd attacker
make clean > /dev/null 2>&1 ;
make SAMPLE_N=$SAMPLE_N NOCACHE=$NOCACHE > /dev/null 2>&1 ;
cd ..

# Compile and run the victim.
taskset -c 8 ssh -p 2222 root@localhost " \
cd /root/rr-artifact/aes-profile/victim/; \
make N_profile=$N_profile NOCACHE=$NOCACHE > /dev/null 2>&1; \
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space > /dev/null 2>&1; \
echo 0 > /root/rr-artifact/aes-profile/victim/flag > /dev/null 2>&1; \
export LD_LIBRARY_PATH=/root/rr-artifact/openssl-1.1.0l/ > /dev/null 2>&1; \
nohup nice -n -20 /root/rr-artifact/aes-profile/victim/victim -t $Te > /dev/null 2>&1 & \
/root/rr-artifact/aes-profile/victim/wait.sh > /dev/null 2>&1; \
cat /root/rr-artifact/aes-profile/victim/address" > ./gpas/address

# Run the attacker.
sudo taskset -c 1 ./attacker/attacker \
	-t $Te \
	-n $N_profile

# Wait until the victim finishes.
taskset -c 8 ssh -p 2222 root@localhost "/root/rr-artifact/aes-profile/victim/block.sh > /dev/null 2>&1;"
}

json_data=$(cat ../config.json)
export CONFIG=$(echo "$json_data" | jq -r '."root-directory"')

N_profile=1000

NOCACHE=0
SAMPLE_N=80
for arg in "$@"; do
    if [[ "$arg" == "nocache" ]]; then
        NOCACHE=1
		SAMPLE_N=180
    fi
done

for Te in $(seq 0 3)
do
	echo "Generating the template for Te$Te..."
	run $Te $N_profile $SAMPLE_N $NOCACHE
	cd analysis-utils
	taskset -c 8 python3 generate-template.py $Te $SAMPLE_N $(cat ../result/d_range_lowerbound_Te$Te)
	cd ..
done

