
truncate -s 0 ../aes-attack/keys/recovered_keys

for ((i=0; i < 100; i++))
do
cd ../aes-profile
./profile.sh
cd ../aes-attack
./attack.sh keyid=$i
done

cd keys
cp recovered_keys recovered_keys_ce
python3 accuracy.py
exit 0
