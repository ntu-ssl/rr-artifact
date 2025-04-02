
truncate -s 0 ../aes-attack/keys/recovered_keys

for ((i=0; i < 100; i++))
do
cd ../aes-profile
./profile.sh nocache
cd ../aes-attack
./attack.sh nocache keyid=$i
done

cd keys
cp recovered_keys recovered_keys_cd
python3 accuracy.py
exit 0

