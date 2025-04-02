keys_path = 'keys'
recovered_keys_path = 'recovered_keys'


with open(keys_path, 'r') as keys_file, open(recovered_keys_path, 'r') as recovered_keys_file:
    keys = keys_file.readlines()
    recovered_keys = recovered_keys_file.readlines()

correct_cnt = 0
for i in range(100):
    key = keys[i]
    recovered_key = recovered_keys[i]

    if key == recovered_key:
        correct_cnt += 1

print(f"Accuracy:{correct_cnt}%")
