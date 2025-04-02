def calculate_average(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
        values = [float(line.strip()) for line in lines]
        
        if not values:
            return None
        average = sum(values) / len(values)
        return average

recovered_secrets_file = "./results/recovered_secrets"
secrets_file = "./secrets/secrets"

time_file = "./results/time"
average_time = calculate_average(time_file)

print(f"Throughput: {1/average_time/1024:.2f} KB/s")

accurate = 0
with open(recovered_secrets_file, 'r') as recovered_secrets, open(secrets_file, 'r') as secrets:
    for i in range(100):
        content1 = recovered_secrets.readline()
        content2 = secrets.readline()

        if content1 == content2:
            accurate += 1

print(f"Correctness: {accurate / 100}")
