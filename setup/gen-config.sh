#!/bin/bash

cpu_model=$(grep 'model name' /proc/cpuinfo | uniq | cut -d ":" -f2 | sed -e 's/^[[:space:]]*//')
arch=0

# Check if the CPU model indicates Zen 2 or Zen 3
if [[ "$cpu_model" == *"EPYC"*"7"[0-9][0-9]"2"* ]]; then
  echo "Machine is based on Zen 2 architecture"
  arch=2
elif [[ "$cpu_model" == *"EPYC"*"7"[0-9][0-9]"3"* ]]; then
  echo "Machine is based on Zen 3 architecture"
  arch=3
else
  echo "Machine architecture is unknown"
fi


export CONFIG="$(pwd)/../config.json"
root_directory=$(pwd)/..
parent_directory=$(pwd)/../..
num_cores=$(nproc)

json_data=$(jq -n --arg root_directory "$root_directory" '{"root-directory": $root_directory}')
json_data=$(echo "$json_data" | jq --arg cores "$num_cores" '. + { "cores": $cores }')
json_data=$(echo "$json_data" | jq --arg parent_directory "$parent_directory" '. + {"parent-directory": $parent_directory}')
json_data=$(echo "$json_data" | jq --arg arch "$arch" '. + {"arch": $arch}')

echo "$json_data" > ../config.json

cat ../config.json

