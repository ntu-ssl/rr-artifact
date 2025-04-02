sudo apt update
sudo apt install $(cat packages.txt) -y
sudo add-apt-repository universe
sudo apt-get update
sudo apt-get install -y wget alien
wget https://www.nasm.us/pub/nasm/releasebuilds/2.15.05/linux/nasm-2.15.05-0.fc31.x86_64.rpm -O/tmp/nasm-2.15.05-0.fc31.x86_64.rpm
sudo alien /tmp/nasm-2.15.05-0.fc31.x86_64.rpm -i
rm -f /tmp/nasm-2.15.05-0.fc31.x86_64.rpm

pip install -r requirements.txt
