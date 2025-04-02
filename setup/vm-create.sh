json=$(cat ../config.json)
ROOTDIR=$(echo "$json" | jq -r '."parent-directory"')
CORE=$(echo "$json" | jq -r '."cores"')
cd $ROOTDIR/rr-artifact/guest-module
make
cd $ROOTDIR/rr-artifact/scripts
qemu-img create -f raw $ROOTDIR/cloud.img 20g
mkfs.ext4 $ROOTDIR/cloud.img
sudo mount $ROOTDIR/cloud.img /mnt
wget https://cloud-images.ubuntu.com/releases/focal/release/ubuntu-20.04-server-cloudimg-amd64-root.tar.xz
sudo mv ubuntu-20.04-server-cloudimg-amd64-root.tar.xz /mnt
cd /mnt; sudo tar xvf ubuntu-20.04-server-cloudimg-amd64-root.tar.xz; sync
sudo touch /mnt/etc/cloud/cloud-init.disabled
sudo mkdir /mnt/root/.ssh
sudo cp -r $ROOTDIR/rr-artifact /mnt/root/rr-artifact
sed -i '1s/.*/root::0:0:root:\/root:\/bin\/bash/' /mnt/etc/passwd
cd; umount /mnt
