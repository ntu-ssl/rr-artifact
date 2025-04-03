# Reload+Reload: Exploiting Cache and Memory Contention Side Channel on AMD SEV

Reload+Reload attacks are hardware side-channel attacks on AMD processors that support SEV-SNP. This artifact contains the information required to reproduce the evaluation results in the paper.

## Environmental Setup

### Hardware Setup

We run experiments on a Dell EMC PowerEdge R7515 hardware with the AMD EPYC 7543P processor. The hardware uses the SEV-SNP firmware version 1.52.

For BIOS settings:
- We disable all cache prefetchers, C-state, and Turbo Boost.
- We set the Determinism Slider to Performance Determinism.
- We set Memory Interleaving to Disable.
- We enable Algorithm Performance Boost Disable (ApbDis).
- We set ApbDis fixed socket P-state to P2.

### Software Setup

This artifact is devised on Ubuntu 22.04. We used the following software to create a SEV-SNP VM.
- KVM in the Linux kernel from the [AMDESE repo](https://github.com/AMDESE/linux/tree/sev-snp-iommu-avic_5.19-rc6_v4) (branch `sev-snp-iommu-avic_5.19-rc6_v4`).
- QEMU from the [AMDESE repo](https://github.com/AMDESE/qemu) (branch `snp-v3`). 
- OVMF (OvmfPkgX64) source from the [edk2 repo](https://github.com/tianocore/edk2) (commit `8fc06b6e19e3df93cc989b4f85877d8a7783e5bf`).

SEV-SNP VM runs a Linux kernel v5.19 on Ubuntu 20.04 with the following configuration:
- a single virtual CPU (vCPU), which was pinned to a single core using `taskset`.
- 4096 main memory
- 20GB virtual disk

Please clone this repo and follow this step-by-step guide to set up the environment. We assume the cloned repo is located in `DIR`.

#### 1. Install Packages

In `DIR/rr-artifact/setup/`, install the required packages.
```
./setup.sh
```

From `DIR/rr-artifact/setup/`, generate the basic configuration.
```
./gen-config.sh
```

#### 2. Install Linux Kernel

In `DIR`, clone the Linux kernel source.
```
git clone --branch sev-snp-iommu-avic_5.19-rc6_v4 https://github.com/AMDESE/linux.git
```

In `DIR/linux`, apply the patch `DIR/rr-artifact/setup/kernel_patch.patch`.
```
patch -t -p1 -i DIR/rr-artifact/setup/kernel_patch.patch
```

Run the following commands to compile and install the kernel.
```
cp DIR/rr-artifact/setup/config .config
make
sudo make modules_install
sudo make install
sudo update-grub
```

Then, modify the grub config. If the file `/etc/default/grub.d/50-cloudimg-settings.cfg` already exists, add the following line to the file. If the file does not exist, create this
file and add the following line to it.

```
GRUB_CMDLINE_LINUX_DEFAULT="modprobe.blacklist=btrfs no5lvl transparent_hugepage=never mem_encrypt=on kvm_amd.sev=1 kpti=0 nox2apic nokaslr nosmap nosmep nmi_watchdog=0 isocpus=0,1,2,3,32,33,34,35 nohz=on nohz_full=0,1,2,3,32,33,34,35 rcu_nocbs=0,1,2,3,32,33,34,35 idle=poll"
```

Update the grub settings.
```
sudo update-grub
```

 Reboot the machine.
```
sudo reboot
```

#### 3. Install QEMU

In `DIR`, clone the QEMU source.
```
git clone --branch snp-v3 https://github.com/AMDESE/qemu.git
```

In `DIR/qemu`, install QEMU.
```
mkdir build
cd build
../configure
make
```

#### 4. Create OVMF

In `DIR`, clone the `edk2` source.
```
git clone https://github.com/tianocore/edk2.git
cd edk2
git checkout 8fc06b6e19e3df93cc989b4f85877d8a7783e5bf
```

In `DIR/edk2`, set up the environment.
```
git submodule update --init
make -C BaseTools
. edksetup.sh
```

Edit the configuration file `Conf/target.txt` as follows.
```
ACTIVE_PLATFORM = OvmfPkg/OvmfPkgX64.dsc
TARGET_ARCH = X64
TOOL_CHAIN_TAG = GCC5
```

Generate the OVMF files.
```
cd OvmfPkg
./build.sh
```

#### 5. Create a VM Image

In `DIR/rr-artifact/setup/`, run the script `vm-create.sh` to create a VM image.
```
sudo ./vm-create.sh
```

The script `vm-create.sh` generates a VM image that uses Ubuntu 20.04. Also, it compiles our customized kernel modules in `DIR/guest-module/` folder for our attacks. Moreover, it copies the entire `rr-artifact` folder into `/root/` in the VM’s file system.

#### 6. Launching a SEV-SNP VM

In `DIR/rr-artifact/setup/`, launch a SEV-SNP VM as follows.
```
./launch-and-setup-vm.exp
```

The script `launch-and-setup-vm.exp` launches a SEV-SNP VM, sets up network configuration using `dhclient`, installs the kernel modules in `/root/rr-artifact/guest-module/`, and pin the VM's vCPU.

#### 7. Set up a SEV-SNP VM

In the VM, follow the below instructions to set up the VM for testing the attack.

**a. Packages**

Install the required packages.
```
apt update
apt install gcc make -y
```

**b. Network**

Set up the network configuration.
```
dpkg-reconfigure openssh-server
```

Now copy the host’s public key to the VM's file `/root/.ssh/authorized_keys` to enable ssh connection to the VM from the host.

To test whether the Network has been set up properly, you can run `ssh -p2222 root@localhost echo hi` in the host. The output should be `hi`.

**c. OpenSSL**

Install OpenSSL in the VM. The source of OpenSSL has been included in `DIR/rr-artifact/openssl-1.1.0l/`. In the VM and in the path `DIR/rr-artifact/openssl-1.1.0l/`,
run the following commands.

```
./config -d shared no-asm no-hw
make
```

## Run

In this artifact, we present two attacks demonstrated in Section 7 in the paper: the AES attack and the Spectre attack. Before running the attacks, please make sure you have completed all the environmental setup described above.

### Install Kernel Module

The implementation of the AES attack and Spectre attack both use the host kernel
module, `hyperattacker`. You must install the module before executing the attacks. Go to the path `DIR/rr-artifact/host-module/` on the KVM host, and run the following commands:

```
make
sudo insmod hyperattacker.ko
```

### Launch a SEV-SNP VM

You must launch a SEV-SNP VM before running the attacks. Please follow the instructions in **6. Launching a SEV-SNP VM**.

> Note: You don't have to run the instructions in **7. Set up a SEV-SNP VM** again.
>
> Note: Re-launch the VM before running the attacks each time.

### AES Attack

The AES attack in this artifact recovers AES secret keys and reports the accuracy. 
 
From `DIR/rr-artifact/scripts/` on the KVM host, test the attack with caching enabled.
```
./evaluate-aes.sh
```

In our test, this will take several hours to finish. Once complete, the accuracy will be printed out.

To test the attack under the scenario where the VM disables caching for the monitored memory region, run:
```
./evaluate-aes-nocache.sh
```

### Spectre Attack

The Spectre attack in this artifact extracts a VM's secret values and reports both the accuracy and the throughput.

From `DIR/rr-artifact/scripts/` on the KVM host, test the attack using the following command:
```
./evaluate-spectre.sh
```

Once complete, the accuracy and throughput will be printed out. 

## Contact

Feel free to contact me if you have any questions: r11922213@csie.ntu.edu.tw
