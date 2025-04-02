#!/bin/bash
json=$(cat ../config.json)
ROOTDIR=$(echo "$json" | jq -r '."parent-directory"')
CORE=$(echo "$json" | jq -r '."cores"')
CMDLINE=""
CONSOLE="1234"
UEFI_BIOS_CODE="$ROOTDIR/edk2/Build/OvmfX64/DEBUG_GCC5/FV/OVMF_CODE.fd"
UEFI_BIOS_VARS="$ROOTDIR/edk2/Build/OvmfX64/DEBUG_GCC5/FV/OVMF_VARS.fd"
KERNEL="$ROOTDIR/linux/arch/x86_64/boot/bzImage"
IMAGE="$ROOTDIR/cloud.img"
QEMU="$ROOTDIR/qemu/build/qemu-system-x86_64"
TRACE=""
QMP="1235"
MEM="4096"
SMP="1"
RESUME=""
NET=""
MACHINE="-enable-kvm -cpu EPYC-v4 -machine q35"
MACHINE="$MACHINE -machine memory-encryption=sev0,vmport=off"

get_cbitpos() {
	modprobe cpuid
	#
	# Get C-bit position directly from the hardware
	#   Reads of /dev/cpu/x/cpuid have to be 16 bytes in size
	#     and the seek position represents the CPUID function
	#     to read.
	#   The skip parameter of DD skips ibs-sized blocks, so
	#     can't directly go to 0x8000001f function (since it
	#     is not a multiple of 16). So just start at 0x80000000
	#     function and read 32 functions to get to 0x8000001f
	#   To get to EBX, which contains the C-bit position, skip
	#     the first 4 bytes (EAX) and then convert 4 bytes.
	#

	EBX=$(dd if=/dev/cpu/0/cpuid ibs=16 count=32 skip=134217728 | tail -c 16 | od -An -t u4 -j 4 -N 4 | sed -re 's|^ *||')
	CBITPOS=$((EBX & 0x3f))
}

get_cbitpos

SEV="-object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1"

while :
do
    case "$1" in
        --nat )
            NET="-netdev user,id=net0,hostfwd=tcp::2222-:22"
            NET="$NET -device virtio-net-pci,netdev=net0"
            shift 1
            ;;
        -k | --kernel )
            KERNEL="$2"
            shift 2
            ;;
        -q | --qemu )
            QEMU="$2"
            shift 2
            ;;
        -c | --console )
            CONSOLE="$2"
            shift 2
            ;;
        -i | --image )
            IMAGE="$2"
            shift 2
            ;;
        -m | --mem )
            MEM="$2"
            shift 2
            ;;
        -s | --smp )
            SMP="$2"
            shift 2
            ;;
        --qmp )
            QMP="$2"
            shift 2
            ;;
        --bios-code )
            UEFI_BIOS_CODE="$2"
            shift 2
            ;;
        --bios-vars )
            UEFI_BIOS_VARS="$2"
            shift 2
            ;;
        -r | --resume )
            RESUME="-incoming tcp:0:$2"
            shift 2
            ;;
        -t | --trace )
            TRACE="--trace events=$2,file=$3"
            shift 3
            ;;
        --)
            shift
            break
            ;;
        -* | --* )
            echo "WTF"
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

echo "Mapping CTRL-C to CTRL-]"
stty intr ^]

sudo taskset -c 2-3,34-35 nice -n -20 $QEMU \
	-object iothread,id=iothread1 \
    -kernel $KERNEL \
    -nographic \
    -append "console=ttyS0 nokaslr root=/dev/vda rw $CMDLINE" \
    -drive if=none,file=$IMAGE,id=vda,cache=none,format=raw \
    -device virtio-blk-pci,drive=vda,iothread=iothread1,write-cache=on \
    $NET \
    -m $MEM \
    -smp $SMP \
    -monitor telnet:localhost:$CONSOLE,server,nowait \
    -qmp tcp:localhost:$QMP,server=on,wait=off \
    -drive if=pflash,format=raw,unit=0,file=$UEFI_BIOS_CODE,readonly=on \
    -drive if=pflash,format=raw,unit=1,file=$UEFI_BIOS_VARS \
    $SEV \
    $MACHINE \
    $TRACE \
    $RESUME 

stty intr ^c
