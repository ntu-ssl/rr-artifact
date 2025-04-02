KERNEL      := /lib/modules/$(shell uname -r)/build
KMOD_DIR    := $(shell pwd)

ifneq ($(KERNELRELEASE),)
obj-m  += hyperattacker.o
hyperattacker-y := main.o utils/translation.o utils/attack.o

else
KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD modules 
endif

clean:
	make -C $(KERNEL) M=$(KMOD_DIR) clean
