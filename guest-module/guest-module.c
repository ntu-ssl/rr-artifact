#include <linux/init.h>
#include <asm/tlbflush.h>
#include <asm/set_memory.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <asm/sev.h>
#include "guest-module.h"

#define MAX_DEV 1
#define MAXDATALEN 4096

#define GUEST_PHYSICAL_ADRS_MASK 0x7fffffffffffULL
#define ENTRY_ADRS_MASK (~(0xFFFULL))

void make_cacheable(u64 cr3, u64 va){
	cr3 = cr3 & GUEST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
    u64 p4d_offset = (va >> 39) & 0x1ff;
    u64 pmd_offset = (va >> 30) & 0x1ff;
  	u64 pgd_offset = (va >> 21) & 0x1ff;
   	u64 pte_offset = (va >> 12) & 0x1ff;
	u64 *entry_va;
	u64 entry;
    entry_va = (u64*)__va(cr3 + p4d_offset * 8);
	entry = *entry_va;
	entry = entry & GUEST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;

    entry_va = (u64*)__va(entry + pmd_offset * 8);
	entry = *entry_va;
	entry = entry & GUEST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;

    entry_va = (u64*)__va(entry + pgd_offset * 8);
	entry = *entry_va;
	entry = entry & GUEST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;

    entry_va = (u64*)__va(entry + pte_offset * 8);
	entry = *entry_va;
	*entry_va = entry & (~(1ULL << 4));
	entry = entry & GUEST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
	for(int i = 0; i < 64; i++){
		asm volatile (
			"clflush (%%rbx) 	\n"
			"mfence				\n"
			::"b"(__va(entry + i * 64)):
		);
	}
}


void make_uncacheable(u64 cr3, u64 va){
	cr3 = cr3 & GUEST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
    u64 p4d_offset = (va >> 39) & 0x1ff;
    u64 pmd_offset = (va >> 30) & 0x1ff;
  	u64 pgd_offset = (va >> 21) & 0x1ff;
   	u64 pte_offset = (va >> 12) & 0x1ff;
	u64 *entry_va;
	u64 entry;
    entry_va = (u64*)__va(cr3 + p4d_offset * 8);
	entry = *entry_va;
	entry = entry & GUEST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;

    entry_va = (u64*)__va(entry + pmd_offset * 8);
	entry = *entry_va;
	entry = entry & GUEST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;

    entry_va = (u64*)__va(entry + pgd_offset * 8);
	entry = *entry_va;
	entry = entry & GUEST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;

    entry_va = (u64*)__va(entry + pte_offset * 8);
	entry = *entry_va;
	*entry_va = entry | (1ULL << 4);
	entry = entry & GUEST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
	for(int i = 0; i < 64; i++){
		asm volatile (
			"clflush (%%rbx) 	\n"
			"mfence				\n"
			::"b"(__va(entry + i * 64)):
		);
	}
}


u64 get_gpa(u64 cr3, u64 va){
	cr3 = cr3 & GUEST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
    u64 p4d_offset = (va >> 39) & 0x1ff;
    u64 pmd_offset = (va >> 30) & 0x1ff;
  	u64 pgd_offset = (va >> 21) & 0x1ff;
   	u64 pte_offset = (va >> 12) & 0x1ff;
   	u64 page_offset = va & 0xfff;
	u64 *entry_va;
	u64 entry;
    entry_va = (u64*)__va(cr3 + p4d_offset * 8);
	entry = *entry_va;
	entry = entry & GUEST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;

    entry_va = (u64*)__va(entry + pmd_offset * 8);
	entry = *entry_va;
	entry = entry & GUEST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;

    entry_va = (u64*)__va(entry + pgd_offset * 8);
	entry = *entry_va;
	entry = entry & GUEST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;

    entry_va = (u64*)__va(entry + pte_offset * 8);
	entry = *entry_va;
	entry = entry & GUEST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
	return entry + page_offset;
}

u64 get_gpa_huge_page(u64 cr3, u64 va){
	cr3 = cr3 & GUEST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;
    u64 p4d_offset = (va >> 39) & 0x1ff;
    u64 pmd_offset = (va >> 30) & 0x1ff;
  	u64 pgd_offset = (va >> 21) & 0x1ff;
   	u64 page_offset = va & 0x1fffff;
	u64 *entry_va;
	u64 entry;
    entry_va = (u64*)__va(cr3 + p4d_offset * 8);
	entry = *entry_va;
	entry = entry & GUEST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;

    entry_va = (u64*)__va(entry + pmd_offset * 8);
	entry = *entry_va;
	entry = entry & GUEST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;

    entry_va = (u64*)__va(entry + pgd_offset * 8);
	entry = *entry_va;
	entry = entry & GUEST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK;

	return entry + page_offset;
}

static int mychardev_open(struct inode *inode, struct file *file);
static int mychardev_release(struct inode *inode, struct file *file);
static long mychardev_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

static const struct file_operations mychardev_fops = {
    .owner      = THIS_MODULE,
    .open       = mychardev_open,
    .release    = mychardev_release,
    .unlocked_ioctl = mychardev_ioctl,
};

struct mychar_device_data {
    struct cdev cdev;
};

static int dev_major = 0;
static struct class *mychardev_class = NULL;
static struct mychar_device_data mychardev_data;

static int mychardev_uevent(struct device *dev, struct kobj_uevent_env *env)
{
    add_uevent_var(env, "DEVMODE=%#o", 0666);
    return 0;
}

static int __init mychardev_init(void)
{
	dev_t dev;
	if(alloc_chrdev_region(&dev, 0, 1, "guest-module") != 0){
		printk("alloc_chrdev_region failed.\n");
		return -EFAULT;
	}
	dev_major = MAJOR(dev);
	printk("guest-module's major: %d\n", dev_major);
	mychardev_class = class_create(THIS_MODULE, "guest-module");
	mychardev_class->dev_uevent = (void*)mychardev_uevent;

    cdev_init(&mychardev_data.cdev, &mychardev_fops);
    mychardev_data.cdev.owner = THIS_MODULE;

    cdev_add(&mychardev_data.cdev, MKDEV(dev_major, 0), 1);

    device_create(mychardev_class, NULL, MKDEV(dev_major, 0), NULL, "guest-module");

	return 0;
}

static void __exit mychardev_exit(void)
{
        device_destroy(mychardev_class, MKDEV(dev_major, 0));

    	class_unregister(mychardev_class);
    	class_destroy(mychardev_class);

    	unregister_chrdev_region(MKDEV(dev_major, 0), MINORMASK);
}

static int mychardev_open(struct inode *inode, struct file *file)
{
    return 0;
}

static int mychardev_release(struct inode *inode, struct file *file)
{
    return 0;
}

static long mychardev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    switch(cmd){
	case GET_GPA :{
    	u64 req;
		u64 cr3;
    	if (copy_from_user(&req, (void*)arg, sizeof(req))) {
       		return -EFAULT;
   		}
		asm volatile ("movq %%cr3, %%rbx \n":"=b"(cr3)::);
		req = get_gpa(cr3, req);
		__flush_tlb_all();
    	if (copy_to_user((void*)arg, &req, sizeof(req))) {
       		return -EFAULT;
   		}
		break;
	}
	case GET_GPA_HUGE_PAGE :{
    	u64 req;
		u64 cr3;
    	if (copy_from_user(&req, (void*)arg, sizeof(req))) {
       		return -EFAULT;
   		}
		asm volatile ("movq %%cr3, %%rbx \n":"=b"(cr3)::);
		req = get_gpa_huge_page(cr3, req);
		__flush_tlb_all();
    	if (copy_to_user((void*)arg, &req, sizeof(req))) {
       		return -EFAULT;
   		}
		break;
	}
	case MAKE_UC :{
    	u64 req;
		u64 cr3;
    	if (copy_from_user(&req, (void*)arg, sizeof(req))) {
       		return -EFAULT;
   		}
		asm volatile ("movq %%cr3, %%rbx \n":"=b"(cr3)::);
		make_uncacheable(cr3, req);
		__flush_tlb_all();
		break;
	}
	case MAKE_C :{
    	u64 req;
		u64 cr3;
    	if (copy_from_user(&req, (void*)arg, sizeof(req))) {
       		return -EFAULT;
   		}
		asm volatile ("movq %%cr3, %%rbx \n":"=b"(cr3)::);
		make_cacheable(cr3, req);
		__flush_tlb_all();
		break;
	}
    }
    return 0;
}


MODULE_LICENSE("GPL");

module_init(mychardev_init);
module_exit(mychardev_exit);
