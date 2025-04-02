#include <linux/init.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/fs.h>

#define HOST_PHYSICAL_ADRS_MASK 0x7fffffffffffULL
#define ENTRY_ADRS_MASK (~(0xFFFULL))

u64 gpa2sva(u64 _cr3, u64 va);
u64 gpa2sva_set_mapping(u64 _cr3, u64 va);
u64 set_mapping(u64 _cr3, u64 va, u64 pfn);
u64 gpa2spa(u64 _cr3, u64 va);
u64 set_uc(u64 host_cr3, u64 va);
u64 set_c(u64 host_cr3, u64 va);
