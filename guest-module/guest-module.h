#include <linux/ioctl.h>
#define IOC_MAGIC 'k'
#define GET_GPA 		_IO(IOC_MAGIC,13)
#define GET_GPA_HUGE_PAGE 		_IO(IOC_MAGIC,14)
#define REMAP 		_IO(IOC_MAGIC,11)
#define RESUME 		_IO(IOC_MAGIC,12)
#define TRANSLATE 		_IO(IOC_MAGIC,1)
#define TRANSLATE2 		_IO(IOC_MAGIC,2)
#define READ_VALUE 		_IO(IOC_MAGIC,3)
#define WRITE_VALUE 		_IO(IOC_MAGIC,4)
#define CREATE_SYNC_MEM 	_IO(IOC_MAGIC,5)
#define FREE_SYNC_MEM 		_IO(IOC_MAGIC,6)
#define GHCB_MSR 		_IO(IOC_MAGIC,7)
#define MAKE_UC 		_IO(IOC_MAGIC,8)
#define MAKE_C 		_IO(IOC_MAGIC,9)
#define TLB_FLUSH 		_IO(IOC_MAGIC,10)

// The kernel_ptr_request structure contains the information needed to get the kernel pointer to the same SPA as the given GPA.
struct kernel_ptr_request{
	uint64_t gpa;
	uint64_t ptr;
};
