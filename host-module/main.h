#include <linux/ioctl.h>
#define IOC_MAGIC 'k'
#define TRANSLATE 				_IO(IOC_MAGIC,1)
#define ATTACK_WITH_TRIGGER 			_IO(IOC_MAGIC,3)
#define MONITOR_SPECTRE 			_IO(IOC_MAGIC,202)
#define SPECTRE_GET_SECRET 			_IO(IOC_MAGIC,204)
#define SAMPLES_COPY_TO_USER_SPECTRE_ONESHOT 			_IO(IOC_MAGIC,201)
#define GET_KERNEL_PTR				_IO(IOC_MAGIC,37)
#define GET_KERNEL_PTR_SNP				_IO(IOC_MAGIC,40)
#define RESUME_STAND_VA				_IO(IOC_MAGIC,41) // TODO: Do we need this?
#define SAMPLES_COPY_TO_USER 			_IO(IOC_MAGIC,15)
#define WRITE_VALUE 				_IO(IOC_MAGIC,10)
#define READ_VALUE 				_IO(IOC_MAGIC,11)
#define GET_SPA_WITH_GPA_NCR3			_IO(IOC_MAGIC,30)
#define SET_UC					_IO(IOC_MAGIC,33)
#define SET_C					_IO(IOC_MAGIC,95)
#define GADGET 				_IO(IOC_MAGIC,17)
#define FLUSH					_IO(IOC_MAGIC,28)
#define GET_KERNEL_PTR_SPECTRE_SNP _IO(IOC_MAGIC,203)


// The translate_request structure contains the information (ncr3, GPA) needed to translate GPA to SPA.
struct translate_request{
	uint64_t ncr3;
	uint64_t gpa;
	uint64_t spa;
};

// The attack_request structure contains the information needed to perform the attack.
struct attack_request{
	uint64_t addr;		// the address to be monitored
	uint64_t trigger; 	// the address for synchronization
	uint64_t number;	// the number of loads
	int ret;		// return value
	uint64_t l3misscnt;		// the count of L3 misses
};

// The sample_request structure contains the information needed to copy the samples from kernel to user.
struct sample_request{
	uint64_t addr;		// the base address to store the samples
	uint64_t number;	// the number of samples
};

// The kernel_ptr_request structure contains the information needed to get the kernel pointer to the same SPA as the given GPA.
struct kernel_ptr_request{
	uint64_t gpa;
	uint64_t ptr;
	uint64_t SYNC;
};

struct kernel_ptr_spectre_request{
	uint64_t gpa;
	uint64_t ptr;
};

struct write_var_request{
	uint64_t adrs;
	uint64_t var;
};

struct attack_request_spectre_oneshot{
	char *adrs[256];
};

struct attack_request_monitor_spectre{
	uint64_t adrs;
    uint64_t trigger_ptr;
	int count;
	int result;
};

struct gadget_request{
	uint64_t addr;
	uint64_t latency;
};
