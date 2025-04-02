#include <stdio.h>
#include <sched.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <openssl/aes.h>

#include "../../guest-module/guest-module.h"
#include "../../guest-module/sev-guest-user.h"
#include "../../guest-utils/user-utils.h"

#define MAX_ENC_NUM (int)200000
#define MAX_KEY_NUM (int)100

unsigned char key[] =
{
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

unsigned char keys[MAX_KEY_NUM][16] = {0};

unsigned char p[MAX_ENC_NUM][16];
static int KEYID = 0;
uint64_t trigger_ptr;

unsigned char ciphertext[128];
AES_KEY key_struct;

void parse_args(int argc, char *argv[]){
        int opt;
        enum { CHARACTER_MODE, WORD_MODE, LINE_MODE } mode = CHARACTER_MODE;

        while ((opt = getopt(argc, argv, "k:")) != -1) {
            switch (opt) {
            case 'k': 
            KEYID = atoi(optarg);
            break;
            default:
                    fprintf(stderr, "Usage: %s [] [file...]\n", argv[0]);
                    exit(EXIT_FAILURE);
            }
        }
}


int main(int argc, char *argv[]){
    parse_args(argc, argv);

    // Allocate kernel page
    struct snp_guest_request_ioctl msg;
    msg.msg_version = 1;
    int fd = open("/dev/sev-guest", O_RDWR);
    ioctl(fd, SNP_ALLOC_SHARED_PAGE, &msg); 
    trigger_ptr = (uint64_t)mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    *(uint64_t*)trigger_ptr = 1;
    close(fd);

    if(mlockall(MCL_CURRENT | MCL_FUTURE) != 0){
         perror("mlockall: error");
         exit(1);
    }

    // Get the secret key from key files.
       FILE *fptr = fopen("/root/rr-artifact/aes-attack/keys/keys", "r");
    for(int i = 0; i < MAX_KEY_NUM; i++){
        for(int j = 0; j < 16; j++){
            fscanf(fptr, "%hhx", &keys[i][j]);
        }
    }
    fclose(fptr);

    // Choose the secret key to use.
    if(KEYID != -1){
        for(int i = 0; i < 16; i++){
            key[i] = keys[KEYID][i];
        }
    }

    AES_set_encrypt_key(key, 128, &key_struct);
    AES_encrypt(p[0], ciphertext, &key_struct);

    // Get GPA of the page that contains T-table arrays and store it into a file.
    FILE *fptr_addr = fopen("/root/rr-artifact/aes-attack/victim/address", "w");
    uint64_t offset_te0 = 0x1e2000;
    uint64_t offset_te1 = 0x1e2400;
    uint64_t offset_te2 = 0x1e2800;
    uint64_t offset_te3 = 0x1e2c00;
    uint64_t base = 0x7ffff7c00000;
       uint64_t va_te0 = base + offset_te0;
       uint64_t va_te1 = base + offset_te1;
       uint64_t va_te2 = base + offset_te2;
       uint64_t va_te3 = base + offset_te3;

    uint64_t gpa_te0, gpa_te1, gpa_te2, gpa_te3;
    uint64_t req;
    fd = open("/dev/guest-module", O_RDONLY);
    req = va_te0;
    ioctl(fd, GET_GPA, &req);
    gpa_te0 = req;
    fprintf(fptr_addr, "%lx\n", gpa_te0);
    req = va_te1;
    ioctl(fd, GET_GPA, &req);
    gpa_te1 = req;
    fprintf(fptr_addr, "%lx\n", gpa_te1);
    req = va_te2;
    ioctl(fd, GET_GPA, &req);
    gpa_te2 = req;
    fprintf(fptr_addr, "%lx\n", gpa_te2);
    req = va_te3;
    ioctl(fd, GET_GPA, &req);
    gpa_te3 = req;
    fprintf(fptr_addr, "%lx\n", gpa_te3);

    uint64_t trigger_gpa;
    req = trigger_ptr;
    ioctl(fd, GET_GPA, &req);
    trigger_gpa = req;
    fprintf(fptr_addr, "%lx\n", trigger_gpa);
    close(fd);

    fclose(fptr_addr);

#if NOCACHE == 1
    fd = open("/dev/guest-module", O_RDONLY);
    req = va_te0;
        ioctl(fd, MAKE_UC, &req);
        close(fd);
#endif

    // Get the pid and store it into a file.
    int pid = getpid();
       fptr = fopen("/root/rr-artifact/aes-attack/victim/pid", "w");
    fprintf(fptr, "%d", pid);
       fclose(fptr);


    // Get the plaintext files that contains plaintexts for AES encryptions.
       fptr = fopen("/root/rr-artifact/aes-attack/plaintexts/plaintexts", "r");
    for(int i = 0; i < N_attack; i++){
        for(int j = 0; j < 16; j++){
            fscanf(fptr, "%hhx", &p[i][j]);
        }
    }
    fclose(fptr);

    // We first compute the resulting ciphertexts from the encryption of each plaintext and store them into a file.
    char filename[128] = {0};
    sprintf(filename, "/root/rr-artifact/aes-attack/victim/ciphertext_%d", KEYID);
    fptr = fopen(filename, "w");
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < N_attack; j++){
            AES_encrypt(p[j], ciphertext, &key_struct);
            for(int q = 0; q < 16; q++){
                fprintf(fptr, "%02x ", ciphertext[q]);
            }
            fprintf(fptr, "\n");
        }
    }
    fclose(fptr);

    // Modify the flag file. 
    // The host machine will check if the file has been modified to know when the victim program gets ready.
    char *filepath = "/root/rr-artifact/aes-attack/victim/flag";
    fptr = fopen(filepath, "w");
    fprintf(fptr, "1");
    fclose(fptr);

    // Initial sync
    while(*(uint64_t*)trigger_ptr == VM_WAIT){
    }
    *(uint64_t*)trigger_ptr = VM_WAIT;

    int cnt = 0;
    for(;;){
        // Busy loop to wait for the attacker's notification.
        while(*(uint64_t*)trigger_ptr == VM_WAIT){
        }
        asm volatile("mfence    \n":::"memory");
        AES_encrypt(p[cnt], ciphertext, &key_struct);
        asm volatile("mfence    \n":::"memory");

        if(*(uint64_t*)trigger_ptr == TERMINATE){
            break;
        }
        
        *(uint64_t*)trigger_ptr = VM_FINISH;    
        while(*(uint64_t*)trigger_ptr == VM_FINISH){
        }
        if(*(uint64_t*)trigger_ptr != RESTART){
            // if sync succeeded, continue.
            // otherwise, run again.
            cnt++;
            cnt %= N_attack;    
        }
        *(uint64_t*)trigger_ptr = VM_WAIT;
    }
#if NOCACHE == 1
    fd = open("/dev/guest-module", O_RDONLY);
    req = va_te0;
    ioctl(fd, MAKE_C, &req);
    close(fd);
#endif
    munlockall();

    *(uint64_t*)trigger_ptr = VM_FINISH;
    return 0;
}
