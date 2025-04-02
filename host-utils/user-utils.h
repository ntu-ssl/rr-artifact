
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include "cJSON.h"

void printProgressBar(int progress, int total, int barWidth) {
    float percentage = (float)progress / total;
    int progressBarWidth = (int)(percentage * barWidth);

    printf("[");
    for (int i = 0; i < barWidth; i++) {
        if (i < progressBarWidth) {
            putchar('=');
        } else {
            putchar(' ');
        }
    }
    printf("] %.2f%%", percentage * 100);
    printf("\r");
}

int get_data_from_json(char *ptr){
	FILE* file = fopen("../config.json", "r");
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

	cJSON* value = cJSON_GetObjectItemCaseSensitive(root, "root-directory");
	if (cJSON_IsString(value) && (value->valuestring != NULL)) {
		strcpy(ptr, value->valuestring);
	}

	cJSON_Delete(root);
	free(json_data);

	return 0;
}

/*
 * sync utils
 */
#define VM_WAIT (int)1
#define HYPERVISOR_TRIGGER (int)0
#define VM_FINISH (int)4
#define RESTART (int)3
#define NEXT (int)5
#define TERMINATE (int)2

uint64_t sync_read(int fd, uint64_t adrs){
	uint64_t req = adrs;
	ioctl(fd, READ_VALUE, (uint64_t)&req);
	return req;
}

void sync_write(int fd, uint64_t adrs, uint64_t var){
	struct write_var_request req;
	req.adrs = adrs;
	req.var = var;
	ioctl(fd, WRITE_VALUE, (uint64_t)&req);
}



