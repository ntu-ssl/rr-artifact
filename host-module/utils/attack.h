#define NUM_SAMPLES 30000000

void rrfs_spectre(uint64_t adrs, uint64_t trigger_ptr, int *result);
void samples_copy_to_user_spectre_oneshot(int samples[256]);
u64 rrmb(char *adrs, char *trigger, int rounds);
void samples_copy_to_user(u64 ptr, int len);

