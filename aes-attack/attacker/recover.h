#include "aes-analysis.h"

#define MAX_ENC_NUM (int)200000

int bot_elems(double *arr, int N, int *bot, int n) {
  int bot_count = 0;
  int i;
  for (i=0;i<N;++i) {
    int k;
    for (k=bot_count;k>0 && arr[i]>arr[bot[k-1]];k--);
    if (k>=n) continue;
    int j=bot_count;
    if (j>n-1) {
      j=n-1;
    } else {
      bot_count++;
    }
    for (;j>k;j--) {
      bot[j]=bot[j-1];
    }
    bot[k] = i;
  }
  return bot_count;
}

uint32_t subWord(uint32_t word) {
  uint32_t retval = 0;

  uint8_t t1 = sbox[(word >> 24) & 0x000000ff];
  uint8_t t2 = sbox[(word >> 16) & 0x000000ff];
  uint8_t t3 = sbox[(word >> 8 ) & 0x000000ff];
  uint8_t t4 = sbox[(word      ) & 0x000000ff];

  retval = (t1 << 24) ^ (t2 << 16) ^ (t3 << 8) ^ t4;

  return retval;
}

int accessed[16][256] = {0};
int bins[16][MAX_ENC_NUM][2] = {0};
uint8_t ciphertexts[MAX_ENC_NUM][16] = {0};
unsigned char ciphertext[128];
int is_access_m[4][MAX_ENC_NUM];
int subbins[256][MAX_ENC_NUM] = {0};
int subbins_length[256] = {0};

void recover_key(int N_attack){
	char filename[256] = {0};
	sprintf(filename, "./ciphertexts/ciphertext");
	FILE *ciphertext_fptr = fopen(filename, "r");
	for(int i = 0; i < N_attack; i++){
		for(int j = 0; j < 16; j++){
			fscanf(ciphertext_fptr, "%02hhx", &ciphertexts[i][j]);
		}
	}

	uint8_t subkey[16] = {0};
	// Recover each subkey byte.
	for(int i = 0; i < 16; i++){
		for(int j = 0; j < 256; j++){
			subbins_length[j] = 0;
		}
		for(int j = 0; j < N_attack; j++){
			bins[i][j][0] = ciphertexts[j][i];
			bins[i][j][1] = j;
		}
		int used_T_table = ((i % 4) + 2) % 4;
		
		for(int j = 0; j < N_attack; j++){
			int ciphertext_byte_value = bins[i][j][0];
			int ciphertext_id = bins[i][j][1];
			subbins[ciphertext_byte_value][subbins_length[ciphertext_byte_value]] = ciphertext_id;
			subbins_length[ciphertext_byte_value]++;
		}
		double accessedRatio[256] = {0};
		for(int j = 0; j < 256; j++){
			for(int k = 0; k < subbins_length[j]; k++){
				if(is_access_m[used_T_table][subbins[j][k]] == 1){
					accessedRatio[j]++;
				}
			}
			accessedRatio[j] /= subbins_length[j];
		}
  		int botIndices[16];
    	bot_elems(accessedRatio, 256, botIndices, 16);

  		int countKeyCandidates[256] = {0};
    	for(int j = 0; j < 16; j++){
      		countKeyCandidates[botIndices[j] ^ 99]++;
      		countKeyCandidates[botIndices[j] ^ 124]++;
      		countKeyCandidates[botIndices[j] ^ 119]++;
      		countKeyCandidates[botIndices[j] ^ 123]++;
      		countKeyCandidates[botIndices[j] ^ 242]++;
      		countKeyCandidates[botIndices[j] ^ 107]++;
      		countKeyCandidates[botIndices[j] ^ 111]++;
      		countKeyCandidates[botIndices[j] ^ 197]++;
      		countKeyCandidates[botIndices[j] ^ 48]++;
      		countKeyCandidates[botIndices[j] ^ 1]++;
      		countKeyCandidates[botIndices[j] ^ 103]++;
      		countKeyCandidates[botIndices[j] ^ 43]++;
      		countKeyCandidates[botIndices[j] ^ 254]++;
      		countKeyCandidates[botIndices[j] ^ 215]++;
      		countKeyCandidates[botIndices[j] ^ 171]++;
      		countKeyCandidates[botIndices[j] ^ 118]++;
    	}
    	int maxValue = 0;
    	int maxIndex;
   		for(int j = 0; j < 256; j++){
      		if(countKeyCandidates[j] > maxValue){
        		maxValue = countKeyCandidates[j];
        		maxIndex = j;
      		}
    	}
		subkey[i] = maxIndex;
	}
  uint32_t roundWords[4];
  roundWords[3] = (((uint32_t) subkey[12]) << 24) ^
                  (((uint32_t) subkey[13]) << 16) ^
                  (((uint32_t) subkey[14]) << 8 ) ^
                  (((uint32_t) subkey[15])      );

  roundWords[2] = (((uint32_t) subkey[8] ) << 24) ^
                  (((uint32_t) subkey[9] ) << 16) ^
                  (((uint32_t) subkey[10]) << 8 ) ^
                  (((uint32_t) subkey[11])      );

  roundWords[1] = (((uint32_t) subkey[4] ) << 24) ^
                  (((uint32_t) subkey[5] ) << 16) ^
                  (((uint32_t) subkey[6] ) << 8 ) ^
                  (((uint32_t) subkey[7] )      );

  roundWords[0] = (((uint32_t) subkey[0] ) << 24) ^
                  (((uint32_t) subkey[1] ) << 16) ^
                  (((uint32_t) subkey[2] ) << 8 ) ^
                  (((uint32_t) subkey[3] )      );

  uint32_t tempWord4, tempWord3, tempWord2, tempWord1;
  uint32_t rcon[10] = {0x36000000, 0x1b000000, 0x80000000, 0x40000000,
                       0x20000000, 0x10000000, 0x08000000, 0x04000000,
                       0x02000000, 0x01000000 };
  // loop to backtrack aes key expansion
  for (int i=0; i<10; i++) {
    tempWord4 = roundWords[3] ^ roundWords[2];
    tempWord3 = roundWords[2] ^ roundWords[1];
    tempWord2 = roundWords[1] ^ roundWords[0];

    uint32_t rotWord = (tempWord4 << 8) ^ (tempWord4 >> 24);

    tempWord1 = (roundWords[0] ^ rcon[i] ^ subWord(rotWord));

    roundWords[3] = tempWord4;
    roundWords[2] = tempWord3;
    roundWords[1] = tempWord2;
    roundWords[0] = tempWord1;
  }

  FILE *key_fptr = fopen("./keys/recovered_keys", "a");
  printf("secret key: ");
  for(int i = 0; i < 4; i++) {
    fprintf(key_fptr, "%02x ", (roundWords[i] >> 24) & 0xff);
    fprintf(key_fptr, "%02x ", (roundWords[i] >> 16) & 0xff);
    fprintf(key_fptr, "%02x ", (roundWords[i] >> 8) & 0xff);
    fprintf(key_fptr, "%02x ", (roundWords[i] >> 0) & 0xff);
    printf("%x ", roundWords[i]);
  }
  fprintf(key_fptr, "\n");
  fclose(key_fptr);
  printf("\n");
	
	
}

