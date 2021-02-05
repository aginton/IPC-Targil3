#pragma once


/* 
Found that MTA_encrypt() uses EVP_EncryptUpdate().
 According to the documentation for EVP_EncryptUpdate():
"EVP_EncryptUpdate() encrypts inl bytes from the buffer in and writes the encrypted version to out. ...
The amount of data written depends on the block alignment of the encrypted data: as a result the amount of data written may be anything 
from zero bytes to (inl + cipher_block_size - 1) so out should contain sufficient room."  - https://www.openssl.org/docs/man1.0.2/man3/EVP_EncryptUpdate.html

Because unsure what the cipher block size is, simply assuming that the encrypted pw (output of mta_encrypt()) is at most 3 times the plain_pw length. 

Same assumption used for output of MTA_decrypt()
*/



#define BUFFER_SIZE 1024

typedef enum {PARAMS_OK = 0, MISSING_PW_LEN, MISSING_NUM_DECRYPTERS, INVALID_PW_LEN_VAL, INVALID_NUM_DECRYPTERS_VAL, INVALID_TIMEOUT_VAL} PARAMS_VALIDATION_STATUS;

typedef enum {CHECK_G_DECRYPTED_PW_GUESS = 0, DONE_WAITING} ENCRYPTER_WAIT_RET_STATUS;
typedef enum {PWS_MATCH = 0, PWS_DONT_MATCH, PW_GUESS_ID_INVALID} CHECK_DECRYPTED_PW_GUESS_RET_STATUS;



// If user doesn't provide timeout argument, we use UINT_MAX as timeout value (seconds to wait).
// Converting UINT_MAX = 4294967295 seconds into years, the default waiting time for the encrypter would be 136.193 years (Assuming this is long enough time to wait)
typedef struct programParams
{
	unsigned int num_decrypters;
	unsigned int plain_pw_len;
	unsigned int key_len;
	unsigned int max_pw_duration_secs;
} ProgramParams;

typedef struct pw
{
	char* pw_data;
    unsigned int pw_data_len;
	int pw_id;
} PW;

typedef struct key
{
    char* key;
    unsigned int key_len;
} Key;

typedef struct decryptedPWGuess
{
	PW pw_guess;
	int guesser_id;
	bool guess_ready_to_be_checked;
	pthread_mutex_t mutex_decrypted_pw_guess;
	pthread_cond_t cv_guess_empty;
	pthread_cond_t cv_guess_full;
	pthread_condattr_t cv_guess_full_attr;
} DecryptedPWGuess;

typedef struct encryptedPW
{
	PW encrypted_pw;
	pthread_mutex_t mutex_encrypted_pw;
	pthread_cond_t cv_encrypted_pw_ready;
	bool encrypted_pw_ready;
} EncryptedPW;

void * encrypter_thread_main();
void* decrypter_thread_main(void* decrypter_id_ptr);

int getNumDecryptersArg(int argc, char* argv[], unsigned int* out_num_decrypters);
int getPWLenArg(int argc, char* argv[], unsigned int* out_pw_len);
int getTimeoutArg(int argc, char* argv[], unsigned int *out_to_seconds);

int parseProgramParams(int argc, char* argv[], unsigned int* out_pw_len, unsigned int* out_num_decrypters, unsigned int* out_timeout_secs);
void initPW(PW* out_pw_p, unsigned int pw_len);
void initKey(Key* out_key_p, unsigned int key_len);
void initProgramParams(ProgramParams* out_program_params);
EncryptedPW* createEncryptedPWStruct();




void createPrintablePW(PW* out_plain_pw);
char getPrintableChar();
int sendClientsEncryptedPW(char* new_encrypted_pw, unsigned int new_encrypted_pw_len, int new_encrypted_pw_id);
//ENCRYPTER_WAIT_RET_STATUS waitForGuessOrTimeout(); //should return stating whether to check guess or if timeout occurred 
CHECK_DECRYPTED_PW_GUESS_RET_STATUS checkDecryptedPWGuess(PW plain_pw, PW decrypted_pw_guess, int guesser_id);


void copyFromGlobalEncryptedPW(PW* out_pw_p);
void copyPW(PW* source_pw_p, PW* out_pw_p);
bool isPrintable(char* str, unsigned int str_len);
void waitForTurnToGuess(unsigned int id);
void setGlobalDecryptedPWGuess(char* pw_guess, unsigned int pw_guess_len, int pw_guess_id, int guessing_thr_id);


void printPWDetails(PW* pw_p);

void respondToGuessOrTimeout(int rc, PW* plain_pw_p, bool* out_create_new_pw_flag_p);
bool outputPrintablePWGuess(int id, Key* out_key_p, PW* encrypted_pw_p, char* out_decrypted_pw_guess, unsigned int* out_decrypted_pw_guess_len);