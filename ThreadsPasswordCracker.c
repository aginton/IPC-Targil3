#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <mqueue.h>
//debug:
#include <stdarg.h>

//#include <sys/time.h>     /* struct timeval definition           */
#include <unistd.h> /* declaration of gettimeofday()       */
#include "mta_crypt.h"
#include "mta_rand.h"
#include "ThreadsPasswordCracker.h"
#include "datastructs.h"
#include "utils.h"

//#define PRINT_8_BYTE_BUFFER(name, buffer) printf(name " buffer=%d %d %d %d %d %d %d %d \n", buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7])
//#define PRINT_8_BYTE_BUFFER_W_ID_AND_ITER(name, id, iter, buffer) printf("(Decrypter id=%d), iter=%d," name " buffer=%d %d %d %d %d %d %d %d \n", id, iter, buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7])

ProgramParams g_program_params = {0};
EncryptedPW *g_encrypted_pw_p = NULL;
DecryptedPWGuess *g_decrypted_pw_guess_p = NULL;

void timed_print(clock_t timestamp, const char *fmt, ...) 
{
    printf("%ld  ", timestamp);

    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}



// ENCRYPTER_WAIT_RET_STATUS waitForGuessOrTimeout()
// {
//     struct timespec timeout; /* timeout value for the wait function */
//     int rc = 0;
//     clock_gettime(CLOCK_MONOTONIC, &timeout);
//     timeout.tv_sec += g_program_params.max_pw_duration_secs;

//     while (!g_decrypted_pw_guess_p->guess_ready_to_be_checked && (rc != ETIMEDOUT))
//     {
//         rc = pthread_cond_timedwait(&g_decrypted_pw_guess_p->cv_guess_full, &g_decrypted_pw_guess_p->mutex_decrypted_pw_guess, &timeout);
//     }

//     if (rc == ETIMEDOUT)
//     {
//         return DONE_WAITING;
//     }
//     else
//     {
//         return CHECK_G_DECRYPTED_PW_GUESS;
//     }
// }

void respondToGuessOrTimeout(int rc, PW *plain_pw_p, bool *out_create_new_pw_flag_p)
{
    *out_create_new_pw_flag_p = false;
    // if signaled, check guess. If guess is correct or timeout, create new pw+key
    if (rc == CHECK_G_DECRYPTED_PW_GUESS)
    {
        if (PWS_MATCH == checkDecryptedPWGuess(*plain_pw_p, g_decrypted_pw_guess_p->pw_guess, g_decrypted_pw_guess_p->guesser_id))
        {
            *out_create_new_pw_flag_p = true;
        }
    }
    else if (rc == DONE_WAITING)
    {
        printf("[Encrypter]:   \t\tTimeout (%u secs) occurred! Creating new password and key.\n", g_program_params.max_pw_duration_secs);
        *out_create_new_pw_flag_p = true;
    }
    g_decrypted_pw_guess_p->guess_ready_to_be_checked = false;
}




void createPrintablePW(PW *out_plain_pw)
{
    for (int i = 0; i < out_plain_pw->pw_data_len; i++)
    {
        out_plain_pw->pw_data[i] = getPrintableChar();
    }
}

char getPrintableChar()
{
    char res = 0;

    do
    {
        res = MTA_get_rand_char();
    } while (!isprint(res));

    return res;
}

CHECK_DECRYPTED_PW_GUESS_RET_STATUS checkDecryptedPWGuess(PW plain_pw, PW decrypted_pw_guess, int guesser_id)
{
    if (decrypted_pw_guess.pw_id != plain_pw.pw_id)
    {
        printf("[Encrypter]:   \t\tDecrypter Thread #%d incorrectly used id #%d. Should be using id #%d.\n",
               guesser_id, decrypted_pw_guess.pw_id, plain_pw.pw_id);
        return PW_GUESS_ID_INVALID;
    }
    if (strcmp(decrypted_pw_guess.pw_data, plain_pw.pw_data) != 0)
    {
        return PWS_DONT_MATCH;
    }

    //passwords match!
    printf("[Encrypter]:   \t\tDecrypter Thread #%d successfully decrypted password %s!\n", guesser_id, plain_pw.pw_data);
    return PWS_MATCH;
}

void *decrypter_thread_main(void *decrypter_id_ptr)
{
    int my_id = *((int *)decrypter_id_ptr);

    Key key;
    initKey(&key, g_program_params.key_len);

    PW encrypted_pw;
    initPW(&encrypted_pw, g_program_params.plain_pw_len);

    char decrypted_pw_guess[BUFFER_SIZE];
    unsigned int decrypted_pw_guess_len = 0;

    pthread_mutex_lock(&g_encrypted_pw_p->mutex_encrypted_pw);
    while (!g_encrypted_pw_p->encrypted_pw_ready)
    {
        pthread_cond_wait(&g_encrypted_pw_p->cv_encrypted_pw_ready, &g_encrypted_pw_p->mutex_encrypted_pw);
    }
    pthread_mutex_unlock(&g_encrypted_pw_p->mutex_encrypted_pw);
    
    while (true)
    {
        copyFromGlobalEncryptedPW(&encrypted_pw);

        //try to decrypt local encrypted_pw to printable pw
        if (!outputPrintablePWGuess(my_id, &key, &encrypted_pw, decrypted_pw_guess, &decrypted_pw_guess_len))
        {
            // Password changed while generating a printable password.
            continue;
        }

        // wait for chance to write decrypted_pw_guess onto g_decrypted_pw_guess
        pthread_mutex_lock(&g_decrypted_pw_guess_p->mutex_decrypted_pw_guess);
        waitForTurnToGuess(my_id);

        if (encrypted_pw.pw_id == g_encrypted_pw_p->encrypted_pw.pw_id)
        {
            setGlobalDecryptedPWGuess(decrypted_pw_guess, decrypted_pw_guess_len, encrypted_pw.pw_id, my_id);
            pthread_mutex_unlock(&g_decrypted_pw_guess_p->mutex_decrypted_pw_guess);
            pthread_cond_signal(&g_decrypted_pw_guess_p->cv_guess_full);
        }
        else
        {
            pthread_mutex_unlock(&g_decrypted_pw_guess_p->mutex_decrypted_pw_guess);
        }
    }
}

bool outputPrintablePWGuess(int id, Key *out_key_p, PW *encrypted_pw_p, char *out_decrypted_pw_guess, unsigned int *out_decrypted_pw_guess_len)
{
    unsigned long long iteration = 0;

    do
    {
        // Check if global encrypted password changed while generating a printable guess.
        // This check doesn't require locking g_encrypted_pw_p because reading a boolean field is an atomic operation (a single mov instruction).
        if (encrypted_pw_p->pw_id != g_encrypted_pw_p->encrypted_pw.pw_id)
        {
            printf("[Decrypter #%d]:\t\tStopped generating keys after %llu iterations because password changed.\n", id, iteration);
            return false;
        }

        //create random key and copy g_encrypted_pw into local variable encrypted_pw
        iteration++;
        ASSERT(encrypted_pw_p->pw_data_len != 0, "Cannot have zero-length encrypted password!");
        MTA_get_rand_data(out_key_p->key, out_key_p->key_len);
        ASSERT((out_key_p->key_len) > 0, "Cannot have a zero-length key.");
        MTA_decrypt(out_key_p->key, out_key_p->key_len, encrypted_pw_p->pw_data, encrypted_pw_p->pw_data_len, out_decrypted_pw_guess, out_decrypted_pw_guess_len);
        out_decrypted_pw_guess[*out_decrypted_pw_guess_len] = '\0';

    } while (!isPrintable(out_decrypted_pw_guess, *out_decrypted_pw_guess_len));

    printf("[Decrypter #%d]:\t\tFound printable decrypted password %s after %llu iterations. Password id: %d\n", id, out_decrypted_pw_guess, iteration, encrypted_pw_p->pw_id);

    return true;
}

void waitForTurnToGuess(unsigned int id)
{
    while (g_decrypted_pw_guess_p->guess_ready_to_be_checked)
    {
        pthread_cond_wait(&g_decrypted_pw_guess_p->cv_guess_empty, &g_decrypted_pw_guess_p->mutex_decrypted_pw_guess);
    }
}

void setGlobalDecryptedPWGuess(char *pw_guess, unsigned int pw_guess_len, int pw_guess_id, int guessing_thr_id)
{
    g_decrypted_pw_guess_p->pw_guess.pw_data_len = pw_guess_len;
    memcpy(g_decrypted_pw_guess_p->pw_guess.pw_data, pw_guess, pw_guess_len);
    g_decrypted_pw_guess_p->pw_guess.pw_id = pw_guess_id;
    g_decrypted_pw_guess_p->guesser_id = guessing_thr_id;
    g_decrypted_pw_guess_p->guess_ready_to_be_checked = true;
}

void copyFromGlobalEncryptedPW(PW *out_pw_p)
{
    pthread_mutex_lock(&g_encrypted_pw_p->mutex_encrypted_pw);
    copyPW(&g_encrypted_pw_p->encrypted_pw, out_pw_p);
    pthread_mutex_unlock(&g_encrypted_pw_p->mutex_encrypted_pw);
}

void copyPW(PW *source_pw_p, PW *dest_pw_p)
{
    ASSERT(dest_pw_p != NULL, "dest_pw_p cannot be NULL!");
    ASSERT(source_pw_p != NULL, "source_pw_p cannot be NULL!");
    dest_pw_p->pw_id = source_pw_p->pw_id;
    dest_pw_p->pw_data_len = source_pw_p->pw_data_len;
    memcpy(dest_pw_p->pw_data, source_pw_p->pw_data, source_pw_p->pw_data_len);
}

int parseProgramParams(int argc, char *argv[], unsigned int *out_pw_len, unsigned int *out_num_decrypters, unsigned int *out_timeout_secs)
{
    if (getNumDecryptersArg(argc, argv, out_num_decrypters))
    {
        return EXIT_FAILURE;
    }

    if (getPWLenArg(argc, argv, out_pw_len))
    {
        return EXIT_FAILURE;
    }

    g_program_params.key_len = g_program_params.plain_pw_len / 8;

    if (getTimeoutArg(argc, argv, out_timeout_secs))
    {
        return EXIT_FAILURE;
    }

    return PARAMS_OK;
}

bool isPrintable(char *str, unsigned int str_len)
{
    for (int i = 0; i < str_len; ++i)
    {
        if (!isprint(str[i]))
        {
            return false;
        }
    }
    return true;
}

int getNumDecryptersArg(int argc, char *argv[], unsigned int *out_num_decrypters)
{
    for (int parameter_num = 1; parameter_num < argc; parameter_num += 2)
    {
        if (0 == strcmp(argv[parameter_num], "-n") || 0 == strcmp(argv[parameter_num], "--num-of-decrypters"))
        {
            int num_of_decrypters = atoi(argv[parameter_num + 1]);
            if (num_of_decrypters > 0)
            {
                //success
                printf("Setting number of decrypters to %d.\n", num_of_decrypters);
                *out_num_decrypters = num_of_decrypters;
                return 0;
            }
            else
            {
                printf("Error: Invalid argument value for number of decrypters\n");
                //invalid argument value for num-of-decrypters
                return INVALID_NUM_DECRYPTERS_VAL;
            }
        }
    }

    //missing argument num-of-decrypters
    printf("Error: Missing argument for number decrypters\n");
    return MISSING_NUM_DECRYPTERS;
}

int getPWLenArg(int argc, char *argv[], unsigned int *out_pw_len)
{
    for (int parameter_num = 1; parameter_num < argc; parameter_num += 2)
    {
        if (0 == strcmp(argv[parameter_num], "-l") || 0 == strcmp(argv[parameter_num], "--password-length"))
        {
            unsigned int password_length = atoi(argv[parameter_num + 1]);
            if (password_length > 0 && (password_length % 8) == 0)
            {
                //success
                printf("Setting password length to %d.\n", password_length);
                *out_pw_len = password_length;
                return 0;
            }
            else
            {
                //invalid argument value for password-length
                printf("Error: Invalid argument value for password length. Must be positive multiple of 8.\n");
                return INVALID_PW_LEN_VAL;
            }
        }
    }

    //missing argument password-length
    printf("Error: Missing argument for password length\n");
    return MISSING_PW_LEN;
}

int getTimeoutArg(int argc, char *argv[], unsigned int *out_to_seconds)
{
    for (int parameter_num = 1; parameter_num < argc; parameter_num += 2)
    {
        if (0 == strcmp(argv[parameter_num], "-t") || 0 == strcmp(argv[parameter_num], "--timeout"))
        {
            int to_secs = atoi(argv[parameter_num + 1]);
            if (to_secs > 0)
            {
                //success
                printf("Setting timeout to %d seconds.\n", to_secs);
                *out_to_seconds = to_secs;
                return 0;
            }
            else
            {
                //invalid argument value for timeout
                printf("Error: Invalid argument value for timeout.\n");
                return INVALID_TIMEOUT_VAL;
            }
        }
    }

    return 0;
}

void initProgramParams(ProgramParams *out_program_params)
{
    ASSERT(NULL != out_program_params, "initProgramParams was passed in a NULL argument");
    out_program_params->key_len = 0;
    out_program_params->num_decrypters = 0;
    out_program_params->plain_pw_len = 0;
    out_program_params->max_pw_duration_secs = UINT_MAX;
}


void printProgramParams()
{
    printf("g_program_params.plain_pw_len = %u.\n", g_program_params.plain_pw_len);
    printf("g_program_params.key_len = %u.\n", g_program_params.key_len);
    printf("g_program_params.num_decrypters = %u.\n", g_program_params.num_decrypters);
    printf("g_program_params.max_pw_duration_secs = %u.\n", g_program_params.max_pw_duration_secs);
}

EncryptedPW *createEncryptedPWStruct()
{
    EncryptedPW *encryptedPW_p = malloc(sizeof(EncryptedPW));
    pthread_mutex_init(&encryptedPW_p->mutex_encrypted_pw, NULL);
    encryptedPW_p->encrypted_pw.pw_data = (char *)calloc(BUFFER_SIZE + 1, sizeof(char));
    encryptedPW_p->encrypted_pw.pw_data_len = 0;
    encryptedPW_p->encrypted_pw.pw_id = 0;
    encryptedPW_p->encrypted_pw_ready = false;
    
    return encryptedPW_p;
}

DecryptedPWGuess *createDecryptedPWGuessStruct()
{
    DecryptedPWGuess *decrypted_pw_guess_p = malloc(sizeof(DecryptedPWGuess));
    pthread_mutex_init(&decrypted_pw_guess_p->mutex_decrypted_pw_guess, NULL);
    decrypted_pw_guess_p->guesser_id = 0;
    decrypted_pw_guess_p->guess_ready_to_be_checked = false;
    decrypted_pw_guess_p->pw_guess.pw_data = (char *)calloc(BUFFER_SIZE + 1, sizeof(char));
    decrypted_pw_guess_p->pw_guess.pw_data_len = 0;
    decrypted_pw_guess_p->pw_guess.pw_id = 0;

    pthread_condattr_init(&decrypted_pw_guess_p->cv_guess_full_attr);
    pthread_condattr_setclock(&decrypted_pw_guess_p->cv_guess_full_attr, CLOCK_MONOTONIC);
    pthread_cond_init(&decrypted_pw_guess_p->cv_guess_full, &decrypted_pw_guess_p->cv_guess_full_attr);

    return decrypted_pw_guess_p;
}

void printPWDetails(PW *pw_p)
{
    printf("PW id = %d.\n", pw_p->pw_id);
    printf("PW len = %d.\n", pw_p->pw_data_len);
    printf("PW pw = %s.\n", pw_p->pw_data);
}

int main(int argc, char *argv[])
{
    initProgramParams(&g_program_params);

    //Extract Parameters into g_command_line_args
    if (parseProgramParams(argc, argv, &g_program_params.plain_pw_len, &g_program_params.num_decrypters, &g_program_params.max_pw_duration_secs))
    {
        return -1;
    }

    g_encrypted_pw_p = createEncryptedPWStruct();
    g_decrypted_pw_guess_p = createDecryptedPWGuessStruct();

    // Create Encrypter
    pthread_t encryptor_thread;

    ASSERT(pthread_create(&encryptor_thread, NULL, encrypter_thread_main, NULL) == 0, "pthread_create failed for encryptor");

    //Create array of decrypters
    pthread_t decryptor_threads[g_program_params.num_decrypters];
    int decrypter_ids[g_program_params.num_decrypters];

    for (int i = 0; i < g_program_params.num_decrypters; ++i)
    {
        decrypter_ids[i] = i;
        ASSERT(pthread_create(&decryptor_threads[i], NULL, decrypter_thread_main, (void *)(&decrypter_ids[i])) == 0, "pthread_create failed for decryptor");
    }

    // block until all threads complete
    pthread_join(encryptor_thread, NULL);
    for (int i = 0; i < g_program_params.num_decrypters; ++i)
    {
        pthread_join(decryptor_threads[i], NULL);
    }

    return EXIT_SUCCESS;
}