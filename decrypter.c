#include <stdio.h>
#include <unistd.h>
#include <mqueue.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>

#include "mta_crypt.h"
#include "mta_rand.h"
#include "datastructs.h"
#include "utils.h"



bool parseProgramParams(int argc, char* argv[], char out_mq_name[], unsigned int* out_num_of_rounds_p)
{
    printf("[%Decrypter process %d]\t\tEntered parseProgramParams, given %d arguments: { ", getpid(), argc);
    for (int i = 0; i < argc - 1; ++i)
    {
        printf("%s, ", argv[i]);
    }
    printf("%s }\n", argv[argc-1]);

    if (argc < 2)    
    {
        printf("Error: invalid number of program arguments.\n");
        return false;
    }

    bool has_valid_id_arg = parseAndOutputMQName(argc, argv, out_mq_name);   
    bool has_valid_num_of_rounds = parseAndOutputRoundsToLive(argc, argv, out_num_of_rounds_p);
    return has_valid_id_arg && has_valid_num_of_rounds;
}


bool parseAndOutputMQName(int argc, char* argv[], char out_mq_name[], unsigned int mq_name_buffer_size)
{
    if (argc < 2)    
    {
        printf("Error: invalid number of program arguments.\n");
        return false;
    }
    unsigned int id = atoi(argv[1]);
    if (0 == id)
    {
        printf("Error: %s is not a valid decrypter id.\n", argv[1]);
        return false;
    }

    if(strlen(DECRYPTER_MQ_BASE_NAME) + strlen(argv[1]) <= mq_name_buffer_size)
    {
        printf("Error: message que name buffer is of insufficient size");
        return false;
    }

    strcpy(out_mq_name, DECRYPTER_MQ_BASE_NAME);
    strcat(out_mq_name, argv[1]);
    return true;
}

bool parseRoundsToLive(int argc, char* argv[], int* out_rounds_to_live)
{
    ASSERT(NULL != out_rounds_to_live, "out_rounds_to_live is NULL in parseRoundsToLive");

    if (argc < 3)
    {
        *out_rounds_to_live = -1;
        return true;
    }

    if ((0 != strcmp(argv[2], "-n")) || argc < 4)
    {   
        printf("Error: Arguments must be in the format <id> [-n <number of rounds>]\n");
        return false;
    }

    unsigned int number_of_rounds = atoi(argv[3]);
    if (0 == number_of_rounds)
    {
        printf("Error: number of rounds must be a positive integer.\n");
        return false;
    }
    
    *out_rounds_to_live = number_of_rounds;
    return true;
}



//TODO: CHange mq_name to global 

int main(int argc, char* argv[])
{   
    bool has_num_rounds_arg = false;
    char mq_name[MAX_MQ_NAME_LEN + 1];

    parseProgramParams(argc, argv, mq_name, &num_of_rounds);
    

    // Key key;
    // initKey(&key, g_program_params.key_len);

    // PW encrypted_pw;
    // initPW(&encrypted_pw, g_program_params.plain_pw_len);

    // char decrypted_pw_guess[BUFFER_SIZE];
    // unsigned int decrypted_pw_guess_len = 0;

    // pthread_mutex_lock(&g_encrypted_pw_p->mutex_encrypted_pw);
    // while (!g_encrypted_pw_p->encrypted_pw_ready)
    // {
    //     pthread_cond_wait(&g_encrypted_pw_p->cv_encrypted_pw_ready, &g_encrypted_pw_p->mutex_encrypted_pw);
    // }
    // pthread_mutex_unlock(&g_encrypted_pw_p->mutex_encrypted_pw);
    
    // while (true)
    // {
    //     copyFromGlobalEncryptedPW(&encrypted_pw);

    //     //try to decrypt local encrypted_pw to printable pw
    //     if (!outputPrintablePWGuess(my_id, &key, &encrypted_pw, decrypted_pw_guess, &decrypted_pw_guess_len))
    //     {
    //         // Password changed while generating a printable password.
    //         continue;
    //     }

    //     // wait for chance to write decrypted_pw_guess onto g_decrypted_pw_guess
    //     pthread_mutex_lock(&g_decrypted_pw_guess_p->mutex_decrypted_pw_guess);
    //     waitForTurnToGuess(my_id);

    //     if (encrypted_pw.pw_id == g_encrypted_pw_p->encrypted_pw.pw_id)
    //     {
    //         setGlobalDecryptedPWGuess(decrypted_pw_guess, decrypted_pw_guess_len, encrypted_pw.pw_id, my_id);
    //         pthread_mutex_unlock(&g_decrypted_pw_guess_p->mutex_decrypted_pw_guess);
    //         pthread_cond_signal(&g_decrypted_pw_guess_p->cv_guess_full);
    //     }
    //     else
    //     {
    //         pthread_mutex_unlock(&g_decrypted_pw_guess_p->mutex_decrypted_pw_guess);
    //     }
    // }
}