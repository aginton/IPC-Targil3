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



//TODO: Change client_id (and other arguments) to global
bool parseProgramParams(int argc, char* argv[], int* out_client_id, char out_mq_name[], int* out_num_of_rounds_p)
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

    bool has_valid_id_arg = parseMQName(argc, argv, out_client_id, out_mq_name);   
    bool has_valid_num_of_rounds = parseRoundsToLive(argc, argv, out_num_of_rounds_p);
    return has_valid_id_arg && has_valid_num_of_rounds;
}


bool parseMQName(int argc, char* argv[], int* out_client_id, char out_mq_name[])
{
    if (argc < 2)    
    {
        printf("Error: invalid number of program arguments.\n");
        return false;
    }
    unsigned int id = atoi(argv[1]);
    if (0 == id)
    {
        if (0 != strcmp(argv[1], "0"))
        {
            printf("Error: %s is not a valid decrypter id.\n", argv[1]);
            return false;
        }
    }

    if(strlen(DECRYPTER_MQ_BASE_NAME) + strlen(argv[1]) < MAX_MQ_NAME_LEN)
    {
        printf("Error: message que name buffer is of insufficient size");
        return false;
    }
    *out_client_id = id;
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


void sendConnectReq(mqd_t server_mq, int client_id, char* client_mq_name)
{
    uint8_t buffer[sizeof(Msg) + sizeof(ConnectReq)] = {0};
    //Msg* msg_p = createMsg(ENCRYPTER_ENCRYPTED_PW, &message, sizeof(EncrypterMsg));
    Msg* msg_p = (Msg*)buffer;
    msg_p->msg_type = CONNECT_REQUEST;
    ConnectReq* connect_request_msg = (ConnectReq*)(msg_p->data);
    connect_request_msg->client_id = client_id;
    strcpy(connect_request_msg->mq_name, client_mq_name);
    sendMsg(&server_mq, msg_p, MQ_MAX_MSG_SIZE, 0);
}

void outputPrintablePWGuess(int client_id, mqd_t* mq_to_read_from, PW *encrypted_pw_p, PW* out_plain_pw_guess_p)
{
    unsigned long long iteration = 0;
    Key generated_key;
    generated_key.key_len = KEY_LEN;

    do
    {
        // Check if encrypted password changed while generating a printable guess: 
        if (doesMQHaveMessages(&mq_to_read_from))
        {
            printf("[Decrypter #%d]:\t\tStopped generating keys after %llu iterations because password changed.\n", client_id, iteration);
            EncrypterMsg* encrypted_pw_msg = (EncrypterMsg*)(readMessage(&mq_to_read_from)->data);
            *encrypted_pw_p = encrypted_pw_msg->encrypted_pw;
            iteration = 0;
        }

        //create random key and copy g_encrypted_pw into local variable encrypted_pw
        iteration++;
        ASSERT(encrypted_pw_p->pw_data_len != 0, "Cannot have zero-length encrypted password!");
        MTA_get_rand_data(generated_key.key, generated_key.key_len);
        ASSERT((generated_key.key_len) > 0, "Cannot have a zero-length key.");
        MTA_decrypt(generated_key.key, generated_key.key_len, encrypted_pw_p->pw_data, encrypted_pw_p->pw_data_len, 
                    out_plain_pw_guess_p->pw_data, out_plain_pw_guess_p->pw_data_len);
        out_plain_pw_guess_p->pw_id = encrypted_pw_p->pw_id;
        //out_decrypted_pw_guess[*out_decrypted_pw_guess_len] = '\0';

    } while (!isPrintable(out_plain_pw_guess_p->pw_data, out_plain_pw_guess_p->pw_data_len));

    printf("[Decrypter #%d]:\t\tFound printable decrypted password %s after %llu iterations. Password id: %d\n", client_id, out_plain_pw_guess_p->pw_data, iteration, out_plain_pw_guess_p->pw_id);
    return true;
}



//TODO: CHange mq_name to global 

int main(int argc, char* argv[])
{   
    int num_of_rounds = -1;
    char client_mq_name[MAX_MQ_NAME_LEN + 1];
    int client_id = -1;

    if (!parseProgramParams(argc, argv, &client_id, client_mq_name, &num_of_rounds))
    {
        exit(1);
    }

    PW encrypted_pw;
    PW plain_pw_guess;
    //TODO: Place everything up to and including send connection request into separate function
    struct mq_attr attr_client, attr_server;
    setMQAttrbs(0, MQ_MAX_MSGS, MQ_MAX_MSG_SIZE, 0, &attr_client);
    setMQAttrbs(0, MQ_MAX_MSGS, MQ_MAX_MSG_SIZE, 0, &attr_server);
    mqd_t decrypter_mq = openReadOnlyMQ(client_mq_name, true, &attr_client);
    mqd_t server_mq = openWriteOnlyMQ(MQ_SERVER_NAME, &attr_server);

    sendConnectReq(server_mq, client_id, client_mq_name);
    
    EncrypterMsg* encrypted_pw_msg = (EncrypterMsg*)(readMessage(&decrypter_mq)->data);
    encrypted_pw = encrypted_pw_msg->encrypted_pw;

    while (true)
    {
        //try to decrypt local encrypted_pw to printable pw
        outputPrintablePWGuess(client_id, &server_mq, &encrypted_pw, &plain_pw_guess);
        
        // wait for chance to write decrypted_pw_guess onto g_decrypted_pw_guess
        // pthread_mutex_lock(&g_decrypted_pw_guess_p->mutex_decrypted_pw_guess);
        // waitForTurnToGuess(my_id);

        // if (encrypted_pw.pw_id == g_encrypted_pw_p->encrypted_pw.pw_id)
        // {
        //     setGlobalDecryptedPWGuess(decrypted_pw_guess, decrypted_pw_guess_len, encrypted_pw.pw_id, my_id);
        //     pthread_mutex_unlock(&g_decrypted_pw_guess_p->mutex_decrypted_pw_guess);
        //     pthread_cond_signal(&g_decrypted_pw_guess_p->cv_guess_full);
        // }
        // else
        // {
        //     pthread_mutex_unlock(&g_decrypted_pw_guess_p->mutex_decrypted_pw_guess);
        // }
    }
}