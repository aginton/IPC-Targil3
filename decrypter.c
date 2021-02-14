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


bool parseMQName(int argc, char* argv[], int* out_client_id, char out_mq_name[]);
bool parseProgramParams(int argc, char* argv[], int* out_client_id, char out_mq_name[], int* out_num_of_rounds_p);
bool parseRoundsToLive(int argc, char* argv[], int* out_rounds_to_live);


//TODO: Change client_id (and other arguments) to global
bool parseProgramParams(int argc, char* argv[], int* out_client_id, char out_mq_name[], int* out_num_of_rounds_p)
{
    printf("[Decrypter process %d]\t\tEntered parseProgramParams, given %d arguments: { ", getpid(), argc);
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

    if(strlen(DECRYPTER_MQ_BASE_NAME) + strlen(argv[1]) > MAX_MQ_NAME_LEN)
    {
        printf("Error: message queue name buffer is of insufficient size\n");
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
    printf("[Decrypter #%d]:\t\tSending connection request to server.\n", client_id);
    uint8_t buffer[sizeof(Msg) + sizeof(ConnectReq)] = {0};
    Msg* msg_p = (Msg*)buffer;
    msg_p->msg_type = CONNECT_REQUEST;
    ConnectReq* connect_request_msg = (ConnectReq*)(msg_p->data);
    connect_request_msg->client_id = client_id;
    strcpy(connect_request_msg->mq_name, client_mq_name);
    sendMsg(server_mq, msg_p, MQ_MAX_MSG_SIZE, 10);
    printf("[Decrypter #%d]:\t\tSuccessfully sent connection request to server.\n", client_id);
}


void generatePWGuess(int client_id, mqd_t mq_to_read_from, Msg *incoming_msg_p, PW* out_plain_pw_guess_p)
{
    printf("[Decrypter #%d]:\t\tTrying to generate printable pw guess.\n", client_id);
    unsigned long long iteration = 0;
    Key generated_key;
    generated_key.key_len = KEY_LEN;
    PW* encrypted_pw_p = &((EncrypterMsg*)(&incoming_msg_p->data))->encrypted_pw;

    //DEBUG:

    PRINT_8_BYTE_BUFFER("decrypter first 8 bytes", ((char*)encrypted_pw_p->pw_data));
    
    //pause();
    do
    {
        // Check if encrypted password changed while generating a printable guess: 
        if (doesMQHaveMessages(mq_to_read_from))
        {
            printf("[Decrypter #%d]:\t\tStopped generating keys after %llu iterations because password changed.\n", client_id, iteration);

            readMessage(mq_to_read_from, incoming_msg_p);
            iteration = 0;
        }

        iteration++;
        ASSERT(encrypted_pw_p->pw_data_len != 0, "Cannot have zero-length encrypted password!");
        MTA_get_rand_data(generated_key.key, generated_key.key_len);
        ASSERT((generated_key.key_len) > 0, "Cannot have a zero-length key.");
        if (MTA_CRYPT_RET_OK != MTA_decrypt(generated_key.key, generated_key.key_len, encrypted_pw_p->pw_data, encrypted_pw_p->pw_data_len, 
                    out_plain_pw_guess_p->pw_data, &out_plain_pw_guess_p->pw_data_len))
        {
            printf("[Decrypter #%d]:\t\tAn error occurred with MTA_decrypt() \n", client_id);
        }
        
        out_plain_pw_guess_p->pw_id = encrypted_pw_p->pw_id;
        //out_decrypted_pw_guess[*out_decrypted_pw_guess_len] = '\0';
        //printf("[Decrypter #%d]:\t\tCurrently on iteration # %llu.\n", client_id, iteration);
    } while (!isPrintable(out_plain_pw_guess_p->pw_data, out_plain_pw_guess_p->pw_data_len));

    printf("[Decrypter #%d]:\t\tFound printable decrypted password %s after %llu iterations. Password id: %d\n", client_id, out_plain_pw_guess_p->pw_data, iteration, out_plain_pw_guess_p->pw_id);
}

void sendPWGuess(mqd_t server_mq, int client_id, PW* plain_pw_guess_p)
{
    uint8_t buffer[sizeof(Msg) + sizeof(DecrypterMsg)] = {0};
    Msg* msg_p = (Msg*)buffer;
    msg_p->msg_type = DECRYPTER_PW_GUESS;
    DecrypterMsg* decrypterMsg = (DecrypterMsg*)(msg_p->data);
    decrypterMsg->client_id = client_id;
    decrypterMsg->decrypted_pw_guess = *plain_pw_guess_p;
    sendMsg(server_mq, msg_p, MQ_MAX_MSG_SIZE, 0);    
}

//TODO: Change all mqd_t* arguments to by value (if not output)
void sendDisconnectReq(mqd_t server_mq, char* client_mq_name, int client_id)
{
    mq_unlink(client_mq_name);
    
    uint8_t buffer[sizeof(Msg) + sizeof(ConnectReq)] = {0};
    Msg* msg_p = (Msg*)buffer;
    msg_p->msg_type = DISCONNECT_REQUEST;
    DisconnectReq* disconnect_req_msg = (DisconnectReq*)(msg_p->data);
    disconnect_req_msg->client_id = client_id;
    sendMsg(server_mq, msg_p, MQ_MAX_MSG_SIZE, 10);

    mq_close(server_mq);
}

int main(int argc, char* argv[])
{   
    int num_of_rounds = -1;
    char client_mq_name[MAX_MQ_NAME_LEN + 1];
    int client_id = -1;

    uint8_t buffer[MQ_MAX_MSG_SIZE] = {0};
    Msg* incoming_msg_p = (Msg*)buffer;
    //PW* encrypted_pw = &((EncrypterMsg*)(&incoming_msg_p->data))->encrypted_pw;

    if (!parseProgramParams(argc, argv, &client_id, client_mq_name, &num_of_rounds))
    {
        exit(1);
    }

    PW plain_pw_guess;
    //TODO: Place everything up to and including send connection request into separate function
    struct mq_attr attr_client, attr_server;
    setMQAttrbs(0, MQ_MAX_MSGS, MQ_MAX_MSG_SIZE, 0, &attr_client);
    setMQAttrbs(0, MQ_MAX_MSGS, MQ_MAX_MSG_SIZE, 0, &attr_server);
    mqd_t decrypter_mq = openReadOnlyMQ(client_mq_name, true, &attr_client);
    mqd_t server_mq = openWriteOnlyMQ(MQ_SERVER_NAME, &attr_server);

    sendConnectReq(server_mq, client_id, client_mq_name);
    
    readMessage(decrypter_mq, incoming_msg_p);
    
    while (true)
    {
        //try to decrypt local encrypted_pw to printable pw
        generatePWGuess(client_id, decrypter_mq, incoming_msg_p, &plain_pw_guess);
        sendPWGuess(server_mq, client_id, &plain_pw_guess);

        if (-1 != num_of_rounds)
        {
            // num_of_rounds cannot be zero.
            --num_of_rounds;
            if (0 == num_of_rounds)
            {
                sendDisconnectReq(server_mq, client_mq_name, client_id);
                exit(0);
            }
        }
    }
}