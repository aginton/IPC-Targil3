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

#define DISCONNECT (true)
#define CONNECT (false)



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

bool parseProgramParams(int argc, char* argv[], int* out_client_id, char out_mq_name[], int* out_num_of_rounds_p)
{
    if (argc < 2)    
    {
        printf("Error: invalid number of program arguments.\n");
        return false;
    }

    bool has_valid_id_arg = parseMQName(argc, argv, out_client_id, out_mq_name);   
    bool has_valid_num_of_rounds = parseRoundsToLive(argc, argv, out_num_of_rounds_p);
    return has_valid_id_arg && has_valid_num_of_rounds;
}

bool updateEncryptedPW(mqd_t mq_to_read_from, Msg* incoming_msg_p)
{
    while (doesMQHaveMessages(mq_to_read_from))
    {
        readMessage(mq_to_read_from, incoming_msg_p);
        return true;
    }

    return false;
}

void generatePWGuess(int client_id, mqd_t mq_to_read_from, Msg* incoming_msg_p, PW* out_plain_pw_guess_p)
{
    unsigned long long iteration = 0;
    Key generated_key = {0};
    memset(&generated_key, 0, sizeof(Key));
    generated_key.key_len = KEY_LEN;
    PW* encrypted_pw_p = &((EncrypterMsg*)(&incoming_msg_p->data))->encrypted_pw;
    out_plain_pw_guess_p->pw_id = encrypted_pw_p->pw_id;
    printf("\n[Decrypter #%d]:\tTrying to generate printable password for encrypted password # %d.\n", client_id, encrypted_pw_p->pw_id);
    
    do
    {
        iteration++;

        // if (0 == (iteration % 10000))
        // {
        //     printf("[Decrypter #%d]:\tdone %llu iterations already.\n", client_id, iteration);
        // }

        // Check if encrypted password changed while generating a printable guess: 
        if (updateEncryptedPW(mq_to_read_from, incoming_msg_p))
        {
            printf("[Decrypter #%d]:\tStopped generating keys for password # %d after %llu iterations because received encrypted pasword # %d\n", client_id, out_plain_pw_guess_p->pw_id, iteration, encrypted_pw_p->pw_id);
            out_plain_pw_guess_p->pw_id = encrypted_pw_p->pw_id;
            iteration = 0;
        }
        
        ASSERT(encrypted_pw_p->pw_data_len != 0, "Cannot have zero-length encrypted password!");
        MTA_get_rand_data(generated_key.key, generated_key.key_len);
        ASSERT((generated_key.key_len) > 0, "Cannot have a zero-length key.");
        
        if (MTA_CRYPT_RET_OK != MTA_decrypt(generated_key.key, generated_key.key_len, encrypted_pw_p->pw_data, encrypted_pw_p->pw_data_len, out_plain_pw_guess_p->pw_data, &out_plain_pw_guess_p->pw_data_len))
        {   
            printf("[Decrypter #%d]:\tAn error occurred with MTA_decrypt() \n", client_id);
        }
        
    } while (!isPrintable(out_plain_pw_guess_p->pw_data, out_plain_pw_guess_p->pw_data_len));

    printf("[Decrypter #%d]:\tAfter %llu iterations, found printable guess %s for encrypted password #%d.\n", client_id, iteration, out_plain_pw_guess_p->pw_data, out_plain_pw_guess_p->pw_id);
}

bool sendPWGuess(mqd_t server_mq, int client_id, PW* plain_pw_guess_p)
{
    printf("[Decrypter #%d]:\tSending server plain pw guess %s with id=%d\n", client_id, plain_pw_guess_p->pw_data, plain_pw_guess_p->pw_id);
    uint8_t buffer[sizeof(Msg) + sizeof(DecrypterMsg)] = {0};
    Msg* msg_p = (Msg*)buffer;
    msg_p->msg_type = DECRYPTER_PW_GUESS;
    DecrypterMsg* decrypterMsg = (DecrypterMsg*)(msg_p->data);
    decrypterMsg->client_id = client_id;
    decrypterMsg->decrypted_pw_guess = *plain_pw_guess_p;
    
    return tryToSendMsg(server_mq, msg_p, MQ_MAX_MSG_SIZE, 0);    
}

void sendConnectReq(mqd_t server_mq, int client_id, char* client_mq_name, bool disconnect)
{
    printf("[Decrypter #%d]:\tSending %s request to server.\n", client_id, disconnect ? "disconnection" : "connection");
    uint8_t buffer[sizeof(Msg) + sizeof(ConnectReq)] = {0};
    Msg* msg_p = (Msg*)buffer;
    msg_p->msg_type = disconnect ? DISCONNECT_REQUEST : CONNECT_REQUEST;
    ConnectReq* connect_request_msg = (ConnectReq*)(msg_p->data);
    connect_request_msg->client_id = client_id;
    strcpy(connect_request_msg->mq_name, client_mq_name);
    sendMsg(server_mq, msg_p, MQ_MAX_MSG_SIZE, 10);
}

void initMQs(char* client_mq_name, int client_id, mqd_t* out_decrypter_mqd, mqd_t* out_server_mqd){
    struct mq_attr attr_client, attr_server;
    setMQAttrbs(0, DECRYPTER_MQ_MAX_MSGS, MQ_MAX_MSG_SIZE, 0, &attr_client);
    setMQAttrbs(0, SERVER_MQ_MAX_MSGS, MQ_MAX_MSG_SIZE, 0, &attr_server);
    mq_unlink(client_mq_name);
    *out_decrypter_mqd = openReadOnlyMQ(client_mq_name, &attr_client);
    *out_server_mqd = openWriteOnlyMQ(MQ_SERVER_NAME, &attr_server);
}

int main(int argc, char* argv[])
{   
    int num_of_rounds = -1;
    char client_mq_name[MAX_MQ_NAME_LEN + 1];
    int client_id = -1;

    uint8_t buffer[MQ_MAX_MSG_SIZE] = {0};
    Msg* incoming_msg_p = (Msg*)buffer;
    
    if (!parseProgramParams(argc, argv, &client_id, client_mq_name, &num_of_rounds))
    {
        exit(1);
    }

    PW plain_pw_guess;
    memset(&plain_pw_guess, 0, sizeof(PW));
    
    mqd_t server_mq, decrypter_mq;
    initMQs(client_mq_name, client_id, &decrypter_mq, &server_mq);
    
    sendConnectReq(server_mq, client_id, client_mq_name, CONNECT);
    
    readMessage(decrypter_mq, incoming_msg_p);
    
    while (true)
    {
        //try to decrypt local encrypted_pw to printable pw
        generatePWGuess(client_id, decrypter_mq, incoming_msg_p, &plain_pw_guess);
        while (!sendPWGuess(server_mq, client_id, &plain_pw_guess))
        {
            if (updateEncryptedPW(decrypter_mq, incoming_msg_p))
            {
                continue;
            }
        }

        if (-1 != num_of_rounds)
        {
            // num_of_rounds cannot be zero.
            --num_of_rounds;
            if (0 == num_of_rounds)
            {
                sendConnectReq(server_mq, client_id, client_mq_name, DISCONNECT);
                mq_close(decrypter_mq);
                mq_close(server_mq);
                printf("[Decrypter #%d]:\tGoodbye!\n", client_id);
                exit(0);
            }
        }
    }
}