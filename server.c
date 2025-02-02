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


typedef enum {PWS_MATCH = 0, PWS_DONT_MATCH, PW_GUESS_ID_INVALID} DECRYPTED_PW_GUESS_RET_STATUS;

typedef struct serverPW {
    PW plain_pw;
    PW encrypted_pw;
    Key key;
} ServerPW;

static bool connected_clients[MAX_NUMBER_CONNECTIONS];
static mqd_t client_mqs[MAX_NUMBER_CONNECTIONS];
static char client_mq_names[MAX_NUMBER_CONNECTIONS][MAX_MQ_NAME_LEN + 1];

int createAndEncryptNewPW(ServerPW *out_server_pw_p)
{
    PW* plain_pw_p = &(out_server_pw_p->plain_pw);
    PW* encrypted_pw_p = &(out_server_pw_p->encrypted_pw);
    Key* key_p = &(out_server_pw_p->key);

    createPrintablePW(plain_pw_p);
    (plain_pw_p->pw_id)++;
    (encrypted_pw_p->pw_id)++;
    MTA_get_rand_data(key_p->key, key_p->key_len);

    if (MTA_CRYPT_RET_OK != MTA_encrypt(key_p->key, key_p->key_len, plain_pw_p->pw_data, plain_pw_p->pw_data_len, encrypted_pw_p->pw_data, &(encrypted_pw_p->pw_data_len)))
    {
        printf("An error occured with MTA_encrypt()...\n");
        exit(-1);
    }

    printf("\n[SERVER]\tCreated plain pw %s with len=%d and id= %d\n", plain_pw_p->pw_data, plain_pw_p->pw_data_len, plain_pw_p->pw_id);
    return 0;
}


bool sendClientEncryptedPW(PW* encrypted_pw_p, mqd_t client_mq)
{
    ASSERT(NULL != encrypted_pw_p, "encrypted pw cannot be NULL\n");
    uint8_t buffer[sizeof(Msg) + sizeof(EncrypterMsg)] = {0};
    Msg* msg_p = (Msg*)buffer;
    msg_p->msg_type = ENCRYPTER_ENCRYPTED_PW;
    EncrypterMsg* encryptedMsg = (EncrypterMsg*)(msg_p->data);
    encryptedMsg->encrypted_pw = *encrypted_pw_p;
    
    return tryToSendMsg(client_mq, msg_p, MQ_MAX_MSG_SIZE, 0);
}



void handleConnectRequest(ConnectReq* connect_req_p, PW* encrypted_pw_p)
{
    ASSERT((NULL != connect_req_p) && (NULL != encrypted_pw_p), "handleConnectRequest received NULL pointer\n");

    printf("[SERVER]:\tReceived connection request from client #%d\n", connect_req_p->client_id);

    int client_id = connect_req_p->client_id;
    
    if(client_id >= 0 && client_id < MAX_NUMBER_CONNECTIONS)
    {
        if (connected_clients[client_id])
        {
            printf("[SERVER]\tAlready has a connected client with id=%d\n", client_id);
            return;
        }
    }
    else
    {
        printf("client id must be in the range [0-%d]", MAX_NUMBER_CONNECTIONS);
    }

    connected_clients[client_id] = true;
    struct mq_attr attr;
    setMQAttrbs(0, DECRYPTER_MQ_MAX_MSGS, MQ_MAX_MSG_SIZE, 0, &attr);
    client_mqs[client_id] = openWriteOnlyMQ(connect_req_p->mq_name, &attr);
    strcpy(client_mq_names[client_id], connect_req_p->mq_name);
    printf("[SERVER]:\tAdded client #%d\n", connect_req_p->client_id);
    
    printf("[SERVER]:\tSending encrypted pw #%d to client #%d.\n", encrypted_pw_p->pw_id, connect_req_p->client_id);
    sendClientEncryptedPW(encrypted_pw_p, client_mqs[client_id]);
}

bool disconnect_client(int client_id)
{
    bool success = false;

    if(client_id >= 0 && client_id < MAX_NUMBER_CONNECTIONS)
    {
        if(connected_clients[client_id])
        {
            mq_close(client_mqs[client_id]);
            mq_unlink(client_mq_names[client_id]);
            client_mq_names[client_id][0] = '\0';   
            connected_clients[client_id] = false;
            printf("[SERVER]:\tClient #%d Disconnected.\n", client_id);
            success = true;
        }
        else
        {
            printf("[SERVER]:\tERROR: client must connected to disconnect\n");
        }
    }
    else
    {
        printf("[SERVER]:\tERROR: client id must be in the range [0-%d]\n", MAX_NUMBER_CONNECTIONS);
    }

    return success;
}

void handleDisconnectRequest(DisconnectReq* disconnect_req_p, bool connected_clients[], mqd_t client_mqs[])
{
    ASSERT(NULL != disconnect_req_p, "Error: disconnect_req_p is NULL in handleDisconnectRequest");
    ASSERT(disconnect_req_p->client_id < MAX_NUMBER_CONNECTIONS, 
        "Error: client_id is out of bounds in handleDisconnectRequest");
    
    int client_id = disconnect_req_p->client_id;
    disconnect_client(client_id);
}

DECRYPTED_PW_GUESS_RET_STATUS checkDecryptedPWGuess(PW plain_pw, DecrypterMsg* decrypter_msg_p)
{
    ASSERT(NULL != decrypter_msg_p, "Error: decrypter_msg_p is NULL in checkDecryptedPWGuess");

    PW* pw_guess = &(decrypter_msg_p->decrypted_pw_guess);

    if (pw_guess->pw_id != plain_pw.pw_id)
    {
        printf("[SERVER]:\tDecrypter #%d incorrectly used id #%d. Should be using id #%d.\n",
               decrypter_msg_p->client_id, pw_guess->pw_id, plain_pw.pw_id);
        return PW_GUESS_ID_INVALID;
    }
    if (strcmp(pw_guess->pw_data, plain_pw.pw_data) != 0)
    {
        printf("[SERVER]:\tDecrypter #%d incorrectly guessed password %s with id=%d!\n", decrypter_msg_p->client_id, decrypter_msg_p->decrypted_pw_guess.pw_data, decrypter_msg_p->decrypted_pw_guess.pw_id);
        return PWS_DONT_MATCH;
    }

    //passwords match!
    printf("[SERVER]:\tDecrypter #%d successfully decrypted password %s!\n", decrypter_msg_p->client_id, plain_pw.pw_data);
    return PWS_MATCH;
}

void handlePWGuess(DecrypterMsg* decrypter_msg_p, ServerPW* server_pw_p, bool connected_clients[], mqd_t client_mqs[])
{
    ASSERT(NULL != decrypter_msg_p, "Error: decrypter_msg_p is NULL in handlePWGuess");
    ASSERT(NULL != server_pw_p, "Error: server_pw_p is NULL in handlePWGuess");

    printf("[SERVER]:\tReceived plain pw guess %s with id=%d from client_id=%d\n", decrypter_msg_p->decrypted_pw_guess.pw_data, decrypter_msg_p->decrypted_pw_guess.pw_id,  decrypter_msg_p->client_id);

    DECRYPTED_PW_GUESS_RET_STATUS rc = checkDecryptedPWGuess(server_pw_p->plain_pw, decrypter_msg_p);
    switch (rc)
    {
    case PWS_MATCH:
        createAndEncryptNewPW(server_pw_p);
        for (int i = 0; i < MAX_NUMBER_CONNECTIONS; ++i)
        {
            if (connected_clients[i] == true)
            {
                printf("[SERVER]:\tSending encrypted pw #%d to client #%d.\n", server_pw_p->encrypted_pw.pw_id, i);
                if (!sendClientEncryptedPW(&(server_pw_p->encrypted_pw), client_mqs[i]))
                {
                    disconnect_client(i);
                }
            }
        }
        break;
    default:
        break;
    }
    
}


void handleMsg(ServerPW* server_pw_p, mqd_t server_mq)
{
    uint8_t buffer[MQ_MAX_MSG_SIZE] = {0};
    Msg* msg_p = (Msg*)buffer;

    printf("[SERVER]\tReading message\n");
    readMessage(server_mq, msg_p);

    MSG_TYPE_E msg_type = msg_p->msg_type;
    
    switch (msg_type)
    {
    case CONNECT_REQUEST:
        handleConnectRequest((ConnectReq*)msg_p->data, &(server_pw_p->encrypted_pw));
        break;

    case DISCONNECT_REQUEST:
        handleDisconnectRequest((DisconnectReq*)msg_p->data, connected_clients, client_mqs);
        break;

    case DECRYPTER_PW_GUESS:
        handlePWGuess((DecrypterMsg*)msg_p->data, server_pw_p, connected_clients, client_mqs);
        break;
    
    default:
        printf("[Server process %d]\tserverRespondToMessage() - received message of unknown type.\n", getpid());
        break;
    }
}

void initServerPW(ServerPW* server_pw_p)
{
    memset(&server_pw_p->key, 0, sizeof(Key));
    memset(&server_pw_p->encrypted_pw, 0, sizeof(PW));
    memset(&server_pw_p->plain_pw, 0, sizeof(PW));

    server_pw_p->plain_pw.pw_data_len = PLAIN_PW_LEN;
    server_pw_p->key.key_len = KEY_LEN;
}


int main()
{
    struct mq_attr attr;
    setMQAttrbs(0, SERVER_MQ_MAX_MSGS, MQ_MAX_MSG_SIZE, 0, &attr);

    mq_unlink(MQ_SERVER_NAME);
    mqd_t server_mq = openReadOnlyMQ(MQ_SERVER_NAME, &attr);    
    ServerPW server_pw = {0};
    initServerPW(&server_pw);

    createAndEncryptNewPW(&server_pw);

    while (true)
    {
        handleMsg(&server_pw, server_mq);
    }
}