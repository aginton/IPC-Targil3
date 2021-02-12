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

int createAndEncryptNewPW(ServerPW* out_server_pw_p);
DECRYPTED_PW_GUESS_RET_STATUS checkDecryptedPWGuess(PW plain_pw, DecrypterMsg* decrypter_msg_p);



int createAndEncryptNewPW(ServerPW *out_server_pw_p)
{
    PW* plain_pw_p = &(out_server_pw_p->plain_pw);
    PW* encrypted_pw_p = &(out_server_pw_p->encrypted_pw);
    Key* key_p = &(out_server_pw_p->key);

    createPrintablePW(plain_pw_p);
    (plain_pw_p->pw_id)++;
    MTA_get_rand_data(key_p->key, key_p->key_len);

    if (MTA_CRYPT_RET_OK != MTA_encrypt(key_p->key, key_p->key_len, plain_pw_p->pw_data, plain_pw_p->pw_data_len, encrypted_pw_p->pw_data, &(encrypted_pw_p->pw_data_len)))
    {
        printf("An error occured with MTA_encrypt()...\n");
        exit(-1);
    }

    printf("[Encrypter]:   \t\tGenerated new password %s with id %d.\n", plain_pw_p->pw_data, plain_pw_p->pw_id);
    return 0;
}


void sendClientsEncryptedPW(PW* encrypted_pw_p, bool connected_clients[], mqd_t client_mqs[])
{
    ASSERT(NULL != encrypted_pw_p, "encrypted pw cannot be NULL\n");

    uint8_t buffer[sizeof(Msg) + sizeof(EncrypterMsg)] = {0};
    //Msg* msg_p = createMsg(ENCRYPTER_ENCRYPTED_PW, &message, sizeof(EncrypterMsg));
    Msg* msg_p = (Msg*)buffer;
    msg_p->msg_type = ENCRYPTER_ENCRYPTED_PW;
    EncrypterMsg* encryptedMsg = (EncrypterMsg*)(msg_p->data);
    encryptedMsg->encrypted_pw = *encrypted_pw_p;

    for (int i; i < MAX_NUMBER_CONNECTIONS; ++i)
    {
        if (connected_clients[i])
        {
            sendMsg(&client_mqs[i], msg_p, MQ_MAX_MSG_SIZE, 0);
        }
    }
    // pthread_mutex_lock(&g_encrypted_pw_p->mutex_encrypted_pw);
    // g_encrypted_pw_p->encrypted_pw.pw_data_len = new_encrypted_pw_len;
    // g_encrypted_pw_p->encrypted_pw.pw_id = new_encrypted_pw_id;

    // memcpy(g_encrypted_pw_p->encrypted_pw.pw_data, new_encrypted_pw, new_encrypted_pw_len);
    // pthread_mutex_unlock(&g_encrypted_pw_p->mutex_encrypted_pw);
}

void handleConnectRequest(ConnectReq* connect_req_p, PW* encrypted_pw_p, bool connected_clients[], mqd_t client_mqs[])
{
    ASSERT((NULL != connect_req_p) && (NULL != encrypted_pw_p), "handleConnectRequest received NULL pointer\n");

    int client_id = connect_req_p->client_id;
    
    if(client_id >= 0 && client_id < MAX_NUMBER_CONNECTIONS)
    {
        if (connected_clients[client_id])
        {
            printf("[Server]\t\tAlready has a connected client with id=%d\n", client_id);
            return;
        }
        else
        {

        }
    }
    else
    {
        printf("client id must be in the range [0-%d]", MAX_NUMBER_CONNECTIONS);
    }
}

void handleDisconnectRequest(DisconnectReq* disconnect_req_p, bool connected_clients[], mqd_t client_mqs[])
{
    ASSERT(NULL != disconnect_req_p, "Error: disconnect_req_p is NULL in handleDisconnectRequest");
    ASSERT(disconnect_req_p->client_id > -1 && disconnect_req_p->client_id < MAX_NUMBER_CONNECTIONS, 
        "Error: client_id is out of bounds in handleDisconnectRequest");

    mq_close(client_mqs[disconnect_req_p->client_id]);
    connected_clients[disconnect_req_p->client_id] = false;
}

void handlePWGuess(DecrypterMsg* decrypter_msg_p, ServerPW* server_pw_p, bool connected_clients[], mqd_t client_mqs[])
{
    ASSERT(NULL != decrypter_msg_p, "Error: decrypter_msg_p is NULL in handlePWGuess");
    ASSERT(NULL != server_pw_p, "Error: server_pw_p is NULL in handlePWGuess");

    DECRYPTED_PW_GUESS_RET_STATUS rc = checkDecryptedPWGuess(server_pw_p->plain_pw, decrypter_msg_p);
    switch (rc)
    {
    case PWS_MATCH:
        createAndEncryptNewPW(server_pw_p);
        sendClientsEncryptedPW(&(server_pw_p->encrypted_pw), connected_clients, client_mqs);
        break;
    default:
        break;
    }
    
}

DECRYPTED_PW_GUESS_RET_STATUS checkDecryptedPWGuess(PW plain_pw, DecrypterMsg* decrypter_msg_p)
{
    ASSERT(NULL != decrypter_msg_p, "Error: decrypter_msg_p is NULL in checkDecryptedPWGuess");

    PW* pw_guess = &(decrypter_msg_p->decrypted_pw_guess);

    if (pw_guess->pw_id != plain_pw.pw_id)
    {
        printf("[Encrypter]:   \t\tDecrypter Thread #%d incorrectly used id #%d. Should be using id #%d.\n",
               decrypter_msg_p->client_id, pw_guess->pw_id, plain_pw.pw_id);
        return PW_GUESS_ID_INVALID;
    }
    if (strcmp(pw_guess->pw_data, plain_pw.pw_data) != 0)
    {
        return PWS_DONT_MATCH;
    }

    //passwords match!
    printf("[Encrypter]:   \t\tDecrypter Thread #%d successfully decrypted password %s!\n", decrypter_msg_p->client_id, plain_pw.pw_data);
    return PWS_MATCH;
}


void handleMsg(ServerPW* server_pw_p, mqd_t* server_mq_p, bool connected_clients[], mqd_t client_mqs[])
{
    //ASSERT..

    Msg* msg_p = readMessage(server_mq_p);
    MSG_TYPE_E msg_type = msg_p->msg_type;

    switch (msg_type)
    {
    case CONNECT_REQUEST:
        //printf("[%s process %d]\t\tserverRespondToMessage() - Received CONNECT_REQ message.\n", server_src, getpid());
        // serverHandleConnectRequest(msg_p->data, out_clients_p, &(out_key_and_pws->encrypted_pw));
        handleConnectRequest((ConnectReq*)msg_p->data, &(server_pw_p->encrypted_pw), connected_clients, client_mqs);
        break;

    case DISCONNECT_REQUEST:
        //printf("[%s process %d]\t\tserverRespondToMessage() - Received DISCONNECT_REQ message.\n", server_src, getpid());
        handleDisconnectRequest((DisconnectReq*)msg_p->data, connected_clients, client_mqs);
        break;

    case DECRYPTER_PW_GUESS:
        //printf("[%s process %d]\t\tserverRespondToMessage() - Received DECRYPTER_NEW_PW_GUESS message.\n", server_src, getpid());
        //DecrypterMsg* decrypter_msg = (DecrypterMsg*)msg_p->data; 
        handlePWGuess((DecrypterMsg*)msg_p->data, server_pw_p, connected_clients, client_mqs);
        break;
    
    default:
        printf("[Server process %d]\t\tserverRespondToMessage() - received message of unknown type.\n", getpid());
        break;
    }

    free(msg_p);
}





int main()
{
    mqd_t server_mq;
    struct mq_attr attr;
    setMQAttrbs(0, MQ_MAX_MSGS, MQ_MAX_MSG_SIZE, 0, &attr);
    //printf("[%s process %d]\t\tmain() - going to try and open mq_server.\n", server_src, getpid());

    mq_unlink(MQ_SERVER_NAME);
    if (-1 == (server_mq = mq_open (MQ_SERVER_NAME, O_CREAT | O_EXCL | O_RDONLY, QUEUE_PERMISSIONS, &attr)))
    {
        perror ("Server: mq_open (server)");
        exit (1);
    }

    ServerPW server_pw;
    bool connected_clients[MAX_NUMBER_CONNECTIONS];
    mqd_t client_mqs[MAX_NUMBER_CONNECTIONS];

    createAndEncryptNewPW(&server_pw);
    sendClientsEncryptedPW(&server_pw.encrypted_pw, connected_clients, client_mqs);
    
    while (true)
    {
        handleMsg(&server_pw, &server_mq, connected_clients, client_mqs);
    }
}