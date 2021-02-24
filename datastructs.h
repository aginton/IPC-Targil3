#pragma once

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <mqueue.h>

#define MAX_NUMBER_CONNECTIONS 100
#define MQ_MAX_MSGS         1
#define MQ_MAX_MSG_SIZE     100 		//Some big value(in bytes)
#define MQ_SERVER_NAME             "/server_mq"
#define DECRYPTER_MQ_BASE_NAME "/decrypter_mq_"
#define MAX_MQ_NAME_LEN 24
#define MAX_PW_LEN 64
#define PLAIN_PW_LEN 8
#define KEY_LEN (PLAIN_PW_LEN / 8)


#define DECRYPTER_PROGRAM_NAME "decrypter"
#define SERVER_PROGRAM_NAME "server"
#define RELATIVE_PATH_TO_PROGRAMS "./"   //assuming programs all in same directory for now

#define QUEUE_PERMISSIONS S_IRWXU | S_IRWXG   // TODO: Consider narrowing restrictions

#define ASSERT(expr, desc)                                                                \
    do                                                                                    \
    {                                                                                     \
        if (!(expr))                                                                      \
        {                                                                                 \
            printf("%s:%d assertion failed: (" #expr ") " desc "\n", __FILE__, __LINE__); \
            exit(1);                                                                      \
        }                                                                                 \
    } while (false)



// https://github.com/gavrielk/LinuxCourseCodePub/tree/master/ipc

typedef enum {
    CONNECT_REQUEST ,
    DISCONNECT_REQUEST,
    DECRYPTER_PW_GUESS,
    ENCRYPTER_ENCRYPTED_PW
} MSG_TYPE_E;

typedef struct msgStruct{
    MSG_TYPE_E msg_type;
    char data[];
} Msg;

typedef struct pw
{
	char pw_data[MAX_PW_LEN + 1];
    unsigned int pw_data_len;
    unsigned int pw_id;
} PW;

typedef struct key
{
    char key[8 + 1];
    unsigned int key_len;
    int dummy;
} Key;

typedef struct connectReq{
    unsigned int client_id;
    char mq_name[MAX_MQ_NAME_LEN + 1];
} ConnectReq;

typedef ConnectReq DisconnectReq;

typedef struct decrypterMsg{
    unsigned int client_id;
    PW decrypted_pw_guess;
} DecrypterMsg;

typedef struct encrypterMsg{
    PW encrypted_pw;
} EncrypterMsg;



