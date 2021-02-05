#include <stdio.h>
#include <unistd.h>
#include <mqueue.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

#include "include.h"
#include "utils.h"
#include "mta_crypt.h"
#include "mta_rand.h"


Msg* allocMsgStruct(unsigned int msg_size)
{
    Msg* msg = malloc(msg_size);
    ASSERT(msg != NULL, "inside allocMsgStruct - malloc(msg_size) returned NULL.");
    return msg;
}

void setMsgType(Msg* out_msg_p, MSG_TYPE_E msg_type)
{
    out_msg_p->msg_type = msg_type;
}



bool doesMQHaveMessages(mqd_t* qd_p)
{
    struct mq_attr attr;   // To store queue attributes
    mq_getattr (*qd_p, &attr);
    return (attr.mq_curmsgs > 0);
}

Msg* readMessage(mqd_t* qd_p)
{
    Msg* msg_p = allocMsgStruct(MQ_MAX_MSG_SIZE); // Allocate big size in advance
    ASSERT(msg_p != NULL, "inside readMessage, allocMsgStruct(MQ_MAX_MSG_SIZE) returned NULL");

    //TODO: Should this be a while loop? 
    if ((mq_receive (*qd_p, (char *)msg_p, MQ_MAX_MSG_SIZE, NULL)) == -1)
    {
        printf("Error with readMessage.\n");
    }

    return msg_p;
}









void createAndEncryptNewPW(EncryptedPWParams* out_key_and_pws)
{
    createPrintablePW(&(out_key_and_pws->plain_pw));
    MTA_get_rand_data(out_key_and_pws->key.key, out_key_and_pws->key.key_len);

    if (MTA_CRYPT_RET_OK != MTA_encrypt(
                                out_key_and_pws->key.key, 
                                out_key_and_pws->key.key_len, 
                                out_key_and_pws->plain_pw.pw_data, 
                                out_key_and_pws->plain_pw.pw_data_len, 
                                out_key_and_pws->encrypted_pw.pw_data, 
                                &(out_key_and_pws->encrypted_pw.pw_data_len)))
    {
        printf("An error occured with MTA_encrypt()...\n"); //TODO: Change message
        exit(-1);
    }
}

void createPrintablePW(PW *out_plain_pw)
{
    for (int i = 0; i < PW_LEN; ++i)
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



Msg* createMsg(MSG_TYPE_E type, void* src_data_ptr, size_t bytes_of_data_to_copy)
{
    Msg* msg_p = malloc(sizeof(Msg) + bytes_of_data_to_copy);
    ASSERT(msg_p != NULL, "inside createMsg(), malloc(sizeof(Msg) + bytes_of_data_to_copy returned NULL.");
    setMsgType(msg_p, type);
    memcpy(msg_p->data, src_data_ptr, bytes_of_data_to_copy);
    return msg_p;
}


bool isPWsMatch(PW* pw1_p, PW* pw2_p)
{
    if (pw1_p->pw_data_len != pw2_p->pw_data_len)
    {
        return false;
    }
    return (0 == strcmp(pw1_p->pw_data, pw2_p->pw_data));
}

SEND_MSG_RC sendMsg(mqd_t* mqd_p, Msg* mg_p, size_t msg_size, unsigned int prio)
{
    while (0 != mq_send (*mqd_p, (const char *)mg_p, msg_size, prio))
    {
        // The call failed.  Make sure errno is EAGAIN
        if (errno != EAGAIN) 
        { 
            //perror ("mq_receive()");
            printf("Error trying to send message (errno=%d).\n", errno);
            return UNKNOWN_ERR;
        }
    }
    return SEND_MSG_SUCC;
}

void setMQAttrbs(long flags, long max_num_messages, long max_msg_size, long cur_num_msgs, struct mq_attr* out_attr_p)
{
    ASSERT(out_attr_p != NULL, "inside setMQAttrbs(), out_attr_p cannot be NULL");
    out_attr_p->mq_flags = flags;
    out_attr_p->mq_maxmsg = max_num_messages;
    out_attr_p->mq_msgsize = max_msg_size;
    out_attr_p->mq_curmsgs = cur_num_msgs;
}


bool parseAndOutputRoundsToLive(int argc, char *argv[], unsigned int* out_rounds_to_live)
{
    if (argc == 2)
    {
        return true;
    }
    else if (argc == 4)
    {
        if (0 != strcmp("-n", argv[2]))
        {
            printf("Error: Arguments must be of form <num_of_decrypters> [-n rounds_to_live]\n");
            return false;
        }
        unsigned int rounds_to_live = atoi(argv[3]);
        if (0 == rounds_to_live)
        {
            printf("Error parsing rounds_to_live value.\n");
            return false;
        }
        *out_rounds_to_live = rounds_to_live;
        return true;
    }
    else
    {
        return false;
    }
}

long getNumOfMsgs(mqd_t* mqd_p)
{
    struct mq_attr mqAttr = {0};
    mq_getattr(*mqd_p, &mqAttr);
    return mqAttr.mq_curmsgs;
}

void printNumOfMsgsAtMQ(mqd_t* mqd_p, char* mq_name)
{
    printf("Currently there are %ld messages at mq %s\n", getNumOfMsgs(mqd_p), mq_name);
}

int openWriteOnlyMQ(char* mq_name)
{
    if (-1 == (server_mq = mq_open (MQ_SERVER_NAME, O_CREAT | O_WRONLY | O_NONBLOCK, QUEUE_PERMISSIONS, &attr)))
    {
        perror ("Server: mq_open (server)");
        exit (1);
    }
    return 
}

int openReadOnlyMQ(char* mq_name, bool unlink, )
{
    mq_unlink(MQ_SERVER_NAME);
    if (-1 == (server_mq = mq_open (MQ_SERVER_NAME, O_CREAT | O_RDONLY | O_NONBLOCK, QUEUE_PERMISSIONS, &attr)))
    {
        perror ("Server: mq_open (server)");
        exit (1);
    }
    return 
}
