#include <stdio.h>
#include <unistd.h>
#include <mqueue.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "utils.h"

#include "mta_crypt.h"
#include "mta_rand.h"

#define MSG_SEND_TIMEOUT_S (1)



bool doesMQHaveMessages(mqd_t mqd)
{
    struct mq_attr attr;   // To store queue attributes
    mq_getattr (mqd, &attr);
    return (attr.mq_curmsgs > 0);
}

void readMessage(mqd_t mqd, Msg* out_msg)
{
    ASSERT(out_msg != NULL, "inside readMessage, out_msg cannot be NULL");

    if (-1 == mq_receive (mqd, (char *)out_msg, MQ_MAX_MSG_SIZE, NULL))
    {
        printf("Error with readMessage.\n");
        exit(1);
    }
}



void createPrintablePW(PW *out_plain_pw)
{
    for (int i = 0; i < out_plain_pw->pw_data_len; ++i)
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


bool isPWsMatch(PW* pw1_p, PW* pw2_p)
{
    if (pw1_p->pw_data_len != pw2_p->pw_data_len)
    {
        return false;
    }
    return (0 == strcmp(pw1_p->pw_data, pw2_p->pw_data));
}

SEND_MSG_RC sendMsg(mqd_t mqd, Msg* mg_p, size_t msg_size, unsigned int prio)
{
    while (0 != mq_send (mqd, (const char *)mg_p, msg_size, prio))
    {
        // The call failed.  Make sure errno is EAGAIN
        if (errno != EAGAIN) 
        { 
            printf("Error trying to send message (errno=%d).\n", errno);
            return UNKNOWN_ERR;
        }

        printf("send returned EAGAIN\n");
    }

    return SEND_MSG_SUCC;
}

bool tryToSendMsg(mqd_t mqd, Msg* mg_p, size_t msg_size, unsigned int prio)
{
    struct timespec timeout;        /* timeout value for the wait function */
    clock_gettime(CLOCK_MONOTONIC, &timeout);
    timeout.tv_sec += MSG_SEND_TIMEOUT_S;

    if (0 != mq_timedsend (mqd, (const char *)mg_p, msg_size, prio, &timeout))
    {
        if (errno != ETIMEDOUT) 
        { 
            printf("Message wasn't sent due to time out\n");
        }

        return false;
    }

    return true;
}

void setMQAttrbs(long flags, long max_num_messages, long max_msg_size, long cur_num_msgs, struct mq_attr* out_attr_p)
{
    ASSERT(out_attr_p != NULL, "inside setMQAttrbs(), out_attr_p cannot be NULL");
    out_attr_p->mq_flags = flags;
    out_attr_p->mq_maxmsg = max_num_messages;
    out_attr_p->mq_msgsize = max_msg_size;
    out_attr_p->mq_curmsgs = cur_num_msgs;
}

long getNumOfMsgs(mqd_t* mqd_p)
{
    struct mq_attr mqAttr = {0};
    mq_getattr(*mqd_p, &mqAttr);
    return mqAttr.mq_curmsgs;
}

mqd_t openWriteOnlyMQ(char* mq_name, struct mq_attr* attr_p)
{
    int mqd = mq_open(mq_name, O_CREAT | O_WRONLY , QUEUE_PERMISSIONS, attr_p);

    if (-1 == mqd)
    {
        perror ("openWriteOnlyMQ: mq_open ");
    }
    return mqd; 
}

mqd_t openReadOnlyMQ(char* mq_name, struct mq_attr* attr_p)
{
    int mqd = mq_open (mq_name, O_CREAT | O_RDONLY , QUEUE_PERMISSIONS, attr_p);

    if (-1 == mqd)
    {
        perror ("openReadOnlyMQ: mq_open ");
        exit (1);
    }
    return mqd;
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