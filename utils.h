#pragma once

#include "datastructs.h"

//#define PRINT_8_BYTE_BUFFER(name, buffer) printf(name " buffer=%d %d %d %d %d %d %d %d \n", buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7])


typedef enum rcsendMsg {
    SEND_MSG_SUCC = 0,
    REACHED_MAX_ATTEMPTS,
    UNKNOWN_ERR
} SEND_MSG_RC;



bool doesMQHaveMessages(mqd_t mqd);
long getNumOfMsgs(mqd_t* mqd_p);
void readMessage(mqd_t mqd, Msg* out_msg);
SEND_MSG_RC sendMsg(mqd_t mqd, Msg* mg_p, size_t msg_size, unsigned int prio);
bool tryToSendMsg(mqd_t mqd, Msg* mg_p, size_t msg_size, unsigned int prio);
void setMQAttrbs(long flags, long max_num_messages, long max_msg_size, long cur_num_msgs, struct mq_attr* out_attr_p);
bool isPWsMatch(PW* pw1_p, PW* pw2_p);
void createPrintablePW(PW *out_plain_pw);
char getPrintableChar();
bool isPrintable(char *str, unsigned int str_len);
bool parseRoundsToLive(int argc, char* argv[], int* out_rounds_to_live);
mqd_t openWriteOnlyMQ(char* mq_name, struct mq_attr* attr_p);
mqd_t openReadOnlyMQ(char* mq_name, struct mq_attr* attr_p);
