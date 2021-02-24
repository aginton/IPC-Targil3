#pragma once

#include "datastructs.h"

#define PRINT_8_BYTE_BUFFER(name, buffer) printf(name " buffer=%d %d %d %d %d %d %d %d \n", buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7])


typedef enum rcsendMsg {
    SEND_MSG_SUCC = 0,
    REACHED_MAX_ATTEMPTS,
    UNKNOWN_ERR
} SEND_MSG_RC;



Msg* allocMsgStruct(unsigned int msg_size);
void setMsgType(Msg* out_msg_p, MSG_TYPE_E msg_type);
bool doesMQHaveMessages(mqd_t mqd);
void readMessage(mqd_t mqd, Msg* out_msg);
SEND_MSG_RC sendMsg(mqd_t mqd, Msg* mg_p, size_t msg_size, unsigned int prio);
bool tryToSendMsg(mqd_t mqd, Msg* mg_p, size_t msg_size, unsigned int prio);
void setMQAttrbs(long flags, long max_num_messages, long max_msg_size, long cur_num_msgs, struct mq_attr* out_attr_p);

bool isPWsMatch(PW* pw1_p, PW* pw2_p);
Msg* createMsg(MSG_TYPE_E type, void* src_data_ptr, size_t bytes_of_data_to_copy);


void createPrintablePW(PW *out_plain_pw);
char getPrintableChar();
bool isPrintable(char *str, unsigned int str_len);

// bool parseAndOutputRoundsToLive(int argc, char *argv[], unsigned int* out_rounds_to_live);
bool parseRoundsToLive(int argc, char* argv[], int* out_rounds_to_live);

long getNumOfMsgs(mqd_t* mqd_p);
//void printNumOfMsgsAtMQ(mqd_t* mqd_p, char* mq_name);
mqd_t openWriteOnlyMQ(char* mq_name, struct mq_attr* attr_p);
mqd_t openReadOnlyMQ(char* mq_name, struct mq_attr* attr_p);

void printPWDetails(PW* encrypted_pw_p);
void printKeyDetails(Key* key_p);
void printPWsAndKey(PW* encrypted_pw_p, PW* plain_pw_p, Key* key_p);
void debugMTADecrypt(PW* encrypted_pw_p, Key* key_p);