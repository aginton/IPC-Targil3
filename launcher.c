#include <stdio.h>
#include <unistd.h>
#include <mqueue.h>
#include <stdbool.h>
#include <limits.h>
#include "utils.h"


typedef struct programParams
{
	int num_decrypters;
	unsigned int plain_pw_len;
	unsigned int key_len;
	int rounds_to_live;
} ProgramParams;



char* createPathToProgramString(char* path_to_program, char* program_name)
{
    char* res = malloc(strlen(path_to_program) + strlen(program_name)+1);
    ASSERT(NULL != res, "failed mallocing within createPathToProgramString");
    strcpy(res, path_to_program);
    strcat(res, program_name);
    res[strlen(path_to_program) + strlen(program_name)] = '\0';
    return res;
}


void launchServer()
{
    pid_t server_pid;
    char* path = NULL;
    
    path = createPathToProgramString(RELATIVE_PATH_TO_PROGRAMS, SERVER_PROGRAM_NAME);
	char *argv[] = {path, NULL};
	server_pid = vfork();
	if (server_pid == 0) 
	{
		execv(path, argv);
	}
    printf("[LAUNCHER]\tSpawned server process.\n");
}

void launchDecrypters(int num_of_decrypters, int rounds_to_live)
{
    printf("[LAUNCHER]\tEntered launchDecrypters(), given %d decrypters to spawn and with rounds_to_live=%d.\n", num_of_decrypters, rounds_to_live);
    pid_t decrypters_pid[num_of_decrypters];

    char rounds_to_live_str[11]; //max value is 4294967295, which is 10 chars
    snprintf(rounds_to_live_str, sizeof(rounds_to_live_str), "%d", rounds_to_live);
    
    for (int i = 0; i < num_of_decrypters; ++i)
    {
        char id_str[3];
        snprintf(id_str, sizeof(id_str), "%d", i);
        char* args[] = {DECRYPTER_PROGRAM_NAME, id_str, "-n", rounds_to_live_str, NULL};
        
        decrypters_pid[i] = vfork();
        if (decrypters_pid[i] == 0)
        {
            execv("./decrypter", args);
            printf("UH OH!!!\n");
            exit(1); //shouldn't get here
        }

        printf("[LAUNCHER]\tSpawned decrypter with the following args: {");
        for (int i = 0; i < 4; i++){
            printf("%s, ", args[i]);
        }
        printf("}\n");
    }
    printf("[LAUNCHER]\tFinished launchDecrypters().\n");
}

bool parseAndOutputNumOfDecrypters(int argc, char *argv[], int* out_num_of_decrypters)
{
    if (argc < 2)
    {
        return false;
    }

    int num_decrypters = atoi(argv[1]);
    if (0 == num_decrypters)
    {
        printf("Error parsing num_of_decrypters value.\n");
        return false;
    }
    *out_num_of_decrypters = num_decrypters;
    return true;
}



bool parseArguments(int argc, char *argv[], int* out_num_of_decrypters, int* out_rounds_to_live)
{
    bool has_valid_num_decrypters_arg = parseAndOutputNumOfDecrypters(argc, argv, out_num_of_decrypters);
    bool has_valid_rounds_to_live_arg = parseRoundsToLive(argc, argv, out_rounds_to_live);
        
    return has_valid_num_decrypters_arg && has_valid_rounds_to_live_arg;
}

int main(int argc, char *argv[])
{
    int num_of_decrypters = 0;
    int rounds_to_live = -1;

    if (!parseArguments(argc, argv, &num_of_decrypters, &rounds_to_live))
    {
        printf("[LAUNCHER]\tparseArguments returned false.\n");
        exit(1);
    }

    printf("[LAUNCHER]\tFinished parseArguments, found num_decrypters=%d and rounds_to_live=%d\n", num_of_decrypters, rounds_to_live);
    launchServer();
    launchDecrypters(num_of_decrypters, rounds_to_live);
    printf("[LAUNCHER]\tFinished spawning server and decrypters.\n");
    pause();
    return 0;
}