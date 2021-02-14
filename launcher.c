#include <stdio.h>
#include <unistd.h>
#include <mqueue.h>
#include <stdbool.h>
#include <limits.h>
#include "utils.h"


typedef struct programParams
{
	unsigned int num_decrypters;
	unsigned int plain_pw_len;
	unsigned int key_len;
	unsigned int rounds_to_live;
} ProgramParams;



char* launcher_str = "launcher";

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
    printf("[%s process %d]\t\tEntered launcherServer().\n", launcher_str, getpid());
    pid_t server_pid;
    char* path = NULL;
    
    path = createPathToProgramString(RELATIVE_PATH_TO_PROGRAMS, SERVER_PROGRAM_NAME);
	char *argv[] = {path, NULL};
	server_pid = vfork();
	if (server_pid == 0) 
	{
		execv(path, argv);
	}
    printf("[%s process %d]\t\tSpawned server process with pid=%d.\n", launcher_str, getpid(), server_pid);
    free(path); //only need to reclaim memory in parent process
    printf("[%s process %d]\t\tFinished launcherServer().\n", launcher_str, getpid());
}


void launchDecrypters(unsigned int num_of_decrypters, unsigned int rounds_to_live)
{
    printf("[%s process %d]\t\tEntered launchDecrypters(), given %d decrypters to spawn and with rounds_to_live=%u.\n", launcher_str, getpid(), num_of_decrypters, rounds_to_live);
    pid_t decrypters_pid[num_of_decrypters];

    char* decrypter_program_path = createPathToProgramString(RELATIVE_PATH_TO_PROGRAMS, DECRYPTER_PROGRAM_NAME);
    char rounds_to_live_str[11]; //max value is 4294967295, which is 10 chars
    snprintf(rounds_to_live_str, sizeof(rounds_to_live_str), "%u", rounds_to_live);  //https://stackoverflow.com/questions/49765045/how-to-pass-a-variable-via-exec
    printf("[%s process %d]\t\trounds_to_live_str=%s\n", launcher_str, getpid(), rounds_to_live_str);
    for (int i = 0; i < num_of_decrypters; ++i)
    {
        char id_str[3];
        snprintf(id_str, sizeof(id_str), "%d", i+1);
        char* args[] = {DECRYPTER_PROGRAM_NAME, id_str, "-n", rounds_to_live_str, NULL};
        printf("[%s process %d]\t\tAbout to exec using path %s\n", launcher_str, getpid(), decrypter_program_path);
        decrypters_pid[i] = vfork();
        if (decrypters_pid[i] == 0)
        {
            execv("./decrypter", args);
            printf("UH OH!!!\n");
            // execv(decrypter_program_path, args);
        }
        printf("[%s process %d]\t\tSpawned decrypter with pid=%d\n", launcher_str, getpid(), decrypters_pid[i]);
    }
    free(decrypter_program_path);
    printf("[%s process %d]\t\tFinished launchDecrypters().\n", launcher_str, getpid());
}

bool parseAndOutputNumOfDecrypters(int argc, char *argv[], unsigned int* out_num_of_decrypters)
{
    if (argc < 2)
    {
        return false;
    }

    unsigned int num_decrypters = atoi(argv[1]);
    if (0 == num_decrypters)
    {
        printf("Error parsing num_of_decrypters value.\n");
        return false;
    }
    *out_num_of_decrypters = num_decrypters;
    return true;
}



bool parseArguments(int argc, char *argv[], unsigned int* out_num_of_decrypters, unsigned int* out_rounds_to_live)
{
    // printf("%s - parseArguments received %d arguments.\n", launcher_str, argc);
    // for (int i = 0; i < argc; ++i)
    // {
    //     printf("launcher parseArguments: argv[%d] = %s.\n", i, argv[i]);
    // }

    bool has_valid_num_decrypters_arg = parseAndOutputNumOfDecrypters(argc, argv, out_num_of_decrypters);
    bool has_valid_rounds_to_live_arg = parseAndOutputRoundsToLive(argc, argv, out_rounds_to_live);
        
    return has_valid_num_decrypters_arg && has_valid_rounds_to_live_arg;
}

int main(int argc, char *argv[])
{
    
    unsigned int num_of_decrypters = 0;
    unsigned int rounds_to_live = UINT_MAX;

    if (!parseArguments(argc, argv, &num_of_decrypters, &rounds_to_live))
    {
        printf("[%s process %d]\t\tparseArguments returned false.\n", launcher_str, getpid());
        exit(1);
    }

    printf("[%s process %d]\t\tFinished parseArguments, found num_decrypters=%d and rounds_to_live=%u\n", launcher_str, getpid(), num_of_decrypters, rounds_to_live);
    launchServer();
    launchDecrypters(num_of_decrypters, rounds_to_live);
    printf("[%s process %d]\t\tFinished spawning server and decrypters.\n", launcher_str, getpid());
    pause();
    return 0;
}