#ifndef __shm_h
#define __shm_h

#include <time.h>
#include "stun_types.h"

#define MAX_STRUCTS	200 //number of passwords we store in memory
#define EXPIRE		10*60 //a password expires after 10 minutes

typedef	struct
    {
	time_t expire; //the time when the entry expires = now+EXPIRE
	char username[USERNAME_LEN];
	char password[PASSWORD_LEN];
    }	shm_struct;


int init_shm(unsigned int count);
int destroy_shm();


int add_entry(shm_struct *);
int locate_entry(char *username,char **password);
int remove_old_entries(int *sleep_time);//removes expired entries, used by timer process
#endif
