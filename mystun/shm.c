#include "shm.h"
#include "common.h"
#include "stun_types.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <semaphore.h>

static int shm_id = -1;
static char *shm_addr = (char *)-1;
static unsigned int len = -1;
static sem_t*	sem = (sem_t *)-1;
static int *available = (int *)-1;
static shm_struct *vector = (shm_struct *)-1;
//lock

#define AVAILABLE_OFFSET	0 //offset for the available entries in memory
#define SEM_OFFSET	sizeof(int)	//offset for the semafore
#define VECTOR_OFFSET	sizeof(int)+sizeof(sem_t)	//actual start of entries

//we are creating a shared zone of memory to store username and passwords
int init_shm(unsigned int count)
{
    int size;
    
    count = MAX_STRUCTS;
    size =  VECTOR_OFFSET+count * sizeof(shm_struct);
    
    shm_id = shmget(IPC_PRIVATE,size,IPC_CREAT|IPC_EXCL|0700);
    if (shm_id == -1) 
	{
	    LOG("init_shm:error getting shm\n");
	    return -1;
	}
    shm_addr = shmat(shm_id,0,0);
    if (shm_addr == (char*)-1)
    {
	LOG("init_shm:cannot shmat\n");
	goto init_error1;
    }
    memset(shm_addr,0,size);
    len = count;
    available = (int *)(shm_addr+AVAILABLE_OFFSET);
    *available = count;
    sem = (sem_t *)(shm_addr+SEM_OFFSET);
    if (sem_init(sem,0,1) < 0)	
    {
	goto init_error2;
    }
    if (sem == (sem_t*)-1)
    {
	LOG("init_shm:sem init failed\n");
	goto init_error2;
    }
    vector = (shm_struct *)(shm_addr+VECTOR_OFFSET);
    LOG("init_shm:initialized a zone of %d size\n",size);
    return 1;
    
init_error1:
    if (shm_id != -1)	shmctl(shm_id,IPC_RMID,0);
    return -2;        
init_error2:
    if (shm_addr != (char *)-1) shmdt(shm_addr);
    if (shm_id != -1)	shmctl(shm_id,IPC_RMID,0);
    return -3;
}

int destroy_shm()
{
    if (sem != (sem_t *)-1)		sem_destroy(sem);
    if (shm_addr != (char *)-1) 	shmdt(shm_addr);
    if (shm_id != -1)			shmctl(shm_id,IPC_RMID,0);
    return 1;
}

//we add a new entry to the list
// should i check for pre existance?
int add_entry(shm_struct *entry)
{
    int i;
    
    sem_wait(sem);
    if (*available <= 0)
	{
	    LOG("add_entry:not enough memory to store password.increase shared memory\n");
	    sem_post(sem);
	    return -1;
	}
    for(i=0;i<len;i++)
    {
	if (vector[i].expire == 0)
	{
	    memcpy(vector[i].username,entry->username,USERNAME_LEN);
	    memcpy(vector[i].password,entry->password,PASSWORD_LEN);
	    vector[i].expire = time(0) + EXPIRE;
	}
    }
    *available = *available - 1;
    
    sem_post(sem);
    return 1;    
}

//returns a password for a given username
int locate_entry(char *username,char **password)
{
    int i;
    char *tmp;
    
    sem_wait(sem);
    if (*available <= 0)
	{
	    //no entries
	    sem_post(sem);
	    return -1;
	}
    for (i=0;i<len;i++)
	{
	    if (vector[i].expire > 0)//valid entry
	    {
		if ((vector[i].username[0] == username[0])&&(vector[i].username[1] == username[1]))//great probability
		{
		    if (memcmp(vector[i].username,username,USERNAME_LEN) == 0)
			{
			    //found it
			    tmp = NULL;
			    tmp = (char *)malloc(PASSWORD_LEN);
			    if (tmp == NULL)	
				{
				    sem_post(sem);
				    return -2;
				}
			    memcpy(tmp,vector[i].password,PASSWORD_LEN);
			    *password = tmp;
			    sem_post(sem);
			    return 1;
			}
		}
	    }
	}
    sem_post(sem);
    return -1;
}

int delete_entry_not_safe(int id)
{
    if (id >= len) return -1;
    vector[id].expire = 0;
    vector[id].username[0]=0;
    vector[id].password[0]=0;
    *available = *available + 1;
    return 1;
}

//from time to time it is called by timer
// it returns the time till the first entry expires
int remove_old_entries(int *sleep_time)
{
    time_t	minim;
    time_t	current;
    int i;
    
    sem_wait(sem);
    if (*available == len)
    {
	*sleep_time = -1;
	sem_post(sem);
	return -1;//empty vector of credentials
    }
    current = time(0);
    minim = (time_t)(-1);
    
    for(i=0;i<len;i++)
    {
	if (vector[i].expire > 0)//a valid entry
	{
	    if (vector[i].expire < current)	delete_entry_not_safe(i);//expired	    
	    else //find out the first entry which is going to expire, in order to sleep until then
		if (minim == (time_t)-1) minim = vector[i].expire;
		    else
			if(minim > vector[i].expire) minim = vector[i].expire;
	}
    }
    *sleep_time = (int)(minim-current);//we are going to wake after sleep_time seconds,no use waking before
    sem_post(sem);
    return 1;
}
