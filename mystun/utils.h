#ifndef __utils_h
#define __utils_h

#include <sys/types.h>
#include <unistd.h>

#define MAX_FD 32 //number of file descriptors we are going to close
#define MAX_LISTEN 16 //maximum number of listening addresses


//transform a process into a deamon
int daemonize();
//locate computer interfaces
int add_interfaces(char* if_name, int family, unsigned short port);

int compute_hmac(char* hmac,char* input, int length, const char* key, int sizeKey);
void to_hex(const char* buffer, int bufferSize, char* output);

#endif

