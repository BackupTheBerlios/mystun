#ifndef __server_h
#define __server_h

#include "stun_types.h"

int respond_to_msg(t_stun_message *msg);
int obtain_password(char *username,unsigned int ulen,char **password,unsigned int *plen);

#endif
