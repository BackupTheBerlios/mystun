#include "server.h"
#include "shm.h"
#include "tls_server.h"
#include "udp_server.h"

int respond_to_msg(t_stun_message *msg)
{
    int ret;
    
    if (msg == NULL)	return -1;
    
    switch(msg->header.msg_type)
    {
	case(MSG_TYPE_BINDING_REQUEST):
	    {
		ret = respond_to_binding_request(msg);
		break;
	    }
#ifdef USE_TLS            
	case(MSG_TYPE_SHARED_SECRET_REQUEST):
	    {
		ret = respond_to_shared_secret_request(msg);	
		break;
	    }
#endif
	default:
	    {
		return -2;	
	    }
    }
    
    if (ret < 0) return -3;
    return 1;
}

int obtain_password(char *username,unsigned int ulen,char **password,unsigned int *plen)
{
#ifdef USE_TLS
    char *tmp;
    
    *plen = 0;
    *password = NULL;
    if (ulen != USERNAME_LEN)	return -1;
    //we get the password from the shared memory
    if (locate_entry(username,&tmp) < 0) return -2;
    *plen = PASSWORD_LEN;
    *password = tmp;    
    return 1;
#else
    return -2;
#endif
}
