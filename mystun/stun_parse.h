#ifndef __parse_stun_h
#define __parse_stun_h

#include "ip_addr.h"
#include "stun_types.h"

//return value represents the number of bytes parsed
int parse_header(char *pos,unsigned int len,t_stun_header *header);
int parse_stun_change_request(char *pos,unsigned int len,t_stun_change_request *cr);
int parse_stun_message_integrity(char *pos,unsigned int len,t_stun_message_integrity *mi);
int parse_stun_username(char *pos,unsigned int len,t_stun_username *user);
int parse_stun_password(char *pos,unsigned int len,t_stun_password *pass);
//addresses are stored in host order
int parse_stun_address(char *pos,unsigned int len,void *address);
int parse_stun_error_code(char *pos,unsigned int len,t_stun_error_code *error);
int parse_stun_unknown_attributes(char *pos,unsigned int len,t_stun_unknown_attributes *ua);


int parse_body_binding_request(char *pos,unsigned int len,t_stun_message *msg);
int parse_body_binding_response(char *pos,unsigned int len,t_stun_message *msg);
int parse_body_binding_error_response(char *pos,unsigned int len,t_stun_message *msg);
int parse_body_shared_secret_request(char *pos,unsigned int len,t_stun_message *msg);//TODO
int parse_body_shared_secret_response(char *pos,unsigned int len,t_stun_message *msg);
int parse_body_shared_secret_error_response(char *pos,unsigned int len,t_stun_message *msg);
int parse_msg(int is_server,char *pos,unsigned int len,t_stun_message *msg);
#endif
