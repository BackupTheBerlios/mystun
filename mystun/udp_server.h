#ifndef udp_server_h
#define udp_server_h

#include "ip_addr.h"
#include "stun_types.h"

#define MAX_RECV_BUFFER_SIZE	65*1024
#define BUFFER_INCREMENT	2048


int udp_init(struct socket_info* si);
int udp_send(struct socket_info* source,char *buf, unsigned len,union sockaddr_union*  to);
int udp_rcv_loop();

int receive_msg_over_udp(char* buf, unsigned int len, struct receive_info *ri);
int send_msg_over_udp(struct socket_info *source,t_stun_message *msg,union sockaddr_union *dest);
int respond_to_binding_request(t_stun_message *msg);

#endif
