#ifndef __clientlib_h
#define __clientlib_h

#include "stun_types.h"

int send_rcv_msg_over_udp(t_stun_message *req,t_stun_message *response,struct socket_info *source,union sockaddr_union *dest);

typedef enum {OPEN_INTERNET=0,FIREWALL_BLOCK_UDP,SYMMETRIC_UDP_FIREWALL,FULL_CONE_NAT,SYMMETRIC_NAT,RESTRICTED_CONE_NAT,
	    RESTRICTED_PORT_CONE_NAT,BLOCKED,ERROR}	t_stun_nat_type;

//ntoh order
int test1(struct socket_info *si,union sockaddr_union *su,t_stun_changed_address *ca);
int test2(struct socket_info *si,union sockaddr_union *su);
int test3(struct socket_info *si,union sockaddr_union *su);


t_stun_nat_type determine_nat_type(struct socket_info *si,union sockaddr_union *su);
int determine_external_address(struct socket_info *si,union sockaddr_union *su,t_uint32 *addr,t_uint16 *port);
int determine_binding_time(struct socket_info *si,union sockaddr_union *su);
int binding_acquisition();

#endif
