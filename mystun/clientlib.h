/*
 * Copyright (C) 2001-2003 iptel.org/FhG
 *
 * This file is part of ser, a free SIP server.
 *
 * ser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * For a license to use the ser software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * ser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
#ifndef __clientlib_h
#define __clientlib_h

#include "stun_types.h"



int send_rcv_msg_over_udp(t_stun_message *req,t_stun_message *response,struct socket_info *source,union sockaddr_union *dest);

typedef enum {OPEN_INTERNET=0,FIREWALL_BLOCK_UDP,SYMMETRIC_UDP_FIREWALL,FULL_CONE_NAT,SYMMETRIC_NAT,RESTRICTED_CONE_NAT,
	    RESTRICTED_PORT_CONE_NAT,BLOCKED,SERROR}	t_stun_nat_type;

//ntoh order
int test1(struct socket_info *si,union sockaddr_union *su,t_stun_message *msg);
int test2(struct socket_info *si,union sockaddr_union *su,t_stun_message *msg);
int test3(struct socket_info *si,union sockaddr_union *su,t_stun_message *msg);


t_stun_nat_type determine_nat_type(struct socket_info *si,union sockaddr_union *su);
int determine_external_address(struct socket_info *si,union sockaddr_union *su,t_uint32 *addr,t_uint16 *port);
int determine_binding_time(struct socket_info *si,union sockaddr_union *su);
int binding_acquisition();

#endif
