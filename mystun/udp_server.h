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
