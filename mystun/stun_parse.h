/*
 * $Id: stun_parse.h,v 1.2 2003/12/13 20:59:19 jiri Exp $
 *
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
