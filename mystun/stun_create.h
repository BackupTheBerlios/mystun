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
#ifndef __stun_create_h
#define __stun_create_h

#include "stun_types.h"

//we have to classes of functions
//1.create ... which fills up a structure
//2.format ... which from a structure constructs a char reprezentation, in order to be sent


//messages
int create_stun_binding_error_response(t_uint8 clas,t_uint8 number,char *reason,unsigned int reason_len,t_stun_message *msg,t_stun_message *req);
int format_stun_binding_error_response(t_stun_message	*msg);

int create_stun_binding_request(t_stun_message *msg);
int format_stun_binding_request(t_stun_message *msg);

int create_stun_binding_response(t_stun_message *msg,t_stun_message *req);
int format_stun_binding_response(t_stun_message *msg);


int create_stun_shared_secret_request(t_stun_message *msg);
int format_stun_shared_secret_request(t_stun_message *msg);

int create_stun_shared_secret_response(t_stun_message *req,t_stun_message *msg);
int format_stun_shared_secret_response(t_stun_message *msg);

int create_stun_shared_secret_error_response(t_uint8 clas,t_uint8 number,char *reason,unsigned int reason_len,t_stun_message *req,t_stun_message *msg);
int format_stun_shared_secret_error_response(t_stun_message *msg);

//attributes
int create_stun_header(t_uint16 msg_type,t_uint16 msg_len,t_uint128 tid,t_stun_header *header);
int format_stun_header(char *buf,unsigned int len,t_stun_header *header);


int create_stun_address(t_uint16 type,t_uint8 family,t_uint16 port,t_uint32 address,void *addr);
int format_stun_address(char *buf,unsigned int len,void *addr);

int create_stun_change_request(int change_ip,int change_port,t_stun_change_request *cr);
int format_stun_change_request(char *buf,unsigned int len,t_stun_change_request *cr);

int create_stun_unknown_attributes(t_uint16 *attributes,unsigned int len,t_stun_unknown_attributes *ua);
int format_stun_unknown_attributes(char *buf,unsigned int len,t_stun_unknown_attributes *ua);

int create_stun_error_code(t_uint8 clas,t_uint8 number,char *reason,unsigned int reason_len,t_stun_error_code *err);
int format_stun_error_code(char *buf,int len,t_stun_error_code *err);

int create_stun_message_integrity(char *msg,unsigned int len,char *key,unsigned int key_len,t_stun_message_integrity *mi);
int format_stun_message_integrity(char *buf,unsigned int len,t_stun_message_integrity *mi);

int create_stun_username(char *attr_value,unsigned int len,t_uint32 client_ip,t_uint16 port,t_stun_username *username);
int format_stun_username(char *buf,unsigned int len,t_stun_username *username);

int create_stun_password(char *attr_value,unsigned int len,t_stun_username *username,t_stun_password *password);
int format_stun_password(char *buf,unsigned int len,t_stun_password *password);
#endif

