/*
 * $Id: server.c,v 1.2 2003/12/13 20:59:19 jiri Exp $
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
