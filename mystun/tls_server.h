/*
 * $Id: tls_server.h,v 1.2 2003/12/13 20:59:19 jiri Exp $
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
#ifndef _tls_server_h
#define _tls_server_h

#include "ip_addr.h"
#include "stun_types.h"

#ifdef USE_TLS

#define CFG_DIR "./"
#define TLS_PKEY_FILE CFG_DIR "cert.pem" 
#define TLS_CERT_FILE CFG_DIR "cert.pem"
#define TLS_CA_FILE 0 /* no CA list file by default */


enum tls_methods { TLS_USE_TLSv1, TLS_USE_SSLv2, TLS_USE_SSLv3,	TLS_USE_SSLv23 };


int init_tls();
int tls_init(struct socket_info *u);
int tls_destroy();

int tls_send(char *buffer,unsigned int len);
int tls_rcv_loop();

int receive_msg_over_tls(char *buf,unsigned int len,struct receive_info *ri);//TODO:
int send_msg_over_tls();//TODO
int respond_to_shared_secret_request(t_stun_message *msg);
#endif

#endif
