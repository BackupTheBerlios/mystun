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
#ifndef __globals_h
#define __globals_h

#define BUF_SIZE 65535
#define TIMER_RESOLUTION 60 //resolution for timer process in seconds

#ifndef WIN32
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

extern int log_1;
extern int sock_no;
extern struct socket_info sock_info[];
extern int children_no;
extern int default_port;
extern int dont_fork;
extern int log_stderr;
extern char* version;
extern char* pid_file;
extern char* working_dir;
extern char* chroot_dir;
extern char* user;
extern char* group;
//extern FILE *f;

extern struct socket_info *bind_address;
extern struct socket_info *alternate_address;
extern struct socket_info *bind_address_port;
extern struct socket_info *alternate_address_port;


#ifdef USE_TLS
#define MAX_PROCESSES 6 //4 , 1 for each socket and a tls server+timer
#else 
#define MAX_PROCESSES 4
#endif
#define THREADS_PER_SOCKET	1


extern unsigned int maxbuffer;//for udp_
extern char *	username_hmac_key;
extern char *	another_private_key;



//TLS
#ifdef USE_TLS
extern int tls_log;
extern int tls_method;

extern int tls_verify_cert;
extern int tls_require_cert;
extern char* tls_cert_file;
extern char* tls_pkey_file;
extern char* tls_ca_file;

extern SSL_CTX *default_ctx;
struct socket_info *tls_bind_address;
#endif
#endif
