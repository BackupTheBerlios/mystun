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
#include "tls_server.h"
#include "globals.h"
#include "stun_types.h"
#include "stun_parse.h"

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "stun_create.h"
#include "server.h"

#ifdef USE_TLS

#if OPENSSL_VERSION_NUMBER < 0x00906000L  /* 0.9.6*/
#error "OpenSSL 0.9.6 or greater required"
/* it might work ok with older versions (I think
 *  >= 0.9.4 should be ok), but I didn't test them
 *  so try them at your own risk :-) -- andrei
 */
#endif


/* global tls related data */
SSL_CTX* default_ctx=0 ; /* global ssl context */

int tls_log=0; /* tls log level */
int tls_method=TLS_USE_TLSv1; /* tls default method */
int tls_verify_cert=0; /* verify the  certificates */
int tls_require_cert=0; /* require client certificate */
char* tls_pkey_file=0; /* private key file name */
char* tls_cert_file=0; /* certificate file name */
char* tls_ca_file=0;   /* CA list file name */



int tcp_init(struct socket_info* sock_info)
{
	union sockaddr_union* addr;
	int optval;
#ifdef DISABLE_NAGLE
	int flag;
	struct protoent* pe;

	if (tcp_proto_no==-1){ /* if not already set */
		pe=getprotobyname("tcp");
		if (pe==0){
			LOG( "ERROR: tcp_init: could not get TCP protocol number\n");
			tcp_proto_no=-1;
		}else{
			tcp_proto_no=pe->p_proto;
		}
	}
#endif
	
	addr=&sock_info->su;
	sock_info->proto=PROTO_TCP;
	if (init_su(addr, &sock_info->address, sock_info->port_no)<0){
		LOG( "ERROR: tcp_init: could no init sockaddr_union\n");
		goto error;
	}
	sock_info->socket=socket(AF2PF(addr->s.sa_family), SOCK_STREAM, 0);
	if (sock_info->socket==-1){
		LOG( "ERROR: tcp_init: socket: %s\n", strerror(errno));
		goto error;
	}
#ifdef DISABLE_NAGLE
	flag=1;
	if ( (tcp_proto_no!=-1) &&
		 (setsockopt(sock_info->socket, tcp_proto_no , TCP_NODELAY,
					 &flag, sizeof(flag))<0) ){
		LOG( "ERROR: tcp_init: could not disable Nagle: %s\n",
				strerror(errno));
	}
#endif


#if  !defined(TCP_DONT_REUSEADDR) 
	/* Stevens, "Network Programming", Section 7.5, "Generic Socket
     * Options": "...server started,..a child continues..on existing
	 * connection..listening server is restarted...call to bind fails
	 * ... ALL TCP servers should specify the SO_REUSEADDRE option 
	 * to allow the server to be restarted in this situation
	 *
	 * Indeed, without this option, the server can't restart.
	 *   -jiri
	 */
	optval=1;
	if (setsockopt(sock_info->socket, SOL_SOCKET, SO_REUSEADDR,
				(void*)&optval, sizeof(optval))==-1) {
		LOG( "ERROR: tcp_init: setsockopt %s\n",
			strerror(errno));
		goto error;
	}
#endif
	/* tos */
	optval=IPTOS_LOWDELAY;
	if (setsockopt(sock_info->socket, IPPROTO_IP, IP_TOS, (void*)&optval, 
				sizeof(optval)) ==-1){
		LOGL(L_WARN, "WARNING: tcp_init: setsockopt tos: %s\n", strerror(errno));
		/* continue since this is not critical */
	}
	if (bind(sock_info->socket, &addr->s, sockaddru_len(*addr))==-1)
	{
		/*
		LOGL( "ERROR: tcp_init: bind(%x, %p, %d) on %s: %s\n",
				sock_info->socket, &addr->s, 
				sockaddru_len(*addr),
				sock_info->address_str.s,strerror(errno));
		*/
		goto error;
	}
	if (listen(sock_info->socket, 10)==-1)
	{
		/*    
		LOGL( "ERROR: tcp_init: listen(%x, %p, %d) on %s: %s\n",
				sock_info->socket, &addr->s, 
				sockaddru_len(*addr),
				sock_info->address_str.s,
				strerror(errno));
		*/
		goto error;
	}
	
	return 0;
error:
	if (sock_info->socket!=-1){
		close(sock_info->socket);
		sock_info->socket=-1;
	}
	return -1;
}

int tls_init(struct socket_info *sock_info)
{
    int ret;
    if ((ret=tcp_init(sock_info))!=0){
		LOG("ERROR: tls_init: tcp_init failed on  %.*s:%d\n", sock_info->address_str.len,sock_info->address_str.s, sock_info->port_no);
		return ret;
	}
    sock_info->proto=PROTO_TLS;
	/* tls specific stuff */

    return 1;
}

int tls_destroy()
{
    if(default_ctx)
	{
		LOG("destroy_tls...\n");
		SSL_CTX_free(default_ctx);
		ERR_free_strings();
		default_ctx=0; 
	}

    return 1;
}

/* inits ser tls support
 * returns 0 on success, <0 on error */
int init_tls()
{

	
	/* default values */
	if (tls_pkey_file==0)
		tls_pkey_file=TLS_PKEY_FILE;
	if (tls_cert_file==0)
		tls_cert_file=TLS_CERT_FILE;
	if (tls_ca_file==0)
		tls_ca_file=TLS_CA_FILE;
	
	DBG("[%d]initializing openssl...\n",getpid());
	/* init mem. alloc. for libcrypt & openssl */
	CRYPTO_set_mem_functions(malloc, realloc,free);
	
	/* init the openssl library */
	SSL_load_error_strings(); /* readable error messages*/
	/* seed the PRNG, nothing on linux because openssl should automatically
	   use /dev/urandom, see RAND_seed, RAND_add */
	SSL_library_init();  /* don't use shm_ for SSL_library_init() */
	
	/* create the ssl context */
	DBG("[%d]creating the ssl context...\n",getpid());
	/* hack 42: get all the methods to properly initialize the corresponding
	 * structures before a fork 
	 * this is to work arround a bug in openssl SSLv*_*_method() which
	 * returns a pointer to a local static variable, which is initialized
	 * only the first time the function is run => if we reinitialize
	 * ssl->method from one process (e.g.: sslv23_accept + sslv3) and
	 * we try to SSL_free(ssl) from another process on which the 
	 * corresponding method was not initialized (ssl->method will
	 * point to an uninitialized static var.) => seg. fault in openssl*/
	SSLv23_method();
	SSLv23_client_method();
	SSLv23_server_method();
	SSLv2_method();
	SSLv2_client_method();
	SSLv2_server_method();
	SSLv3_method();
	SSLv3_client_method();
	SSLv3_server_method();
	TLSv1_method();
	TLSv1_client_method();
	TLSv1_server_method();
	
	switch(tls_method){
		case TLS_USE_SSLv23:
			default_ctx=SSL_CTX_new(SSLv23_method());
			break;
		case TLS_USE_SSLv2:
			default_ctx=SSL_CTX_new(SSLv2_method());
			break;
		case TLS_USE_SSLv3:
			default_ctx=SSL_CTX_new(SSLv3_method());
			break;
		case TLS_USE_TLSv1:
			default_ctx=SSL_CTX_new(TLSv1_method());
			break;
		default:
			LOG( "ERROR: tls_init: unknown tls method %d,"
						" using TLSv1\n", tls_method);
			default_ctx=SSL_CTX_new(TLSv1_method());
	}
	if (default_ctx==0){
		LOG( "init_tls: failed to create ssl context\n");
		goto error;
	}
#ifdef EXTRA_DEBUG
	DBG("init_tls: ctx->method=%p\n", default_ctx->method);
	DBG("init_tls: ctx->method->ssl_free=%p\n", default_ctx->method->ssl_free);
#endif
	/* no passwd: */
	 /* SSL_CTX_set_default_passwd_cb(ctx, callback); */
	
	/* disable session cache */
	SSL_CTX_set_session_cache_mode(default_ctx, SSL_SESS_CACHE_OFF);
		
	/* set options, e.g SSL_OP_NO_SSLv2, 
	 * SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
	 */
	SSL_CTX_set_options(default_ctx, SSL_OP_ALL);
	/*
	 SSL_CTX_set_options(default_ctx, SSL_OP_NO_SSLv2 |
			 				SSL_OP_ALL); */
	/*FIXME: all workarrounfs enabled */
	
	/* mode, e.g. SSL_MODE_ENABLE_PARTIAL_WRITE,
	 * SSL_MODE_AUTO_RETRY */
	/* SSL_CTX_set_mode(ctx, mode); */
	
	/* using certificates (we don't allow anonymous ciphers => at least
	 * the server must have a cert)*/
	/* private key */
	if (SSL_CTX_use_PrivateKey_file(default_ctx, tls_pkey_file,
				SSL_FILETYPE_PEM)!=1){
		LOG( "init_tls: failed to load private key from \"%s\"\n",
				tls_pkey_file);
		goto error_certs;
	}
	if (SSL_CTX_use_certificate_chain_file(default_ctx, tls_cert_file)!=1){
		/* better than *_use_certificate_file 
		 * see SSL_CTX_use_certificate(3)/Notes */
		LOG( "init_tls: failed to load certificate from \"%s\"\n",
					tls_cert_file);
		goto error_certs;
	}
	/* check if private key corresponds to the loaded ceritficate */
	if (SSL_CTX_check_private_key(default_ctx)!=1){
		LOG( "init_tls: private key \"%s\" does not match the"
				" certificate file \"%s\"\n", tls_pkey_file, tls_cert_file);
		goto error_certs;
	}
	
	/* set session id context, usefull for reusing stored sessions */
	/*
	if (SSL_CTX_set_session_id_context(ctx, version, version_len)!=1){
		LOG(L_CRIT, "init_tls: failed to set session id\n");
		goto error;
	}
	*/
	
	/* set cert. verifications options */
	/* verify peer if it has a cert (to fail for no cert. add 
	 *  | SSL_VERIFY_FAIL_IF_NO_PEER_CERT ); forces the server to send
	 *  a client certificate request */
	SSL_CTX_set_verify(default_ctx, 
			(tls_verify_cert)?(	SSL_VERIFY_PEER | ( (tls_require_cert)?
								SSL_VERIFY_FAIL_IF_NO_PEER_CERT:0 ))
							:SSL_VERIFY_NONE, 0);
	/* SSL_CTX_set_verify_depth(ctx, 2);  -- default 9 */
	/* CA locations, list */
	if (tls_ca_file && (*tls_ca_file)){
		if (SSL_CTX_load_verify_locations(default_ctx, tls_ca_file, 0 )!=1){
			/* we don't support ca path, we load them only from files */
			LOG( "init_tls: error while processing CA locations\n");
			goto error_certs;
		}
		SSL_CTX_set_client_CA_list(default_ctx, 
									SSL_load_client_CA_file(tls_ca_file));
		if (SSL_CTX_get_client_CA_list(default_ctx)==0){
			LOG( "init_tls: error setting client CA list from <%s>\n",
						tls_ca_file);
			goto error_certs;
		}
	}
	
	/* DH tmp key generation -- see DSA_generate_parameters,
	 * SSL_CTX_set_tmp_dh, SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE */
	
	/* RSA tmp key generation => we don't care, we won't accept 
	 * connection to export restricted applications and tls does not
	 * allow a tmp key in another sitaution */
	
	return 1;
error_certs:
	/*
	SSL_CTX_free(ctx);
	ctx=0;
	*/
error:
	//tls_dump_errors("tls_init:");
	return -1;
}

int tls_rcv_loop()
{
    t_uint16 *tmp;
    int sd;
    socklen_t	slen;
    SSL	*ssl;
    int err;
    int bytes_read,n,len;
    char *pos;
    union sockaddr_union from;
    struct timeval tv;
//inainte sau dupa accept?
     fd_set fdSet; 
     int fdSetSize;

    
#ifdef DYN_BUF
	char* buf;
#else
	static char buf [BUF_SIZE+1];
#endif
    struct receive_info ri;
    
    //while(1) pause();
    ri.bind_address=bind_address; /* this will not change, we do it only once*/
    ri.dst_port=bind_address->port_no;
    ri.dst_ip=bind_address->address;
    ri.proto=PROTO_UDP;
    //ri.proto_reserved1=ri.proto_reserved2=0;

    for(;;)
    {
#ifdef DYN_BUF
		buf=malloc(BUF_SIZE+1);
		if (buf==0){
			LOGL(L_ERR, "ERROR: udp_rcv_loop: could not allocate receive buffer\n");
			goto error;
		}
#endif
		LOG("tls_rcv_loop:%d\n",getpid());
    		
		slen = sizeof(from);
		sd = accept(tls_bind_address->socket,&(from.s),&slen);
		LOG ("Connection from %lx, port %x\n",from.sin.sin_addr.s_addr, ntohs(from.sin.sin_port));
		ssl = SSL_new(default_ctx);
		SSL_set_fd(ssl,sd);
		if (SSL_accept(ssl) < 0) 
		    {
			LOG("tls_rcv_loop:cannot accept ssl\n");
			close(sd);
			continue;
		    }
		LOG ("SSL connection using %s\n", SSL_get_cipher (ssl));
    //we do not check client certificate
      pos = buf;
      bytes_read = 0;
    // we need protection against those who send fragments, over a long time, and keep the connecion occupied.perhaps a fork was better
    // to handle incomings
      FD_ZERO(&fdSet); fdSetSize=0;
      FD_SET(sd,&fdSet); 
      fdSetSize = sd+1;
      tv.tv_sec=0;
      tv.tv_usec=200*1000; // 200 ms 

	//should i create a list of conexions?
gagain:
    
        //we wait until a connection arrives
      err = select(fdSetSize, &fdSet, NULL, NULL, &tv);
      if (err < 0)
        {
	    LOG("tls_rcv_loop:error in select\n");
	    close(sd);    
	    continue;
	}
      else 
        if (err == 0)
	    {
		LOG("tls_rcv_loop:no response in 200ms.aborting\n");
		close(sd);    
		continue;
	    }
    else if (FD_ISSET(sd,&fdSet))
    {
		//we received something
		memcpy(&(ri.src_su),&from,sizeof(union sockaddr_union));
		su2ip_addr(&ri.src_ip, &from);
		ri.src_port=su_getport(&from);

		n = SSL_read(ssl,pos,BUF_SIZE-bytes_read);
		bytes_read += n;
		pos = buf+bytes_read;
		if (bytes_read > STUN_HEADER_LEN) 
		    {
			tmp = (t_uint16 *)(buf+2);
			len = ntohs(*tmp);
			if (bytes_read >= STUN_HEADER_LEN+len)
			    {
				//now we have an entire STUN message
				receive_msg_over_tls(buf,len,&ri);	
				
			    }
		    }
		else goto gagain;
    }
    }	
}

//TODO:
int receive_msg_over_tls(char *buf,unsigned int len,struct receive_info *ri)
{
    int SERVER=1;
    t_stun_message	msg;
    int ret;
    
    LOG("receive_msg_over_tls:message received on pid:%d from ",getpid());
    print_ip(&ri->src_ip);
    LOG(":%u\n",ri->src_port);
    memset(&msg,0,sizeof(t_stun_message));
    msg.buff_len = len;
    msg.pos = NULL;
    msg.len = 0;
    msg.src = ri->src_su;
    msg.original_src = ri->src_su;
    msg.dst = bind_address->su;//bind_address
    if (len%4!=0)
	LOG("Message length is not modulo  4!!!!!\n");
    if ((ret=parse_msg(SERVER,buf,len,&msg)) < 0)
    {
	LOG("receive_msg_over_udp:error parsing message\n");
	return -1;
    }
    //we have parsed a message and now we respond.it should be a shared_secret_request
    if ((ret = respond_to_msg(&msg)) < 0)
    {
	LOG("receive_msg_over_udp:error responding to message\n");
	return -2;
    }

    return 1;
}

/* NOT IMPLEMENTED YET */
int respond_to_shared_secret_request(t_stun_message *msg)
{
    t_stun_message		resp;
    struct socket_info 		*addr;
    int ret;
    //sent on  TLS
    if (create_stun_shared_secret_response(msg,&resp)<0) return -1;
    //TODO:
    //ret = tls_send(addr,(char *)resp.buff,resp.buff_len,&msg->src);    
    return 1;
}

#endif
