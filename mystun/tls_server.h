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
