#ifndef __globals_h
#define __globals_h

#define BUF_SIZE 65535
#define TIMER_RESOLUTION 60 //resolution for timer process in seconds

#include <openssl/ssl.h>
#include <openssl/err.h>


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
