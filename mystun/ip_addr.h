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
#ifndef ip_addr_h
#define ip_addr_h

#include <string.h>
#include <sys/types.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#else
#include <winsock2.h>
#include <stdlib.h>
#include <io.h>
#endif


#ifdef WIN32

typedef int socklen_t;
typedef SOCKET t_socket;

#define EWOULDBLOCK             WSAEWOULDBLOCK
#define EINPROGRESS             WSAEINPROGRESS
#define EALREADY                WSAEALREADY
#define ENOTSOCK                WSAENOTSOCK
#define EDESTADDRREQ            WSAEDESTADDRREQ
#define EMSGSIZE                WSAEMSGSIZE
#define EPROTOTYPE              WSAEPROTOTYPE
#define ENOPROTOOPT             WSAENOPROTOOPT
#define EPROTONOSUPPORT         WSAEPROTONOSUPPORT
#define ESOCKTNOSUPPORT         WSAESOCKTNOSUPPORT
#define EOPNOTSUPP              WSAEOPNOTSUPP
#define EPFNOSUPPORT            WSAEPFNOSUPPORT
#define EAFNOSUPPORT            WSAEAFNOSUPPORT
#define EADDRINUSE              WSAEADDRINUSE
#define EADDRNOTAVAIL           WSAEADDRNOTAVAIL
#define ENETDOWN                WSAENETDOWN
#define ENETUNREACH             WSAENETUNREACH
#define ENETRESET               WSAENETRESET
#define ECONNABORTED            WSAECONNABORTED
#define ECONNRESET              WSAECONNRESET
#define ENOBUFS                 WSAENOBUFS
#define EISCONN                 WSAEISCONN
#define ENOTCONN                WSAENOTCONN
#define ESHUTDOWN               WSAESHUTDOWN
#define ETOOMANYREFS            WSAETOOMANYREFS
#define ETIMEDOUT               WSAETIMEDOUT
#define ECONNREFUSED            WSAECONNREFUSED
#define ELOOP                   WSAELOOP
#define EHOSTDOWN               WSAEHOSTDOWN
#define EHOSTUNREACH            WSAEHOSTUNREACH
#define EPROCLIM                WSAEPROCLIM
#define EUSERS                  WSAEUSERS
#define EDQUOT                  WSAEDQUOT
#define ESTALE                  WSAESTALE
#define EREMOTE                 WSAEREMOTE


#endif

#include "common.h"
struct _str{
	char* s; /* null terminated string*/
	int len; /*string len*/
};

typedef struct _str str;


enum sip_protos { PROTO_NONE, PROTO_UDP, PROTO_TCP, PROTO_TLS, PROTO_SCTP };


struct ip_addr{
	unsigned int af; /* address family: AF_INET6 or AF_INET */
	unsigned int len;    /* address len, 16 or 4 */
	    
	/* 64 bits alligned address */
	union {
		unsigned long  addrl[16/sizeof(long)]; /* long format*/
		unsigned int   addr32[4];
		unsigned short addr16[8];
		unsigned char  addr[16];
	}u;
};



struct net{
	struct ip_addr ip;
	struct ip_addr mask;
};

union sockaddr_union{
		struct sockaddr     s;
		struct sockaddr_in  sin;
};


struct socket_info
{
#ifndef WIN32
	int socket;
#else 
	t_socket socket;
#endif

	str name; /* name - eg.: foo.bar or 10.0.0.1 */
	struct ip_addr address; /* ip address */
	str address_str;        /* ip address converted to string -- optimization*/
	unsigned short port_no;  /* port number */
//	str port_no_str; /* port number converted to string -- optimization*/
//	int is_ip; /* 1 if name is an ip address, 0 if not  -- optimization*/
	int is_lo; /* 1 if is a loopback, 0 if not */
	union sockaddr_union su; 
	int proto; /* tcp or udp*/    
    
};


struct receive_info{
	struct ip_addr src_ip;
	struct ip_addr dst_ip;
	unsigned short src_port; /* host byte order */
	unsigned short dst_port; /* host byte order */
	int proto;
//	int proto_reserved1; /* tcp stores the connection id here */
//	int proto_reserved2;
	union sockaddr_union src_su; /* usefull for replies*/
	struct socket_info* bind_address; /* sock_info structure on which 
									  the msg was received*/
	/* no need for dst_su yet */
};

/*
struct dest_info
{
	int proto;
	int proto_reserved1; // tcp stores the connection id here 
	union sockaddr_union to;
	struct socket_info* send_sock;
};
*/


/* len of the sockaddr */
#ifdef HAVE_SOCKADDR_SA_LEN
#define sockaddru_len(su)	((su).s.sa_len)
#else
#define sockaddru_len(su)	sizeof(struct sockaddr_in)
#endif /* HAVE_SOCKADDR_SA_LEN*/
	
/* inits an ip_addr with the addr. info from a hostent structure
 * ip = struct ip_addr*
 * he= struct hostent*
 */
#define hostent2ip_addr(ip, he, addr_no) \
	do{ \
		(ip)->af=(he)->h_addrtype; \
		(ip)->len=(he)->h_length;  \
		memcpy((ip)->u.addr, (he)->h_addr_list[(addr_no)], (ip)->len); \
	}while(0)
	



/* gets the protocol family corresponding to a specific address family
 * ( PF_INET - AF_INET, PF_INET6 - AF_INET6, af for others)
 */
#define AF2PF(af)   (((af)==AF_INET)?PF_INET:(af))




struct net* mk_net(struct ip_addr* ip, struct ip_addr* mask);
struct net* mk_net_bitlen(struct ip_addr* ip, unsigned int bitlen);

void print_ip(struct ip_addr* ip);
void stdout_print_ip(struct ip_addr* ip);
void print_net(struct net* net);




/* returns 1 if ip & net.mask == net.ip ; 0 otherwise & -1 on error 
	[ diff. adress fams ]) */
static 
#ifndef WIN32
inline 
#endif

int matchnet(struct ip_addr* ip, struct net* net)
{
	unsigned int r;
	int ret;
	
	ret=-1;
	if (ip->af == net->ip.af){
		for(r=0; r<ip->len/4; r++){ /* ipv4 & ipv6 addresses are
									   all multiple of 4*/
			if ((ip->u.addr32[r]&net->mask.u.addr32[r])!=
														 net->ip.u.addr32[r]){
				return 0;
			}
		}
		return 1;
	};
	return -1;
}




/* inits an ip_addr pointer from a sockaddr structure*/
static 
#ifndef WIN32
inline 
#endif

void sockaddr2ip_addr(struct ip_addr* ip, struct sockaddr* sa)
{
	switch(sa->sa_family){
	case AF_INET:
			ip->af=AF_INET;
			ip->len=4;
			memcpy(ip->u.addr, &((struct sockaddr_in*)sa)->sin_addr, 4);
			break;
	default:
			LOG("sockaddr2ip_addr: BUG: unknown address family %d\n",
					sa->sa_family);
	}
}



/* compare 2 ip_addrs (both args are pointers)*/
#define ip_addr_cmp(ip1, ip2) \
	(((ip1)->af==(ip2)->af)&& \
	 	(memcmp((ip1)->u.addr, (ip2)->u.addr, (ip1)->len)==0))



/* compare 2 sockaddr_unions */
static 
#ifndef WIN32
inline
#endif
int su_cmp(union sockaddr_union* s1, union sockaddr_union* s2)
{
	if (s1->s.sa_family!=s2->s.sa_family) return 0;
	switch(s1->s.sa_family){
		case AF_INET:
			return (s1->sin.sin_port==s2->sin.sin_port)&&
					(memcmp(&s1->sin.sin_addr, &s2->sin.sin_addr, 4)==0);
		default:
			LOG("su_cmp: BUG: unknown address family %d\n",
						s1->s.sa_family);
			return 0;
	}
}



/* gets the port number (host byte order) */
static 
#ifndef WIN32
inline 
#endif
short su_getport(union sockaddr_union* su)
{
	switch(su->s.sa_family){
		case AF_INET:
			return ntohs(su->sin.sin_port);
		default:
			LOG("su_get_port: BUG: unknown address family %d\n",
						su->s.sa_family);
			return 0;
	}
}



/* sets the port number (host byte order) */
static 
#ifndef WIN32
inline 
#endif
void su_setport(union sockaddr_union* su, unsigned short port)
{
	switch(su->s.sa_family){
		case AF_INET:
			su->sin.sin_port=htons(port);
			break;
		default:
			LOG("su_set_port: BUG: unknown address family %d\n",
						su->s.sa_family);
	}
}



/* inits an ip_addr pointer from a sockaddr_union ip address */
static 
#ifndef WIN32
inline 
#endif
void su2ip_addr(struct ip_addr* ip, union sockaddr_union* su)
{
	switch(su->s.sa_family){
	case AF_INET: 
					ip->af=AF_INET;
					ip->len=4;
					memcpy(ip->u.addr, &su->sin.sin_addr, 4);
					break;
	default:
					LOG("su2ip_addr: BUG: unknown address family %d\n",
							su->s.sa_family);
	}
}


/* ip_addr2su -> the same as init_su*/
#define ip_addr2su init_su

/* inits a struct sockaddr_union from a struct ip_addr and a port no 
 * returns 0 if ok, -1 on error (unknown address family)
 * the port number is in host byte order */
static 
#ifndef WIN32
inline 
#endif
int init_su( union sockaddr_union* su,
							struct ip_addr* ip,
							unsigned short   port ) 
{
	memset(su, 0, sizeof(union sockaddr_union));/*needed on freebsd*/
	su->s.sa_family=ip->af;
	switch(ip->af){
	case AF_INET:
		memcpy(&su->sin.sin_addr, ip->u.addr, ip->len);
		#ifdef HAVE_SOCKADDR_SA_LEN
			su->sin.sin_len=sizeof(struct sockaddr_in);
		#endif
		su->sin.sin_port=htons(port);
		break;
	default:
		LOG("init_ss: BUG: unknown address family %d\n", ip->af);
		return -1;
	}
	return 0;
}



/* inits a struct sockaddr_union from a struct hostent, an address index in
 * the hostent structure and a port no. (host byte order)
 * WARNING: no index overflow  checks!
 * returns 0 if ok, -1 on error (unknown address family) */
static 
#ifndef WIN32
inline
#endif
int hostent2su( union sockaddr_union* su,
								struct hostent* he,
								unsigned int idx,
								unsigned short   port ) 
{
	memset(su, 0, sizeof(union sockaddr_union)); /*needed on freebsd*/
	su->s.sa_family=he->h_addrtype;
	switch(he->h_addrtype){
	case AF_INET:
		memcpy(&su->sin.sin_addr, he->h_addr_list[idx], he->h_length);
		#ifdef HAVE_SOCKADDR_SA_LEN
			su->sin.sin_len=sizeof(struct sockaddr_in);
		#endif
		su->sin.sin_port=htons(port);
		break;
	default:
		LOG( "hostent2su: BUG: unknown address family %d\n", 
				he->h_addrtype);
		return -1;
	}
	return 0;
}



/* fast ip_addr -> string convertor;
 * it uses an internal buffer
 */
static 
#ifndef WIN32
inline 
#endif
char* ip_addr2a(struct ip_addr* ip)
{

	static char buff[40];/* 1234:5678:9012:3456:7890:1234:5678:9012\0 */
	int offset;
	register unsigned char a,b,c;
	int r;
	#define HEXDIG(x) (((x)>=10)?(x)-10+'A':(x)+'0')
	
	
	offset=0;
	switch(ip->af){
		case AF_INET:
			for(r=0;r<3;r++){
				a=ip->u.addr[r]/100;
				c=ip->u.addr[r]%10;
				b=ip->u.addr[r]%100/10;
				if (a){
					buff[offset]=a+'0';
					buff[offset+1]=b+'0';
					buff[offset+2]=c+'0';
					buff[offset+3]='.';
					offset+=4;
				}else if (b){
					buff[offset]=b+'0';
					buff[offset+1]=c+'0';
					buff[offset+2]='.';
					offset+=3;
				}else{
					buff[offset]=c+'0';
					buff[offset+1]='.';
					offset+=2;
				}
			}
			/* last number */
			a=ip->u.addr[r]/100;
			c=ip->u.addr[r]%10;
			b=ip->u.addr[r]%100/10;
			if (a){
				buff[offset]=a+'0';
				buff[offset+1]=b+'0';
				buff[offset+2]=c+'0';
				buff[offset+3]=0;
			}else if (b){
				buff[offset]=b+'0';
				buff[offset+1]=c+'0';
				buff[offset+2]=0;
			}else{
				buff[offset]=c+'0';
				buff[offset+1]=0;
			}
			break;
		
		default:
			LOG( "BUG: ip_addr2a: unknown address family %d\n",
					ip->af);
			return 0;
	}
	
	return buff;
}



/* converts an ip_addr structure to a hostent, returns pointer to internal
 * statical structure */
static 
#ifndef WIN32
inline 
#endif
struct hostent* ip_addr2he(str* name, struct ip_addr* ip)
{
	static struct hostent he;
	static char hostname[256];
	static char* p_aliases[1];
	static char* p_addr[2];
	static char address[16];
	
	p_aliases[0]=0; /* no aliases*/
	p_addr[1]=0; /* only one address*/
	p_addr[0]=address;
	strncpy(hostname, name->s, (name->len<256)?(name->len)+1:256);
	if (ip->len>16) return 0;
	memcpy(address, ip->u.addr, ip->len);
	
	he.h_addrtype=ip->af;
	he.h_length=ip->len;
	he.h_addr_list=p_addr;
	he.h_aliases=p_aliases;
	he.h_name=hostname;
	return &he;
}


/* 
 * Initialize socket_info entry by an IP(v4) address
 *
 * Returns 0 on success, -1 otherwise.
 */
static 
#ifndef WIN32
inline 
#endif
int ip2socket_info(struct socket_info *si, const char *ip)
{
    struct in_addr addr;

    if (inet_aton(ip, &addr) == 0) {
        LOG("Malformed IP address `%s'\n", ip);
        return -1;
    }

    si->name.len = strlen(ip);
    if ((si->name.s = strdup(ip)) == NULL) {
        LOG("Out of memory\n");
        return -1;
    };

    si->address.af = AF_INET;
    si->address.len = 4;
    memcpy(si->address.u.addr, &addr, sizeof(struct in_addr));

    return 0;
}


#endif /* !ip_addr_h */
