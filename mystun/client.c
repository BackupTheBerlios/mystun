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

#include "client.h"
#include "clientlib.h"
#include "common.h"
#include "ip_addr.h"
#include "globals.h"

#ifndef WIN32
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <syslog.h>

#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//#include <sys/mman.h>
#include <sys/stat.h>
#include <net/if.h>

#else
#include <winsock2.h>
#include <stdlib.h>
#include <io.h>

#endif
#include <string.h>

static char help[] = "\n\t-d address of STUN server \n"
"\t-p port of STUN server \n"
"\t-s source address of request\n"
"\t-P port of the request\n"
"\t-e show debug information\n"
"\t-v version and compile info\n"
"\t-h help message(this message)\n\n";
static t_uint16 default_destination_port = 3478;
static t_uint16 default_source_port = 50001;
static char *version = "0.0.2";
static char *compiled= __TIME__ " " __DATE__ ;
#define MAX_ADDRESS_LEN 255
char daddress[MAX_ADDRESS_LEN] = "127.0.0.1";
int sinterface = 1;

struct socket_info si;
union sockaddr_union su;

#define M_LISTEN 32
struct socket_info sock_info[M_LISTEN];
static int sock_number = 0;


/* add all family type addresses of interface if_name to the socket_info array
 * if if_name==0, adds all addresses on all interfaces
 * WARNING: it only works with ipv6 addresses on FreeBSD
 * return: -1 on error, 0 on success
 */

int client_add_interfaces(char* if_name, int family, unsigned short port)
{
#ifndef WIN32
	struct ifconf ifc;
	struct ifreq ifr;
	struct ifreq ifrcopy;
	char*  last;
	char* p;
	int size;
	int lastlen;
	int s;
	char* tmp;
	struct ip_addr addr;
	int ret;

#ifdef HAVE_SOCKADDR_SA_LEN
#ifndef MAX
#define MAX(a,b) ( ((a)>(b))?(a):(b))
#endif
#endif
	/* ipv4 or ipv6 only*/
	s=socket(family, SOCK_DGRAM, 0);
	ret=-1;
	lastlen=0;
	ifc.ifc_req=0;
	for (size=10; ; size*=2)
    {
		ifc.ifc_len=size*sizeof(struct ifreq);
		ifc.ifc_req=(struct ifreq*) malloc(size*sizeof(struct ifreq));
		if (ifc.ifc_req==0)
        {
			fprintf(stderr, "memory allocation failure\n");
			goto error;
		}
		if (ioctl(s, SIOCGIFCONF, &ifc)==-1)
        {
			if(errno==EBADF) return 0; /* invalid descriptor => no such ifs*/
			fprintf(stderr, "ioctl failed: %s\n", strerror(errno));
			goto error;
		}
		if  ((lastlen) && (ifc.ifc_len==lastlen)) break; /*success,  len not changed*/
		lastlen=ifc.ifc_len;
		/* try a bigger array*/
		free(ifc.ifc_req);
	}

	last=(char*)ifc.ifc_req+ifc.ifc_len;

	for(p=(char*)ifc.ifc_req; p<last;
       p+=(sizeof(ifr.ifr_name)+
#ifdef  HAVE_SOCKADDR_SA_LEN
        		MAX(ifr.ifr_addr.sa_len, sizeof(struct sockaddr))
#else
			(sizeof(struct sockaddr_in))
			/*	( (ifr.ifr_addr.sa_family==AF_INET)?sizeof(struct sockaddr_in):((ifr.ifr_addr.sa_family==AF_INET6)?sizeof(struct sockaddr_in6):sizeof(struct sockaddr)) ) */
#endif
				)
		)
	{
		/* copy contents into ifr structure
		 * warning: it might be longer (e.g. ipv6 address) */
		memcpy(&ifr, p, sizeof(ifr));
		if (ifr.ifr_addr.sa_family!=family)
        {
			printf("strange family %d skipping...\n",ifr.ifr_addr.sa_family);
			continue;
		}

		/*get flags*/
		ifrcopy=ifr;
		if (ioctl(s, SIOCGIFFLAGS,  &ifrcopy)!=-1)
		{ /* ignore errors */
			/* ignore down ifs only if listening on all of them*/
			if (if_name==0)
			{
				/* if if not up, skip it*/
				if (!(ifrcopy.ifr_flags & IFF_UP)) continue;
			}
		}



		if ((if_name==0)||(strncmp(if_name, ifr.ifr_name, sizeof(ifr.ifr_name))==0))
        {
			/* if (log_1) LOG("Trying to add an address %d\n",sock_number); */
				/*add address*/
			if (sock_number<M_LISTEN)
			{

				sockaddr2ip_addr(&addr,(struct sockaddr*)(p+(long)&((struct ifreq*)0)->ifr_addr));
				if ((tmp=ip_addr2a(&addr))==0) goto error;
				/* fill the strings*/
       			sock_info[sock_number].address = addr;
				sock_info[sock_number].name.s=(char*)malloc(strlen(tmp)+1);
				if(sock_info[sock_number].name.s==0)
            			{
					fprintf(stderr, "Out of memory.\n");
					goto error;
				}
				/* fill in the new name and port */
				sock_info[sock_number].name.len=strlen(tmp);
				strncpy(sock_info[sock_number].name.s, tmp,sock_info[sock_number].name.len+1);
				sock_info[sock_number].port_no=port;
				/* mark if loopback */
				if (ifrcopy.ifr_flags & IFF_LOOPBACK)
					sock_info[sock_number].is_lo=1;
				sock_number++;
				ret=0;
			}else
			{
				fprintf(stderr, "Too many addresses (max %d)\n", M_LISTEN);
				goto error;
			}
		}
			/*
			DBG("%s:\n", ifr.ifr_name);
			print_sockaddr(&(ifr.ifr_addr));
			DBG("        ");
			ls_ifflags(ifr.ifr_name, family, 0);
			DBG("\n");
            */
	}
	free(ifc.ifc_req); /*clean up*/
	close(s);
	return  ret;
error:
	if (ifc.ifc_req) free(ifc.ifc_req);
	close(s);
	return -1;
#else
	return -1;
#endif //WIN32
}


int  get_sending_socket()
{
#if defined(__linux__)
    int r;

    if (sock_number == 0)
    {
    if (client_add_interfaces(0,AF_INET,0) == -1) //ipv4 interfaces
        {
            if (log_1) LOG("error finding addresses\n");
            return -1;
        }
    //if (log_1) LOG("after general %d interfaces\n",sock_number);
    }

    for (r=0; r<sock_number;)
    {
		if (client_add_interfaces(sock_info[r].name.s, AF_INET,sock_info[r].port_no)!=-1)
	        {
			/* success => remove current entry (shift the entire array)*/
			free(sock_info[r].name.s);
			memmove(&sock_info[r], &sock_info[r+1],(sock_number-r)*sizeof(struct socket_info));
			sock_number --;
			continue;
		}
		r++;
	}
    if (log_1) LOG("Located %d interfaces \n",sock_number);
    for(r=0;r<sock_number;r++)
    {
	if (log_1) 
	{
	    LOG("    [%.*s] ", sock_info[r].name.len,sock_info[r].name.s);
    	    LOG("ip->");print_ip(&(sock_info[r].address));
    	    LOG("\n");
	}
    }


    if (log_1) LOG("Sending FROM:%.*s:%d\n",sock_info[sinterface].name.len,sock_info[sinterface].name.s,default_source_port);
    if (log_1) LOG("Sending TO:%s:%d\n",daddress,default_destination_port);

	if (sock_info[sinterface].is_lo) LOG("ERROR:Sending interface is loopback\n");
    sock_info[sinterface].port_no = default_source_port;

    return sinterface;
#else
	return -1;
#endif
}

#ifdef WIN32

int network_start()
{
   WORD wVersionRequested = MAKEWORD( 2, 2 );
   WSADATA wsaData;
   int err;

   err = WSAStartup( wVersionRequested, &wsaData );
   if ( err != 0 )
   {
      // could not find a usable WinSock DLL
      if (log_1) LOG("ERROR:Could not load winsock\n");
      return -1;
   }

   /* Confirm that the WinSock DLL supports 2.2.*/
   /* Note that if the DLL supports versions greater    */
   /* than 2.2 in addition to 2.2, it will still return */
   /* 2.2 in wVersion since that is the version we      */
   /* requested.                                        */

   if ( LOBYTE( wsaData.wVersion ) != 2 ||  HIBYTE( wsaData.wVersion ) != 2 )
   {
      /* Tell the user that we could not find a usable */
      /* WinSock DLL.                                  */
      WSACleanup( );
      if (log_1) LOG("ERROR:Bad winsock version:%d.%d\n",LOBYTE( wsaData.wVersion ),HIBYTE( wsaData.wVersion ));
      return -2;
   }

   return 1;
}
#endif

#if COMPILE_CLIENT
#ifndef WIN32
int linux_main(int argc, char **argv)
{
	int r;
	char *options;
	char *tmp;
	char c;
	t_stun_nat_type result;


	//printf("Argc:%d\n",argc);
	if (argc == 1)
	{
		printf("USAGE:%s\n",help);
		return 0;
	}
	
	log_1 = 0;
	options="i:d:p:P:vhe";

	while((c=getopt(argc,argv,options))!=-1)
	{
			switch(c)
			{
				case 'e':
							log_1 = 1;
							break;
				case 'i':
						tmp = 0;
						sinterface = strtol(optarg, &tmp, 10);
						if (tmp &&(*tmp))
						{
							fprintf(stderr, "bad interface number: -i [%s]\n", optarg);
							return 2;
						}

						break;
				case 'd':
						if (strlen(optarg) >= MAX_ADDRESS_LEN)
						{
							fprintf(stderr,"destination address to big.try a shorter address\n");
							return 1;
						}
						memset(daddress,0,MAX_ADDRESS_LEN);
						memcpy(daddress,optarg,strlen(optarg));

						break;
				case 'p':
						tmp = 0;
						default_destination_port = strtol(optarg, &tmp, 10);
						if (tmp &&(*tmp))
						{
							fprintf(stderr, "bad port number: -p [%s] %d\n", optarg,default_destination_port);
							return 2;
						}
						break;

				case 'P':
						tmp = 0;
						default_source_port = strtol(optarg, &tmp, 10);
						if (tmp &&(*tmp))
						{
							fprintf(stderr, "bad port number: -p [%s] %d\n", optarg,default_source_port);
							return 3;
						}
						break;

				case 'v':
						printf("version: %s\n", version);
               					printf("compiled: %s\n",compiled);
						return 0;
						break;

				case 'h':
						printf("%s",help);
						return 0;
						break;
/*
				case 'c':
	#ifdef USE_TLS
						tls_cert_file=optarg;
	#endif
						break;
				case 'k':
	#ifdef USE_TLS
						tls_pkey_file=optarg;
	#endif
						break;
*/
				case '?':
						if (isprint(optopt))
							fprintf(stderr, "Unknown option `-%c´.\n", optopt);
						else
							fprintf(stderr,"Unknown option character `\\x%x´.\n",optopt);
						return 4;
				case ':':
						fprintf(stderr,"Option `-%c´ requires an argument.\n",optopt);
						return 5;
				default:
						return 0;
			}
		}

	r = get_sending_socket();
	if (r < 0)
	{
	    if (log_1) LOG("Failed to obtain sending address\n");
	    return 7;
	}

	si = sock_info[r];

	struct sockaddr_in ia;

	ia.sin_family = AF_INET;

#if !defined(__linux__) && !defined(__solaris__)
	ia.sin_len = sizeof(*ia);
#endif
	ia.sin_port = htons(default_destination_port);

        if (inet_aton(daddress, &ia.sin_addr) == 0)
	{
#if !defined(__solaris__)
            struct hostent *he = NULL;

            he = gethostbyname2(daddress, ia.sin_family);
            if (he == NULL)
	    {
                if (log_1) LOG("ERROR:gethostbyname of %s failed", daddress);
            }
            bcopy(he->h_addr, &ia.sin_addr, he->h_length);
#else
	    if (log_1) LOG("ERROR:%s: invalid ip address", daddress);
#endif
	    if (he) free(he);
	}
	su.sin = ia;
	result = determine_nat_type(&si,&su);

	switch (result)
	{
		case OPEN_INTERNET:
			printf("Client seems to be on OPEN INTERNET\n");
			break;
		case FIREWALL_BLOCK_UDP:
			printf("Client seems to be behind a FIREWALL which BLOCKS UDP\n");
			break;
		case SYMMETRIC_UDP_FIREWALL:
			printf("Client seems to be behind a SYMMETRIC UDP FIREWALL\n");
			break;
		case FULL_CONE_NAT:
			printf("Client seems to be behind a FULL CONE NAT\n");
			break;
		case SYMMETRIC_NAT:
			printf("Client seems to be behind a SYMMETRIC NAT\n");
			break;
		case RESTRICTED_CONE_NAT:
			printf("Client seems to be behind a RESTRICTED CONE NAT\n");
			break;
		case RESTRICTED_PORT_CONE_NAT:
			printf("Client seems to be behind a RESTRICTED PORT CONE NAT\n");
			break;
		case BLOCKED:
			printf("Client seems to be BLOCKED(or perhaps the STUN server is not there?)\n");
			break;
		case SERROR:
			printf("ERROR detecting network status.\n");
			break;
		default:
			printf("Unknown return code ??.\n");
			return 6;
	}

        for(r=0;r<sock_number;r++)
        if (sock_info[r].name.s != NULL)
            free(sock_info[r].name.s);

	return 0;
}
#endif

#ifdef WIN32



int win_main(int argc, char **argv)
{

	struct hostent* localHost;
	char hostname[1024];
	int ret;
	char *tmp;
	t_stun_nat_type result;
    struct ip_addr ipad;
	struct hostent* h;
	t_uint32 ip;
	struct sockaddr_in ia;
	struct in_addr sin_addr;
	int mode;

	//printf("Argc:%d\n",argc);
	mode = 0;
	log_1 = 0;

	if (argc == 3)
	{
		mode = 1;//client [default address:port] server port [debug]
	}
	if (argc == 4)
	{
		mode = 2;//client [default address:port] server port debug
		log_1 = 1;
	}	
	if (argc == 5)
	{
		mode = 3;//client default address:port server port [debug]
		//printf("USAGE: client local_address port stun_server port\n");

	}
	if (argc == 6)
	{
		mode = 4;//client default address:port server port debug
		log_1 = 1;
	}
	if (mode == 0)
	{
		printf("\nUsage:\n\tclient [default_address default_port] server port [debug]");
		printf("        \n\tclient [default_address default_port] server port debug");
		printf("        \n\tclient default_address default_port server port [debug]");
		printf("        \n\tclient default_address default_port server port debug\n");
		printf("Version :%30s\n",version);
		printf("Compiled:%30s\n",compiled);
		
		return 0;
	}

	/* printf("Using mode %d\n",mode);*/
	tmp = 0;
	if ((mode == 1)||(mode == 2)) default_destination_port = strtol(argv[2], &tmp, 10);
	else 
		if ((mode == 3)||(mode == 4)) default_destination_port = strtol(argv[4], &tmp, 10);

	if (tmp &&(*tmp))
		{
			fprintf(stderr, "bad port number: -p [%s] %d\n", argv[4],default_destination_port);
			return 2;
		}

	if ((mode == 1) || (mode == 2))	default_source_port = 0;
		else
			if ((mode == 3)||(mode == 4)) default_source_port = strtol(argv[2], &tmp, 10);
	if (tmp &&(*tmp))
		{
			fprintf(stderr, "bad port number: -p [%s] %d\n", argv[2],default_destination_port);
			return 2;
		}

	if (network_start()<0)
	{
		if (log_1) LOG("ERROR:Unable to start network services\n");
		return 9;
	}

	ret = gethostname((char *)hostname,1022);
	if (log_1) 
	{
		if (ret < 0) LOG("ERROR:gethostname\n");
		else LOG("HOSTNAME:%s\n",hostname);
	}
	localHost = NULL;
	localHost = gethostbyname(0);//gethostname((char *)hostname,1022)

	if (localHost == NULL)
	{
		if (log_1) LOG("ERROR:gethostbyname\n");
		return 21;
	}
	/*
	if (WSAGetLastError() != 0)
	{
	  if (log_1) 
	  {
		  LOG("gethostname error.code is %d:",WSAGetLastError());
		  DisplayErrorText(WSAGetLastError());
		  LOG("\n");
	  }
	  return 21;
	}
	*/
	//if (log_1) LOG("Running on %s\n",hostname);
	if (localHost->h_length != sizeof(t_uint32))
	{
		if (log_1) LOG("ERROR:you are not using IPv4 !?\n");
		return 22;
	}
	
	memcpy(&ip,localHost->h_addr_list[0],4);
	/* windows does not put the loopback address in here so it's sure a good address */
	if (ip == 0)
	{
		if (log_1) LOG("ERROR:you do not seem to have a network connection !\n");
	}
	if (log_1) LOG("Detected IP is %X\n",ip);
/*	
    if ( isdigit( argv[1][0] ) )
	{
		ip = inet_addr(argv[1]);		
	    //ip = ntohl( ip );
	}
	else
	{
	   h = gethostbyname( argv[1] );
	   if ( h == NULL )
	   {
		   if (log_1) LOG("ERROR:Cannot resolve host name\n");
		   return 11;
	   }
	   else
	   {
		   sin_addr = *(struct in_addr*)h->h_addr;
		   ip = ( sin_addr.s_addr );
	   }
	  }

*/
	/*if (log_1) LOG("Sending from ip %X\n",ip);*/

	ipad.af=AF_INET;
	ipad.len=4;
	memcpy(&(ipad.u.addr),&ip,4);

	si.address = ipad;
	si.port_no = default_source_port;
	
	/* obtaining the destination address */
	if ((mode == 1)||(mode == 2)) ret = 1;
		else 
		if ((mode == 3)||(mode == 4)) ret = 3;
    if ( isdigit( argv[ret][0] ) )
	{
		ip = inet_addr(argv[ret]);		
	    //ip = ntohl( ip );
	}
	else
	{
	   h = gethostbyname( argv[ret] );
	   if ( h == NULL )
	   {
		   if (log_1) LOG("ERROR:Cannot resolve host name\n");
		   return 11;
	   }
	   else
	   {
		   sin_addr = *(struct in_addr*)h->h_addr;
		   ip = ( sin_addr.s_addr );
	   }
	  }
	
	/*if (log_1) LOG("Sending to ip %x\n",ip);*/

	memcpy(&ia.sin_addr,&ip,4);
	ia.sin_port = htons(default_destination_port);
	ia.sin_family = AF_INET;
#if !defined(__linux__) && !defined(__solaris__) && !defined(WIN32)
	ia.sin_len = sizeof(*ia);
#endif

	su.sin = ia;

    if (log_1) LOG("Sending TO:%s:%d\n",argv[ret],default_destination_port);
    //if (log_1) LOG("Sending FROM:%s:%d\n",argv[1],default_destination_port);


	result = determine_nat_type(&si,&su);

	switch (result)
	{
		case OPEN_INTERNET:
			printf("Client seems to be on OPEN INTERNET\n");
			break;
		case FIREWALL_BLOCK_UDP:
			printf("Client seems to be behind a FIREWALL which BLOCKS UDP\n");
			break;
		case SYMMETRIC_UDP_FIREWALL:
			printf("Client seems to be behind a SYMMETRIC UDP FIREWALL\n");
			break;
		case FULL_CONE_NAT:
			printf("Client seems to be behind a FULL CONE NAT\n");
			break;
		case SYMMETRIC_NAT:
			printf("Client seems to be behind a SYMMETRIC NAT\n");
			break;
		case RESTRICTED_CONE_NAT:
			printf("Client seems to be behind a RESTRICTED CONE NAT\n");
			break;
		case RESTRICTED_PORT_CONE_NAT:
			printf("Client seems to be behind a PORT RESTRICTED CONE NAT\n");
			break;
		case BLOCKED:
			printf("Client seems to be BLOCKED(or perhaps the STUN server is not there?)\n");
			break;
		case SERROR:
			printf("ERROR detecting network status.\n");
			break;
		default:
			printf("Unknown return code ??.\n");
			return 6;
	}

	return 0;
}

#endif 
int main(int argc, char **argv)
{
#ifndef WIN32
	return linux_main(argc,argv);
#else
	return win_main(argc,argv);
#endif

}

#endif
