/*
 * $Id: clientlib.c,v 1.5 2003/12/19 01:15:18 gabriel Exp $
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
#include "clientlib.h"
#include "stun_create.h"
#include "stun_parse.h"
#include "globals.h"
#include "udp_server.h"
#ifndef WIN32
#include <unistd.h>
#endif

#define MAX_SEND_RETRIES 9

//sendinf and waiting for a response on UDP
int send_rcv_msg_over_udp(t_stun_message *req,t_stun_message *response,struct socket_info *source,union sockaddr_union *dest)
{
    int retries;
    int rcv_retries;
    int read_retries;
    struct timeval tv;
    fd_set fdSet; 
    int fdSetSize;
    int err;
    union sockaddr_union from;
    unsigned int fromlen;
    unsigned int len;
    char buf [BUF_SIZE+1];
    long time_now ;
    long time_max;

    
    retries = 0;
    rcv_retries = 0;
    FD_ZERO(&fdSet); 
    fdSetSize=0;
    FD_SET(source->socket,&fdSet); 
    fdSetSize = source->socket+1;
    tv.tv_sec=0;
    time_max  =4000*1000; //4s
    time_now  =1000*1000; //1s
    tv.tv_usec=time_now; // 1 s 

    //we try several times in case of failure
send_again:
    if (send_msg_over_udp(source,req,dest) < 0)
	{
	    retries ++;
	    if (retries < MAX_SEND_RETRIES) goto send_again;
	    else
		{
		    LOG("send_rcv_msg_over_udp:unable to send message\n"); 
		    return -1;//unable to send
		}
	}
    retries = 0;
//waiting for a response-after receiving one, i should wait for 10 seconds-page 17 bottom
//if it's an error or has a different mapped address, i should discard it,it's an attack
//but 10 seconds it too much

//page 16, we should retransmit starting with 100ms and doubling it until 1.6s,
      tv.tv_usec = time_now;
#ifdef WIN32
	  /* for some reason the fdSet is destroyed on an exit from select on win32 ??? */
    FD_ZERO(&fdSet); 
    fdSetSize=0;
    FD_SET(source->socket,&fdSet); 
    fdSetSize = source->socket+1;

#endif
      err = select(fdSetSize, &fdSet, NULL, NULL, &tv);
      if (err < 0)
        {
	    LOG("send_rcv_msg_over_udp:error in select\n");
#ifdef WIN32
		goto jumphere;
#endif
	    goto send_again;
	}
      else 
        if (err == 0) /* timeout */
	    {
		LOG("send_rcv_msg_over_udp:no response in %ld ms.maybe if doubling...\n",time_now);
		if (time_now < time_max) time_now *= 2;
		else rcv_retries ++;
		if (rcv_retries == 3)
		    {
			LOG("send_rcv_msg_over_udp:giving up\n");
			return -2;
		    }
		else goto send_again;
	    }
    //we have something to read
    else if (FD_ISSET(source->socket,&fdSet))
    {
	rcv_retries = 0;
	memset(&from, 0 , sizeof(union sockaddr_union));
	fromlen=sockaddru_len(si->su);
	read_retries = 0;
read_again:	
#ifdef WIN32
jumphere:
	//sleep(4);
#endif
	len=recvfrom(source->socket, buf, BUF_SIZE, 0, &from.s,&fromlen);
	if (len==-1)
		{
			LOG("send_rcv_msg_over_udp:recvfrom:[%d] %s\n",errno, strerror(errno));

#ifndef WIN32
			if ((errno==EINTR)||(errno==EAGAIN)||(errno==EWOULDBLOCK)||(errno==ECONNREFUSED))
			{
#else
			
			LOG("ERROR code is %d:%s\n",WSAGetLastError(),DisplayErrorText(WSAGetLastError()));
			if ((errno == ENOTSOCK)||(errno == ECONNREFUSED))
			{
				
				if (errno == ENOTSOCK) LOG("ERROR: we do not send from a socket ??\n");
				if (errno == ECONNREFUSED) LOG("ERROR: connection refused\n");
#endif
			
			
			    read_retries ++;
			    if (read_retries < 3)	goto read_again; 
			    else return -3;
			}
			else
			{
				LOG("ERROR:strange error on send_rcv_msg_over_udp %d\n",errno);
				return -4;
			}
			

		}
	buf[len]=0; 

	if (len%4!=0)
	    LOG("Message length is not modulo 4!!!!!\n");
        if ((err=parse_msg(0,buf,len,response)) < 0)
	{    
	    LOG("send_rcv_msg_over_udp:error parsing message of %d len return %d\n",len,err);
    	    return -5;
	}
	if (memcmp(&(req->header.tid.bytes),&(response->header.tid.bytes),16) != 0)
	{
	    LOG("send_rcv_msg_over_udp:unespected response.id-s differ:%x\n",response->header.msg_type);
	    return -6;	
	}
	//TODO:teoretically we should jump to rcv_again with a timeout of 10 seconds and if we receive
	//something different than it's an attack.but then we are going to loose very much client time
    }

    return 1;	
}

/*
int get_sock(t_uint32 address,t_uint16 port)
{
    int sock;
     struct sockaddr_in addr;
    
    sock= socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
   if ( sock < 0 )
   {
      LOG("Could not create a UDP socket:");
      return -1;
   }
    
   memset((char*) &(addr),0, sizeof((addr)));
   addr.sin_family = AF_INET;
   if (address == 0)
       addr.sin_addr.s_addr = htonl(INADDR_ANY);
    else  addr.sin_addr.s_addr = address;
   addr.sin_port = port;
    
   
   if ( bind( sock,(struct sockaddr*)&addr, sizeof(addr)) != 0 )
   {
      int e = errno;
        
      switch (e)
      {
         case EADDRINUSE:
         {
            LOG( "Port %d for receiving UDP is in use",port);
            return -2;
         }
         case EADDRNOTAVAIL:
         {
            LOG("Cannot assign requested address");;
            return -3;
         }
         default:
         {
	    LOG("Could not bind UDP receive port. Error=%s",strerror(e));
            return -4;
         }
      }
   }

    return sock;
}
*/

#define NO_RESPONSE 	0
#define IP_SAME		1
#define IP_NOT_SAME	2

int test1(struct socket_info *source,union sockaddr_union *dest,t_stun_changed_address *ca)
{
    t_stun_message binding_request;
    t_stun_message response;
    t_uint32	naddress;
    int err;

    //i should request an username and password
    LOG("NOTICE:Starting TEST1\n");    
    //we create a  STUN Binding request
    if (create_stun_binding_request(&binding_request) < 0)
    {
	LOG("test_1:unable to create message\n");
	return -1;
    }
    
    err = send_rcv_msg_over_udp(&binding_request,&response,source,dest);
/*    
    if (err < 0) //try again
	err = send_rcv_msg_over_udp(&binding_request,&response,source,dest);	
    if (err < 0) //try again
	err = send_rcv_msg_over_udp(&binding_request,&response,source,dest);
*/	
    if (err < 0)
	{
	    if (err == -2)	//no response
		{
		    LOG("test1:no response\n");
		    return NO_RESPONSE;
		}
		else return err;
	}
    
    if (response.header.msg_type != MSG_TYPE_BINDING_RESPONSE)
    {
	LOG("test1:unespected response:%x\n",response.header.msg_type);
	return -6;
    }
    
    if (ca != NULL) memcpy(ca,&(response.u.resp.changed_address),sizeof(t_stun_changed_address));
    //i compare with the response from mapped_address.if == it's not  nat and go to test 2
    
    naddress = htonl(response.u.resp.mapped_address.address);
    LOG("NOTICE:TEST1 finished\n");
	if (htons(response.u.resp.mapped_address.port) == source->su.sin.sin_port)
	{
		printf( "---------------------------------------\n"
				"Acording to test1 NAT does NOT change port.\n"
				"Port before NAT is %d Port after NAT is %d\n"
				"---------------------------------------\n",ntohs(source->su.sin.sin_port),response.u.resp.mapped_address.port);
	}
	else
	{
		printf( "---------------------------------------\n"
				"Acording to test1 NAT does change port.\n"
				"Port before NAT is %d Port after NAT is %d\n"
				"---------------------------------------\n",ntohs(source->su.sin.sin_port),response.u.resp.mapped_address.port);

	}

    if ((htons(response.u.resp.mapped_address.port) == source->su.sin.sin_port)
	&&
	(memcmp(&(naddress),&(source->su.sin.sin_addr),4) == 0))
	return IP_SAME;
	else return IP_NOT_SAME;
}


int test2(struct socket_info *source,union sockaddr_union *dest)
{
    t_stun_message binding_request;
    t_stun_change_request cr;
    t_stun_message response;
    t_uint32 		naddress;
    int err;
    
    LOG("NOTICE:Starting TEST2\n");
    if (create_stun_binding_request(&binding_request) < 0)
    {
	LOG("test2:unable to create message\n");
	return -1;
    }
    if (create_stun_change_request(1,1,&cr) < 0)
    {
	return -2;
    }
    binding_request.u.req.change_request = cr;
    binding_request.u.req.is_change_request = 1;

    err = send_rcv_msg_over_udp(&binding_request,&response,source,dest);
/*    
    if (err < 0) //try again
	err = send_rcv_msg_over_udp(&binding_request,&response,source,dest);
    if (err < 0) //try again
	err = send_rcv_msg_over_udp(&binding_request,&response,source,dest);
*/	
    if (err < 0)
	{
	    if (err == -2)	//no response
		{
		    LOG("test2:no response\n");
		    return NO_RESPONSE;
		}
	}
    
    if (response.header.msg_type != MSG_TYPE_BINDING_RESPONSE)
    {
	LOG("test2:unespected response:%x\n",response.header.msg_type);
	return -6;
    }
    naddress = htonl(response.u.resp.mapped_address.address);
    LOG("NOTICE:TEST2 finished\n");
	if (htons(response.u.resp.mapped_address.port) == source->su.sin.sin_port)
	{
		printf( "---------------------------------------\n"
				"Acording to test2 NAT does NOT change port.\n"
				"Port before NAT is %d Port after NAT is %d\n"
				"---------------------------------------\n",ntohs(source->su.sin.sin_port),response.u.resp.mapped_address.port);
	}
	else
	{
		printf( "---------------------------------------\n"
				"Acording to test2 NAT does change port.\n"
				"Port before NAT is %d Port after NAT is %d\n"
				"---------------------------------------\n",ntohs(source->su.sin.sin_port),response.u.resp.mapped_address.port);

	}

    if ((htons(response.u.resp.mapped_address.port) == source->su.sin.sin_port)
	&&
	(memcmp(&(naddress),&(source->su.sin.sin_addr),4) == 0))
	return IP_SAME;
	else return IP_NOT_SAME;
}

/* not tested yet, I did not find such a nat */
int test3(struct socket_info *source,union sockaddr_union *dest)
{
    t_stun_message binding_request;
    t_stun_change_request cr;
    t_stun_message response;
    t_uint32	naddress;
    int err;
    
    //creez si trimit un STUN Binding request
    LOG("NOTICE:Starting TEST3\n");
    if (create_stun_binding_request(&binding_request) < 0)
    {
	LOG("test3:unable to create message\n");
	return -1;
    }
    if (create_stun_change_request(0,1,&cr) < 0)
    {
	return -2;
    }
    binding_request.u.req.change_request = cr;
    binding_request.u.req.is_change_request = 1;
    
    err = send_rcv_msg_over_udp(&binding_request,&response,source,dest);
/*    
    if (err < 0) //try again
	err = send_rcv_msg_over_udp(&binding_request,&response,source,dest);
    if (err < 0) //try again
	err = send_rcv_msg_over_udp(&binding_request,&response,source,dest);
*/	
    if (err < 0)
	{
	    if (err == -2)	//no response
		{
		    LOG("test3:no response\n");
		    return NO_RESPONSE;
		}
	}

    if (response.header.msg_type != MSG_TYPE_BINDING_RESPONSE)
    {
	LOG("test3:unespected response:%x\n",response.header.msg_type);
	return -6;
    }
    LOG("NOTICE:TEST3 finished\n");
	if (htons(response.u.resp.mapped_address.port) == source->su.sin.sin_port)
	{
		printf( "---------------------------------------\n"
				"Acording to test3 NAT does NOT change port.\n"
				"Port before NAT is %d Port after NAT is %d\n"
				"---------------------------------------\n",ntohs(source->su.sin.sin_port),response.u.resp.mapped_address.port);
	}
	else
	{
		printf( "---------------------------------------\n"
				"Acording to test3 NAT does change port.\n"
				"Port before NAT is %d Port after NAT is %d\n"
				"---------------------------------------\n",ntohs(source->su.sin.sin_port),response.u.resp.mapped_address.port);

	}

    naddress = htonl(response.u.resp.mapped_address.address);
    if ((htons(response.u.resp.mapped_address.port) == source->su.sin.sin_port)
	&&
	(memcmp(&(naddress),&(source->su.sin.sin_addr),4) == 0))
	return IP_SAME;
	else return IP_NOT_SAME;
}


t_stun_nat_type determine_nat_type(struct socket_info *si,union sockaddr_union *su)
{
    int res1,res2,res3;
    t_stun_changed_address ca;
    union sockaddr_union  nsu;
    t_uint32 addr;
    struct ip_addr ip;  
#ifdef WIN32
	struct sockaddr_in ia;
#endif	
    
    if (udp_init(si) < 0) goto error;
    res1 = test1(si,su,&ca);
    if (res1 < 0) goto error;
    if (res1 == NO_RESPONSE) return BLOCKED;
    
    res2 = test2(si,su);
    if (res2 < 0) goto error;
    
    if (res1 == IP_SAME)
	{
	    if (res2 == NO_RESPONSE)	return SYMMETRIC_UDP_FIREWALL;
		else return OPEN_INTERNET;
	}
    else //res1 ==IP_NOT_SAME
	{
	    if (res2 == NO_RESPONSE)	
		{
			addr = htonl(ca.address);
		    memset(&ip,0,sizeof(struct ip_addr));
		    ip.af = AF_INET;
		    memcpy(&(ip.u.addr),&addr,4);

#ifndef WIN32
	    	
		    init_su(&nsu,&ip,ca.port);
#else
			memcpy(&ia.sin_addr,&addr,4);
			ia.sin_port = htons(ca.port);
			ia.sin_family = AF_INET;
			nsu.sin = ia;
#endif
		    LOG("NOTICE:Now sending to :port:%d address:",ca.port);print_ip(&ip);LOG("\n");
		    /*
		    memcpy(&(nsu.sin.sin_addr),&(addr),4);
		    nsu.sin.sin_port = htons(ca.port);
		    */
		    res1 = test1(si,&nsu,0);//we send to CHANGED_ADDRESS received in  test1
		    if (res1 < 0) goto error;
		    
		    if (res1 == IP_SAME) 
			{
			    res3 = test3(si,su);
			    if (res3 < 0) goto error;
			    if (res3 == NO_RESPONSE) return RESTRICTED_PORT_CONE_NAT;
			    else return RESTRICTED_CONE_NAT;
			}
		    else return SYMMETRIC_NAT;
		} 
		else	return FULL_CONE_NAT;
	}
error:
    if (si->socket>0) close(si->socket);	
    return SERROR;    
}

int determine_external_address(struct socket_info *source,union sockaddr_union *su,t_uint32 *addr,t_uint16 *port)
{
    t_stun_message binding_request;
    t_stun_message response;
    int err;

    if (udp_init(source) < 0)
	return -1;    
    
    if (create_stun_binding_request(&binding_request) < 0)
    {
	LOG("test_1:unable to create message\n");
	return -1;
    }
    err = send_rcv_msg_over_udp(&binding_request,&response,source,su);

/*    
    if (err < 0) //try again
	err = send_rcv_msg_over_udp(&binding_request,&response,source,su);
    if (err < 0) //try again
	err = send_rcv_msg_over_udp(&binding_request,&response,source,su);
*/	
    if (err < 0)
	{
	    if (err == -2)	//no response
		{
		    LOG("test1:no response\n");
		    close(source->socket);
		    return NO_RESPONSE;
		}
	}
    
    if (response.header.msg_type != MSG_TYPE_BINDING_RESPONSE)
    {
	LOG("test1:unespected response:%x\n",response.header.msg_type);
	return -6;
    }
    
    *port = response.u.resp.mapped_address.port;
    *addr = response.u.resp.mapped_address.address;
    close(source->socket);    
    return 1;	
}

int determine_binding_time(struct socket_info *si,union sockaddr_union *su)
{
    return 0;
}
