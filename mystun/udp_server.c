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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#else
#include <winsock2.h>
#include <stdlib.h>
#include <io.h>
#include "utils.h"
#endif




#include <errno.h>

#ifdef __linux__
	#include <linux/types.h>
	#include <linux/errqueue.h>
#endif

#include <sys/types.h>

#include "udp_server.h"
#include "globals.h"
#include "stun_parse.h"
#include "ip_addr.h"
#include "stun_create.h"
#include "server.h"


int probe_max_receive_buffer( int udp_sock )
{
	int optval;
	int ioptval;
	unsigned int ioptvallen;
	int foptval;
	unsigned int foptvallen;
	int voptval;
	unsigned int voptvallen;
	int phase=0;

	/* jku: try to increase buffer size as much as we can */
	ioptvallen=sizeof(ioptval);
	if (getsockopt( udp_sock, SOL_SOCKET, SO_RCVBUF, (void*) &ioptval,&ioptvallen) == -1 )
	{
		if (log_1) LOG("ERROR: udp_init: getsockopt: %s\n", strerror(errno));
		return -1;
	}
	if ( ioptval==0 ) 
	{
		if (log_1) LOG("DEBUG: udp_init: SO_RCVBUF initialy set to 0; resetting to %d\n",BUFFER_INCREMENT );
		ioptval=BUFFER_INCREMENT;
	} else 
	    //LOGL(L_INFO, "INFO: udp_init: SO_RCVBUF is initially %d\n", ioptval );
	for (optval=ioptval; ;  ) 
        {
		/* increase size; double in initial phase, add linearly later */
		if (phase==0) optval <<= 1; else optval+=BUFFER_INCREMENT;
		if (optval > maxbuffer){
			if (phase==1) break; 
			else { phase=1; optval >>=1; continue; }
		}
		//LOGL(L_DBG, "DEBUG: udp_init: trying SO_RCVBUF: %d\n", optval );
		if (setsockopt( udp_sock, SOL_SOCKET, SO_RCVBUF,(void*)&optval, sizeof(optval)) ==-1){
			/* Solaris returns -1 if asked size too big; Linux ignores */
			//LOGL(L_DBG, "DEBUG: udp_init: SOL_SOCKET failed for %d, phase %d: %s\n", optval, phase, strerror(errno));
			/* if setting buffer size failed and still in the aggressive
			   phase, try less agressively; otherwise give up 
			*/
			if (phase==0) { phase=1; optval >>=1 ; continue; } 
			else break;
		} 
		/* verify if change has taken effect */
		/* Linux note -- otherwise I would never know that; funny thing: Linux
		   doubles size for which we asked in setsockopt
		*/
		voptvallen=sizeof(voptval);
		if (getsockopt( udp_sock, SOL_SOCKET, SO_RCVBUF, (void*) &voptval,
		    &voptvallen) == -1 )
		{
			if (log_1) LOG("ERROR: udp_init: getsockopt: %s\n", strerror(errno));
			return -1;
		} else {
			//LOGL(L_DBG, "DEBUG: setting SO_RCVBUF; set=%d,verify=%d\n", optval, voptval);
			if (voptval<optval) 
			{
				//LOGL(L_DBG, "DEBUG: setting SO_RCVBUF has no effect\n");
				/* if setting buffer size failed and still in the aggressive
				phase, try less agressively; otherwise give up 
				*/
				if (phase==0) { phase=1; optval >>=1 ; continue; } 
				else break;
			} 
		}
	
	} /* for ... */
	foptvallen=sizeof(foptval);
	if (getsockopt( udp_sock, SOL_SOCKET, SO_RCVBUF, (void*) &foptval,
		    &foptvallen) == -1 )
	{
		//LOGL(L_ERR, "ERROR: udp_init: getsockopt: %s\n", strerror(errno));
		return -1;
	}
	//LOGL(L_INFO, "INFO: udp_init: SO_RCVBUF is finally %d\n", foptval );

	return 0;

	/* EoJKU */
}

int udp_init(struct socket_info* sock_info)
{
	union sockaddr_union* addr;
	int optval;
//#ifdef WIN32
	struct sockaddr_in sa;
	int sa_len;
//#endif
    


	//if (log_1) LOG("sizeof = %d\n",sizeof(t_stun_shared_req));
	addr=&sock_info->su;
/*
	addr=(union sockaddr_union*)pkg_malloc(sizeof(union sockaddr_union));
	if (addr==0){
		LOGL(L_ERR, "ERROR: udp_init: out of memory\n");
		goto error;
	}
*/
	sock_info->proto=PROTO_UDP;
	if (init_su(addr, &sock_info->address, sock_info->port_no)<0){
		if (log_1) LOG("ERROR: udp_init: could not init sockaddr_union\n");
		goto error;
	}
	
	sock_info->socket = socket(AF2PF(addr->s.sa_family), SOCK_DGRAM, 0);
	if (sock_info->socket==-1){
		if (log_1) LOG("ERROR: udp_init: socket: %s\n", strerror(errno));
		goto error;
	}
	/* set sock opts? */
	optval=1;
	if (setsockopt(sock_info->socket, SOL_SOCKET, SO_REUSEADDR ,
					(void*)&optval, sizeof(optval)) ==-1){
		if (log_1) LOG("ERROR: udp_init: setsockopt: %s\n", strerror(errno));
		goto error;
	}
	/* tos */
#ifndef WIN32
	optval=IPTOS_LOWDELAY;
	if (setsockopt(sock_info->socket, IPPROTO_IP, IP_TOS, (void*)&optval,sizeof(optval)) ==-1)
	{
		if (log_1) LOG("WARNING: udp_init: setsockopt tos: %s\n", strerror(errno));
		/* continue since this is not critical */
	}
#endif
#if defined (__linux__) && defined(UDP_ERRORS)
	optval=1;
	/* enable error receiving on unconnected sockets */
	if(setsockopt(sock_info->socket, SOL_IP, IP_RECVERR,
					(void*)&optval, sizeof(optval)) ==-1){
		if (log_1) LOG("ERROR: udp_init: setsockopt: %s\n", strerror(errno));
		goto error;
	}
#endif


	if ( probe_max_receive_buffer(sock_info->socket)==-1) goto error;
	
	if (bind(sock_info->socket,  &addr->s, sockaddru_len(*addr))==-1){
		if (log_1) LOG("ERROR: udp_init: bind(%x, %p, %d) on %s: %s\n",
				sock_info->socket, &addr->s, 
				sockaddru_len(*addr),
				sock_info->address_str.s,
				strerror(errno));
		goto error;
	}

//#ifdef WIN32
	sa_len = sizeof(struct sockaddr_in);
	if (getsockname(sock_info->socket, (struct sockaddr *)&sa, &sa_len) == -1)
	{
		if (log_1) LOG("ERROR:getsockname failed\n");
#ifdef WIN32		
		if (WSAGetLastError() != 0)
		{
			if (log_1) 
			{
				LOG("getsockname error.code is %d:",WSAGetLastError());
				DisplayErrorText(WSAGetLastError());
				LOG("\n");
			}
			return 21;
		}
#endif		
	}
	if (log_1) LOG("Sending FROM: %s:%d\n", inet_ntoa(sa.sin_addr),ntohs(sa.sin_port));
        if (sock_info->port_no != ntohs(sa.sin_port)) /* perhaps we wanted an ephemeral port ? */
		sock_info->port_no = ntohs(sa.sin_port);

//#endif
/*	pkg_free(addr);*/
	if (log_1) LOG("NOTICE:udp init succeded %d\n",sock_info->socket);
	return 0;
	
error:
/*	if (addr) pkg_free(addr);*/
	if (log_1) LOG("ERROR:udp init failed\n");
	return -1;
}



int udp_rcv_loop()
{
#ifndef WIN32
	unsigned len;
#ifdef DYN_BUF
	char* buf;
#else
	static char buf [BUF_SIZE+1];
#endif

	union sockaddr_union from;
	unsigned int fromlen;
	struct receive_info ri;

	//TODO:dealocare
	/*
	from=(union sockaddr_union*) malloc(sizeof(union sockaddr_union));
	if (from==0){
		LOGL(L_ERR, "ERROR: udp_rcv_loop: out of memory\n");
		goto error;
	}
	*/
	memset(&from, 0 , sizeof(union sockaddr_union));
	ri.bind_address=bind_address; /* this will not change, we do it only once*/
	ri.dst_port=bind_address->port_no;
	ri.dst_ip=bind_address->address;
	ri.proto=PROTO_UDP;
	//ri.proto_reserved1=ri.proto_reserved2=0;
	for(;;){
#ifdef DYN_BUF
		buf=malloc(BUF_SIZE+1);
		if (buf==0){
			if (log_1) LOG("ERROR: udp_rcv_loop: could not allocate receive buffer\n");
			goto error;
		}
#endif
		if (log_1) LOG("udp_rcv_loop:%d\n",getpid());
		fromlen=sockaddru_len(bind_address->su);
		//---------AICI ASTEPT DOAR PE O ADRESA, iar eu trebuie sa astept pe 4
		//2 solutii,select sau fork
		len=recvfrom(bind_address->socket, buf, BUF_SIZE, 0, &from.s,&fromlen);
		
		if (len==-1)
		{
			if (log_1) LOG("ERROR: udp_rcv_loop:recvfrom:[%d] %s\n",errno, strerror(errno));
			if ((errno==EINTR)||(errno==EAGAIN)||(errno==EWOULDBLOCK)||(errno==ECONNREFUSED))
				continue; /* goto skip;*/
			else goto error;
		}
		/* we must 0-term the messages, receive_msg expects it */
		buf[len]=0; /* no need to save the previous char */

		//ri.src_su=from;
		memcpy(&(ri.src_su),&from,sizeof(union sockaddr_union));
		su2ip_addr(&ri.src_ip, &from);
		ri.src_port=su_getport(&from);
		
		
		/* receive_msg must free buf too!*/
		receive_msg_over_udp(buf, len, &ri);
		
	/* skip: do other stuff */
		
	}
	/*
	if (from) pkg_free(from);
	return 0;
	*/
	
error:
	//if (from) free(from);
#endif //win32
	return -1;
}




/* which socket to use? main socket or new one? */
int udp_send(struct socket_info *source, char *buf, unsigned len,union sockaddr_union*  to)
{

	int n;
	int tolen;

	tolen=sockaddru_len(*to);
again:
	n=sendto(source->socket, buf, len, 0, &to->s, tolen);
	if (log_1) LOG("INFO: send status: %d\n", n);
	if (n==-1){
		if (log_1) LOG("ERROR: udp_send: sendto(%d,%p,%d,%x,): %s(%d)\n",source->socket,buf,len,to->s.sa_data,strerror(errno),errno);
		if (errno==EINTR) goto again;
		if (errno==EINVAL) 
                {
			if (log_1) LOG("CRITICAL: invalid sendtoparameters\n"
			"one possible reason is the server is bound to localhost and\n"
			"attempts to send to the net\n");
		}
	}
	return n;
}


/* this function is called when we receive a UDP packet */

int receive_msg_over_udp(char* buf, unsigned int len, struct receive_info* ri) 
{
    int SERVER=1;
    t_stun_message	msg;
    int ret;
    t_stun_message 		n;
    int 			adv;

#ifndef WIN32    
    if (log_1) LOG("receive_msg_over_udp:message received on pid:%d from ",getpid());
#endif
    print_ip(&ri->src_ip);
    if (log_1) LOG(":%u\n",ri->src_port);
    memset(&msg,0,sizeof(t_stun_message));
    msg.buff_len = len;
    msg.pos = NULL;
    msg.len = 0;
    msg.src = ri->src_su;
    msg.original_src = ri->src_su;
    msg.dst = bind_address->su;//bind_address
    if (len%4!=0)
	if (log_1) LOG("Message length is not modulo 4!!!!!\n");
    //TODO:we should have error classes to distinguish between servers fault and message fault
    if ((ret=parse_msg(SERVER,buf,len,&msg)) < 0)
    {
	if (log_1) LOG("receive_msg_over_udp:error parsing message\n");
	
	if (ret < -100) //internal error class
	    {
	    	adv = create_stun_binding_error_response(5,0,STUN_ERROR_500_REASON,STUN_ERROR_500_REASON_LEN,&msg,&n);
			adv = send_msg_over_udp(bind_address,&n,&(msg.original_src));
			return -1;
	    }
	if (ret < -50)	//malformed message for which we did not respond
	    {
			adv = create_stun_binding_error_response(4,0,STUN_ERROR_400_REASON,STUN_ERROR_400_REASON_LEN,&msg,&n);
			adv = send_msg_over_udp(bind_address,&n,&(msg.original_src));
			return -2;
	    }
	return -3;
    }
    //now we have a parsed message, we respond
    if ((ret = respond_to_msg(&msg)) < 0)
    {
		if (log_1) LOG("receive_msg_over_udp:error responding to message\n");
		return -4;
    }
    
    return 1;
}

/* based on the message type, we format, and send the response */
int send_msg_over_udp(struct socket_info *source,t_stun_message *msg,union sockaddr_union *dest)
{
    int ret;
    switch (msg->header.msg_type)
    { 
	case MSG_TYPE_BINDING_REQUEST:
	    ret = format_stun_binding_request(msg);
	    break;
	case MSG_TYPE_BINDING_RESPONSE:
	    ret = format_stun_binding_response(msg);
	    break;
	case MSG_TYPE_BINDING_ERROR_RESPONSE:
	    ret = format_stun_binding_error_response(msg);
	    break;
	case MSG_TYPE_SHARED_SECRET_REQUEST:
	    ret = format_stun_shared_secret_request(msg);
	    break;
	case MSG_TYPE_SHARED_SECRET_RESPONSE:
	    ret = format_stun_shared_secret_response(msg);
	    break;
	case MSG_TYPE_SHARED_SECRET_ERROR_RESPONSE:
	    ret = format_stun_shared_secret_error_response(msg);
	    break;	
	default:
	     return -1;
    }
    if (ret < 0) return -2;
    if (udp_send(source,(char *)msg->buff,msg->buff_len,dest) < 0)
    {
	if (log_1) LOG("send_msg_over_udp:failed to send message\n");
	return -3;
    }
    return 1;
}

int respond_to_binding_request(t_stun_message *msg)
{
    //we can have inside :mapped_address,source_address,changed_address,mi,reflected_from
    t_stun_message		resp;
    struct socket_info 		*addr;
    int ret;
    
    if (create_stun_binding_response(msg,&resp) < 0) 
	return -1;
    

    if (format_stun_binding_response(&resp) < 0)
	return -2;
    //we send it to  msg->src, from resp->source_address
    
    if (msg->u.req.is_change_request)
    {
	if ((msg->u.req.change_request.value & CHANGE_IP_FLAG)&&(msg->u.req.change_request.value & CHANGE_PORT_FLAG))
	    addr = alternate_address_port;
	else
	    if (msg->u.req.change_request.value & CHANGE_IP_FLAG)
		addr = alternate_address;
	    else if (msg->u.req.change_request.value & CHANGE_PORT_FLAG)
		    addr = bind_address_port;
		else //no flag
		    addr = bind_address;
    }
    else
	addr = bind_address;
    
    ret = udp_send(addr,(char *)resp.buff,resp.buff_len,&msg->src);
    return 1;
}
