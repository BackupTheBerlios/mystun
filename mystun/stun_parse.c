#include <unistd.h>
#include <string.h>

#include "stun_parse.h"
#include "globals.h"
#include "ip_addr.h"
#include "stun_types.h"
#include "stun_create.h"

#include "server.h"
#include "udp_server.h"
#include "utils.h"

//we parse the STUN header
int parse_header(char *pos,unsigned int len,t_stun_header *header)
{
    int hl = STUN_HEADER_LEN;//sizeof(t_stun_header);
    t_uint16 *t16;
    
    
    if (len < hl)
    {
	LOG("Message to small for a header\n");
	return -1;
    }
    
    //saving type of request and length of the body
    t16 = (t_uint16 *)pos;	header->msg_type = ntohs(*t16);
    t16 = (t_uint16 *)(pos+2);	header->msg_len = ntohs(*t16);    
    memcpy(header->tid.bytes,(pos+4),16);
        
    if	(hl + header->msg_len != len)
	{
	    LOG("Message size does not match header len\n");
	    return -2;
	}
    LOG("Received a request:type=%d	len=%d\n",header->msg_type,header->msg_len);	
    
    return hl; //advance length
}

//parsing attributtes.the name coresponds to the attribute parsed
int parse_stun_change_request(char *pos,unsigned int len,t_stun_change_request *cr)
{
    t_uint16	*t16;
    t_uint32 	*t32;
    
    if (len < STUN_ATTR_HEADER_LEN+STUN_CHANGE_REQUEST_LEN) return -1;
    
    //type is change request, len is 4 and we need to see if we have a 
    // CHANGE_IP or CHANGE_PORT
    t16 = (t_uint16 *)pos;	cr->header.type = ntohs(*t16);
    t16 = (t_uint16 *)(pos+2);	cr->header.len = ntohs(*t16);    
    t32 = (t_uint32 *)(pos+4); 	cr->value = ntohl(*t32);	    
    
    LOG("parse_change_request:[%x][%x]CHANGE_REQUEST received.value =%ld\n",cr->header.type,cr->header.len,cr->value);
    
    if (cr->value & CHANGE_IP_FLAG) 	LOG("CHANGE_IP_FLAG\n");
    if (cr->value & CHANGE_PORT_FLAG) 	LOG("CHANGE_PORT_FLAG\n");
    
    return  STUN_ATTR_HEADER_LEN+STUN_CHANGE_REQUEST_LEN;    
}

int parse_stun_message_integrity(char *pos,unsigned int len,t_stun_message_integrity *mi)
{
    t_uint16 *t16;
    
    if (len < STUN_MESSAGE_INTEGRITY_LEN) return -1; //20        
    t16 = (t_uint16 *)pos;	mi->header.type = ntohs(*t16);
    t16 = (t_uint16 *)(pos+2);	mi->header.len = ntohs(*t16);    

    //we store the hash on the message.this attribute must be the last in message
    memcpy(mi->hmac,(pos+4),STUN_MESSAGE_INTEGRITY_LEN);
    
    return  STUN_ATTR_HEADER_LEN+STUN_MESSAGE_INTEGRITY_LEN;
}


int parse_stun_username(char *pos,unsigned int len,t_stun_username *user)
{
    t_uint16 *t16;
    
    t16 = (t_uint16 *)pos;	user->header.type = ntohs(*t16);
    t16 = (t_uint16 *)(pos+2);	user->header.len = ntohs(*t16);    

    if (user->header.len >= MAX_STRING_LEN) return -1;
    user->len = user->header.len;
    memcpy(user->value,(pos+4),user->len);
    user->value[user->len]=0;
    return  STUN_ATTR_HEADER_LEN+user->len;
}

int parse_stun_password(char *pos,unsigned int len,t_stun_password *pass)
{
    t_uint16 *t16;
    
    t16 = (t_uint16 *)pos;	pass->header.type = ntohs(*t16);
    t16 = (t_uint16 *)(pos+2);	pass->header.len = ntohs(*t16);    

    if (pass->header.len >= MAX_STRING_LEN) return -1;
    pass->len = pass->header.len;
    memcpy(pass->value,(pos+4),pass->len);
    pass->value[pass->len]=0;
    return  STUN_ATTR_HEADER_LEN+pass->len;
    
}
int parse_stun_address(char *pos,unsigned int len,void *address)
{
    struct mapped_address *a;
    t_uint16	*port,*t16;
    t_uint32	*ip;
    if (len < STUN_ADDRESS_LEN) return -1;
    
    a = (struct mapped_address *)address;
    
    t16 = (t_uint16 *)pos;	a->header.type = ntohs(*t16);
    t16 = (t_uint16 *)(pos+2);	a->header.len = ntohs(*t16);    
    
    a->unused = (t_uint8)*pos;
    a->family = (t_uint8)*(pos+1);
    if (a->family != IPv4FAMILY) return -2;
    port = (t_uint16 *)(pos+2);
    a->port = ntohs(*port);
    ip = (t_uint32 *)(pos+4);
    a->address = ntohl(*ip);
    LOG("parse_stun_address:received family %u,port %u,ip %lu\n",a->family,ntohs(a->port),ntohl(a->address));
    
    return STUN_ATTR_HEADER_LEN+STUN_ADDRESS_LEN;
}

int parse_stun_error_code(char *pos,unsigned int len,t_stun_error_code *error)
{
    t_uint16	*t16;
    
    t16 = (t_uint16 *)pos;	error->header.type = ntohs(*t16);
    t16 = (t_uint16 *)(pos+2);	error->header.len = ntohs(*t16);    
    
    if (error->header.len < 4) return -1;
    
    t16 = (t_uint16 *)pos;
    error->unused = ntohs(*t16);
    if (error->unused != 0)
	LOG("parse_stun_error_code:unused != 0 !!!!\n");
    error->clas = *(pos+2);
    error->number = *(pos+3);
    error->reason_len = error->header.len - 4;
    //4 must divide the total length of the reason
    if ((error->reason_len % 4 != 0)||(error->reason_len >= MAX_STRING_LEN))
    {
	LOG("parse_stun_error:reason_len not modulo 4 or too long!!!!!!!\n");
	return -2;
    }
    memcpy(error->reason,(pos+4),error->reason_len);
    error->reason[error->reason_len]=0;
    return STUN_ATTR_HEADER_LEN+error->header.len;
}

int parse_stun_unknown_attributes(char *pos,unsigned int len,t_stun_unknown_attributes *ua)
{
    t_uint16	*t16;
    int i;
    
    t16 = (t_uint16 *)pos;	ua->header.type = ntohs(*t16);
    t16 = (t_uint16 *)(pos+2);	ua->header.len = ntohs(*t16);    
    
    if (ua->header.len < 4)	return -1;
    
    ua->attr_number = ua->header.len/sizeof(t_uint16);
    if (ua->attr_number>MAX_UNKNOWN_ATTRIBUTES) return -2;
    for(i=0;i<ua->attr_number;i++)
    {
	t16 = (t_uint16 *)(pos+4+i*2);
	ua->attr[i] = *t16;
    }

    return STUN_ATTR_HEADER_LEN+ua->header.len;
}


int parse_body_binding_request(char *pos,unsigned int len,t_stun_message *msg)
{
    int total_parsed = 0;
    t_uint16 htype,hlen,*t16;
    int hl = STUN_ATTR_HEADER_LEN;//sizeof(t_stun_attr_header);
    int ret;
    t_stun_bind_req *req;
    
    t_stun_unknown_attributes	ua;
    t_stun_message 		n;
    t_uint16 			u;
    int 			adv;
    char *pass;
    unsigned int plen;
    char hmac[STUN_MESSAGE_INTEGRITY_LEN];
    t_uint32 			naddress;
    
    req = &msg->u.req;
    if (len < hl)
	{
	    if (len == 0)//binding request may be 0 length
		{
		    LOG("binding_request with len = 0\n");
		    return 0;//parsed nothing
		}
	    LOG("parse_body:body to small\n");
	    return -54;
	}
    LOG("len is %u\n",len);
    while(len > 0)
    {
	t16 = (t_uint16 *)pos;		htype = ntohs(*t16);
	t16 = (t_uint16 *)(pos+2);	hlen  = ntohs(*t16);
	ret = 0;
	//we have at least len octets
	if (len-hl < hlen)
	    {
		LOG("parse_body:body to small for attribute len=%u h->len=%u\n",len,hlen);
		return -55;
	    }
	if ((hlen%4 != 0)||(hlen == 0))
	    {
		LOG("parse_body:header has a length not modulo or is 0 %d\n",hlen);
		return -56;
	    }
	LOG("parse_body:received an attr %x with len %d\n",htype,hlen);
	
	switch(htype)
	{
	    case RESPONSE_ADDRESS:
		{
		    if (hlen != STUN_ADDRESS_LEN)
			{
			    LOG("pbr:difference in len.response address\n");
			    return -51;
			}
		    if ((ret = parse_stun_address(pos,len,&req->response_address))<0) return -52;//we shall respond with a 400
		    req->is_response_address = 1;
		    //change source address, so the response is going here
			naddress = htonl(req->response_address.address);
			memcpy(&msg->src.sin.sin_addr,&naddress,4);
			msg->src.sin.sin_port = htons(req->response_address.port);//HTONS?
		    
		    break;
		}
	    case CHANGE_REQUEST:
		{
		    if (hlen != STUN_CHANGE_REQUEST_LEN)
			{
			    LOG("pbr:difference in len.cr\n");
			    return -61;
			}	
		    if ((ret = parse_stun_change_request(pos,len,&req->change_request)) < 0) return -62;
		    req->is_change_request = 1;
		    break;
		}
	    case USERNAME:
		{
		    if (hlen > MAX_STRING_LEN)
			{
			    LOG("pbr:username to long > 256.username\n");
			    return -71;
			}
		    if ((ret = parse_stun_username(pos,len,&req->username)) < 0) return -72;
		    req->is_username = 1;
		    break;
		}
	    case MESSAGE_INTEGRITY:
		{
		    if (hlen != STUN_MESSAGE_INTEGRITY_LEN)
			{
			    LOG("pbr:difference in len.message integrity\n");
			    return -81;
			}
		    if ((ret = parse_stun_message_integrity(pos,len,&req->message_integrity)) < 0) return -82;
		    //TODO:it must be last header,else error
		    //------------------------------------------
		    if (len - ret != 0)
			{
			    LOG("pbr:message integrity is not last\n");
			    //we shall return a 400 error
			    return -83;
			}
		    req->is_message_integrity = 1;
		    
		    //TODO:if USERNAME absent error 432,if no password present,error 430,
		    //if we have password but  hmac is not matching,431
		    if (req->is_username != 1)
			{
			    //error 432
			    adv = create_stun_binding_error_response(4,32,STUN_ERROR_432_REASON,STUN_ERROR_432_REASON_LEN,msg,&n);
			    adv = format_stun_binding_error_response(&n);
			    adv = udp_send(bind_address,(char *)n.buff,n.buff_len,&(msg->original_src));
			    return -13;
			}
		    pass = NULL;
		    plen = 0;
		    if (obtain_password(req->username.value,req->username.len,&pass,&plen)<0)	return -101;//internal error
		    if (plen == 0)
		    {
			//error  430 we do not have such user registred
			    adv = create_stun_binding_error_response(4,30,STUN_ERROR_430_REASON,STUN_ERROR_430_REASON_LEN,msg,&n);
			    adv = format_stun_binding_error_response(&n);
			    adv = udp_send(bind_address,(char *)n.buff,n.buff_len,&(msg->original_src));
			    return -14;
		    }
		    
		    if (compute_hmac(hmac,msg->buff,msg->buff_len,pass,plen) < 0) 
			{
			    if (pass) free(pass);
			    return -102;//internal error
			}
		    if (pass) free(pass);
		    if (memcmp(hmac,req->message_integrity.hmac,STUN_MESSAGE_INTEGRITY_LEN) != 0)
		    {
			//error 431 credential do not match
			adv = create_stun_binding_error_response(4,31,STUN_ERROR_431_REASON,STUN_ERROR_431_REASON_LEN,msg,&n);
			adv = format_stun_binding_error_response(&n);
			adv = udp_send(bind_address,(char *)n.buff,n.buff_len,&(msg->original_src));
			return -14;
			
		    }
		    //=======================================================
		    break;
		}	
	
	    default:
		{	
		    if (htype <= MANDATORY_LIMIT)
		    {
			LOG("parse_body:unknown attribute\n");
			//TODO:sending error message because we do not understand it and is mandatory
			//-----------------------------------
			
			adv = create_stun_binding_error_response(4,20,STUN_ERROR_420_REASON,STUN_ERROR_420_REASON_LEN,msg,&n);
			u = htype;
			adv = create_stun_unknown_attributes(&u,1,&ua);
			n.u.err_resp.unknown_attributes = ua;
			n.u.err_resp.is_unknown_attributes = 1;
			adv = format_stun_binding_error_response(&n);
			adv = udp_send(bind_address,(char *)n.buff,n.buff_len,&(msg->original_src));
			return -14;
		    }
		    
		    else
		    {
			//TODO:ignoring the attribute, it's not mandatory
			//return -4;
			ret = STUN_ATTR_HEADER_LEN+hlen;
		    }
		    
		}
	
	}
	
	    total_parsed += ret;
	    pos += ret;
	    len -= ret;
	    LOG("len becomes %u\n",len);
    }
    return total_parsed;
}

//COD CLIENT:TODO
int parse_body_binding_response(char *pos,unsigned int len,t_stun_message *msg)
{
    int total_parsed = 0;
    t_uint16	*t16,hlen,htype;
    int hl = STUN_HEADER_LEN;
    int ret;
    t_stun_bind_resp *resp;
    
    resp = &msg->u.resp;
    if (len < hl)
	{
	    LOG("parse_body_resp:body to small\n");
	    return -51;
	}
        
    while(len > 0)
    {
        //find out the type of attributte
	t16 = (t_uint16 *)pos;		htype = ntohs(*t16);
	t16 = (t_uint16 *)(pos+2);	hlen  = ntohs(*t16);
	ret = 0;
	if (len < hlen)
	    {
		LOG("parse_body_response:body to small for attribute len=%u h->len=%u\n",len,hlen);
		return -52;
	    }
	if ((hlen%4 != 0)||(hlen == 0))
	    {
		LOG("parse_body_response:header has a length not modulo 4 or is 0\n");
		return -53;
	    }
	LOG("parse_body_response:received an attr %x with len %d\n",htype,hlen);
	
        //this are the attributes types acceptable in binding response
	switch(htype)
	{
	    case MAPPED_ADDRESS:
		{
		    if (hlen != STUN_ADDRESS_LEN)
			{
			    LOG("pbresp:difference in len.mapped address\n");
			    return -54;
			}
		    if ((ret = parse_stun_address(pos,len,&resp->mapped_address))<0) return -55;
                    //mark we have a mapped address in the message
		    resp->is_mapped_address = 1;
		    break;
		}
	    case SOURCE_ADDRESS:
		{
		    if (hlen != STUN_ADDRESS_LEN)
			{
			    LOG("pbresp:difference in len.source address\n");
			    return -56;
			}
		    if ((ret = parse_stun_address(pos,len,&resp->source_address))<0) return -57;
		    resp->is_source_address = 1;
		    break;
		}
		
	    case CHANGED_ADDRESS:
		{
		    if (hlen != STUN_ADDRESS_LEN)
			{
			    LOG("pbresp:difference in len.changed address\n");
			    return -58;
			}
		    if ((ret = parse_stun_address(pos,len,&resp->changed_address))<0) return -59;
		    resp->is_changed_address = 1;
		    break;
		}
	    case REFLECTED_FROM:
		{
		    if (hlen != STUN_ADDRESS_LEN)
			{
			    LOG("pbresp:difference in len.reflected from\n");
			    return -60;
			}
		    if ((ret = parse_stun_address(pos,len,&resp->reflected_from))<0) return -61;
		    resp->is_reflected_from = 1;
		    break;
		}
		

	    case MESSAGE_INTEGRITY:
		{
		    if (hlen != STUN_MESSAGE_INTEGRITY_LEN)
			{
			    LOG("pbresp:difference in len.message integrity\n");
			}
		    if ((ret = parse_stun_message_integrity(pos,len,&resp->message_integrity)) < 0) return -62;
                    //check if this attributte is the last
		    if (len - ret != 0)
			{
			    LOG("pbresp:message integrity is not last\n");
			    //TODO:error message or ignore?
			    return -63;
			}
		    resp->is_message_integrity = 1;
		    break;
		}	
	
	    default:
		{	
                    //we do not understant mandatory attribute
		    if (htype <=  MANDATORY_LIMIT)
		    {
			//client code
			LOG("parse_body:unknown attribute\n");
			return -3;
		    }
		    
		    else //an optional parameter we do not understand
		    {
			//TODO:ignore
			ret = STUN_ATTR_HEADER_LEN+hlen;
			//return -4;
		    }
		    
		}
	
	}
	
	    total_parsed += ret;
	    pos += ret;
	    len -= ret;
	    //LOG("len becomes %u\n",len);
    }
    return total_parsed;
    
}
int parse_body_binding_error_response(char *pos,unsigned int len,t_stun_message *msg)
{
    int total_parsed = 0;
    t_uint16	*t16,hlen,htype;
    int hl = STUN_HEADER_LEN;
    int ret;
    t_stun_bind_err_resp *resp;
    
    resp = &msg->u.err_resp;
    if (len < hl)
	{
	    LOG("parse_body_binding_error_response:body to small\n");
	    return -1;
	}
    while(len > 0)
    {
    
        //find out the type of attributte
	t16 = (t_uint16 *)pos;		htype = ntohs(*t16);
	t16 = (t_uint16 *)(pos+2);	hlen  = ntohs(*t16);
	ret = 0;
	if (len < hlen)
	    {
		LOG("parse_body_binding_error_response:body to small for attribute len=%u h->len=%u\n",len,hlen);
		return -2;
	    }
	if ((hlen%4 != 0)||(hlen == 0))
	    {
		LOG("parse_body_binding_error_response:header has a length not modulo 4 or is 0\n");
		return -3;
	    }
	LOG("parse_body_binding_error_response:received an attr %x with len %d\n",htype,hlen);
	
	switch(htype)
	{
	    case ERROR_CODE:
		{
		    if (hlen < 8)
			{
			    LOG("pberrresp:difference in len.error code\n");
			    return -4;
			}
		    if ((ret = parse_stun_error_code(pos,len,&resp->error_code))<0) return -5;
		    resp->is_error_code = 1;
		    break;
		}
	    case UNKNOWN_ATTRIBUTES:
		{
		    if (hlen % 4 != 0 )
			{
			    LOG("pbresp:difference in %%.unknown attributes\n");
			    return -6;
			}
		    if ((ret = parse_stun_unknown_attributes(pos,len,&resp->unknown_attributes))<0) return -7;
		    resp->is_unknown_attributes = 1;
		    break;
		}
	
	    default:
		{	
		    if (htype <=  MANDATORY_LIMIT)
		    {
			LOG("parse_body_banding_error_response:unknown attribute\n");
			return -3;
		    }
		    
		    else
		    {
			//TODO:ignore
			ret = STUN_ATTR_HEADER_LEN+hlen;
		    }
		    
		}
	
	}
	
	    total_parsed += ret;
	    pos += ret;
	    len -= ret;
	
    }
    return total_parsed;
}
int parse_body_shared_secret_request(char *pos,unsigned int len,t_stun_message *msg)
{
    //TODO:we must check if it arrived on TLS
    //i should generate a username and a password,and add them to the shared memory
    //the body does not contain anything, so we just ignore it, we might check and not to ignore
    // if (len != 0) return -1;
    return len;
}

int parse_body_shared_secret_response(char *pos,unsigned int len,t_stun_message *msg)
{
    //TODO:it must arrive on TLS and must contain an username and a password
    int total_parsed = 0;
    t_uint16	*t16,hlen,htype;
    int hl = STUN_HEADER_LEN;
    int ret;
    t_stun_shared_resp *resp;
    
    resp = &msg->u.shared_resp;
    if (len < hl)
	{
	    LOG("parse_body_binding_error_response:body to small\n");
	    return -1;
	}
    while(len > 0)
    {
	t16 = (t_uint16 *)pos;		htype = ntohs(*t16);
	t16 = (t_uint16 *)(pos+2);	hlen  = ntohs(*t16);
	ret = 0;
	if (len < hlen)
	    {
		LOG("parse_body_binding_error_response:body to small for attribute len=%u h->len=%u\n",len,hlen);
		return -2;
	    }
	if ((hlen%4 != 0)||(hlen == 0))
	    {
		LOG("parse_body_binding_error_response:header has a length not modulo 4 or is 0\n");
		return -3;
	    }
	LOG("parse_body_binding_error_response:received an attr %x with len %d\n",htype,hlen);
	
	switch(htype)
	{
	    case USERNAME:
		{
		    if (hlen != USERNAME_PREFIX_LEN+8 )
			{
			    LOG("pberrresp:difference in len.username\n");
			    return -4;
			}
		    if ((ret = parse_stun_username(pos,len,&resp->username))<0) return -5;
		    resp->is_username = 1;
		    break;
		}
	    case PASSWORD:
		{
		    if (hlen != STUN_MESSAGE_INTEGRITY_LEN )
			{
			    LOG("pbresp:difference in len.password\n");
			    return -6;
			}

		    if ((ret = parse_stun_password(pos,len,&resp->password))<0) return -7;
		    resp->is_password = 1;
		    break;
		}
	
	    default:
		{	
		    if (htype <=  MANDATORY_LIMIT)
		    {
			LOG("parse_body_banding_error_response:unknown attribute\n");
			return -8;
		    }
		    
		    else
		    {
			//TODO:ignore
			ret = STUN_ATTR_HEADER_LEN+hlen;
		    }
		    
		}
	
	}
	
	    total_parsed += ret;
	    pos += ret;
	    len -= ret;
	
    }
    return total_parsed;
}

//almost the same code, the difference is that this is sent on TLS
//perhaps it was better if I would just call the other error parsing function
int parse_body_shared_secret_error_response(char *pos,unsigned int len,t_stun_message *msg)
{
    int total_parsed = 0;
    t_uint16	*t16,hlen,htype;
    int hl = STUN_HEADER_LEN;
    int ret;
    t_stun_shared_err_resp *resp;
    
    resp = &msg->u.shared_err_resp;
    if (len < hl)
	{
	    LOG("parse_body_binding_error_response:body to small\n");
	    return -1;
	}
    //LOG("len is %u\n",len);
    while(len > 0)
    {
	//advance(msg,hl);
	t16 = (t_uint16 *)pos;		htype = ntohs(*t16);
	t16 = (t_uint16 *)(pos+2);	hlen  = ntohs(*t16);
	ret = 0;
	if (len < hlen)
	    {
		LOG("parse_body_binding_error_response:body to small for attribute len=%u h->len=%u\n",len,hlen);
		return -2;
	    }
	if ((hlen%4 != 0)||(hlen == 0))
	    {
		LOG("parse_body_binding_error_response:header has a length not modulo 4 or is 0\n");
		return -3;
	    }
	LOG("parse_body_binding_error_response:received an attr %x with len %d\n",htype,hlen);
	
	switch(htype)
	{
	    //ar trebui sa verific ca tipul asta de atribut are voie in
	    //tipul asta de cerere
	    case ERROR_CODE:
		{
		    if (hlen < 8)
			{
			    LOG("pberrresp:difference in len.error code\n");
			    return -4;
			}
		    if ((ret = parse_stun_error_code(pos,len,&resp->error_code))<0) return -5;
		    resp->is_error_code = 1;
		    break;
		}
	    case UNKNOWN_ATTRIBUTES:
		{
		    if (hlen % 4 != 0 )
			{
			    LOG("pbresp:difference in %%.unknown attributes\n");
			    return -6;
			}
		    if ((ret = parse_stun_unknown_attributes(pos,len,&resp->unknown_attributes))<0) return -7;
		    resp->is_unknown_attributes = 1;
		    break;
		}
	
	    default:
		{	
		    if (htype <=  MANDATORY_LIMIT)
		    {
			LOG("parse_body_banding_error_response:unknown attribute\n");
			return -8;
		    }
		    
		    else
		    {
			//TODO:ignore
			ret = STUN_ATTR_HEADER_LEN+hlen;
			//return -4;
		    }
		    
		}
	
	}
	
	    total_parsed += ret;
	    pos += ret;
	    len -= ret;
	    //LOG("len becomes %u\n",len);
    }
    return total_parsed;
}

//we split parsing on the tipe of the caller
//on the server we only acceot binding requests and shared secret requests
int parse_msg(int is_server,char *pos,unsigned int len,t_stun_message *msg)
{

    int adv;
/*  t_uint16 u;
    t_stun_unknown_attributes ua;
    
    t_stun_message n;
    adv = create_stun_binding_error_response(6,0,"SERVER Down",11,&n);
    LOG("c=%d\n",adv);
    u = CHANGE_REQUEST;
    adv = create_stun_unknown_attributes(&u,1,&ua);
    n.u.err_resp.unknown_attributes = ua;
    n.u.err_resp.is_unknown_attributes = 1;
    LOG("a=%d\n",adv);
    adv = format_stun_binding_error_response(&n);
    LOG("f=%d\n",adv);
    adv = udp_send(bind_address,(char *)n.buff,n.buff_len,&(msg->src));
    LOG("u=%d\n",adv);
    fflush(stdout);
*/
    
    if ((adv=parse_header(pos,len,&msg->header)) < 0) return -1;
    if (is_server)
    {
    switch(msg->header.msg_type)
    {
	case MSG_TYPE_BINDING_REQUEST:			return parse_body_binding_request(pos+adv,len-adv,msg);
	case MSG_TYPE_SHARED_SECRET_REQUEST:		return parse_body_shared_secret_request(pos+adv,len-adv,msg);
	default:
	    return -2;
    }
    }
    else
    {
    switch(msg->header.msg_type)
    {
	case MSG_TYPE_BINDING_RESPONSE:			return parse_body_binding_response(pos+adv,len-adv,msg);
	case MSG_TYPE_BINDING_ERROR_RESPONSE:		return parse_body_binding_error_response(pos+adv,len-adv,msg);
	case MSG_TYPE_SHARED_SECRET_RESPONSE:		return parse_body_shared_secret_response(pos+adv,len-adv,msg);
	case MSG_TYPE_SHARED_SECRET_ERROR_RESPONSE:	return parse_body_shared_secret_error_response(pos+adv,len-adv,msg);
	default:
	    return -2;
    }
	
    }
    return 1;
}

