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
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>

#ifndef WIN32
#include <unistd.h>
#include <sys/wait.h>
#endif

#include <signal.h>
#include <sys/types.h>

#include <ctype.h>

#include "stun_types.h"
#include "utils.h"
#include "common.h"
#include "globals.h"
#include "ip_addr.h"
#include "udp_server.h"
#include "tls_server.h"
#include "shm.h"

//extern int log;

int log_1 = 1;
struct socket_info sock_info[MAX_LISTEN];
int sock_no = 0;
//number of children to fork.unused
int children_no = 4;
int default_port = 3478;
int default_alternate_port = 3479;
int dont_fork = 1;
int log_stderr = 0;
char *version = "0.0.1";
char *pid_file = "pid_file";
char *working_dir = "/tmp";
char *chroot_dir = NULL;
char *user = NULL;
char *group = NULL;
static char *compiled= __TIME__ " " __DATE__ ;
unsigned int maxbuffer = MAX_RECV_BUFFER_SIZE;

int first_interface = -1;
int second_interface = -1;

struct socket_info *bind_address = NULL; // the main address for each of the childs
struct socket_info *alternate_address = NULL;  
struct socket_info *bind_address_port = NULL;
struct socket_info *alternate_address_port = NULL;

#ifdef USE_TLS
struct socket_info *tls_bind_address = NULL;
#endif

int pids[MAX_PROCESSES];

//used for generating username and passwords
char *username_hmac_key = "key1";
char *another_private_key = "key2";

//FILE *f;

int is_main = 1;
int is_timer = 0;
int is_udp = 0;
int is_tls = 0;
char help_msg[] = "\
my stun server --- version 0.0.1\n\
Usage: my_stun [-p port] [-l address [-p port]...] [options]\n\
Options:\n\
    -p port         Listen on the specified port (default: 3478)\n\
    -a port 	    Alternate port\n\
    -i address      Listen on the specified interfaces(eg:1,2 or 2,3) \n\
    -n processes    Number of child processes to fork \n\
                    (default: 4)(not implemented)\n\
    -u uid          Uid to drop privilegies\n\
    -g gid          Gid to drop privilegies\n\
    -w working dir  Working directory\n\
    -c chroot dir   Chroot directory    \n\
    -P pid_file     File name used to store server pid\n\
                    (default: pid_file)\n\
    -D              Fork into daemon mode\n\
    -c certfile     File certificate for TLS server\n\
    -k keyfile	    Private key file for TLS server\n\
    -s		    Secure.Require only Binding Request authenticated(unused)\n\
    -E              Log to stderr\n\
    -v              Print version\n\
    -h              Print this help message\n";


#ifndef WIN32
//we dealocate the interface vector
int cleanup_vector()
{
    int r;
    for(r=0;r<sock_no;r++)
        if (sock_info[r].name.s != NULL)
            free(sock_info[r].name.s);
	    
    return 0;
}

//we kill or childres,it will be called by the main process
int cleanup_childs()
{
    int r;

    for(r=0;r<MAX_PROCESSES;r++)
    {
	if (pids[r]>0) 
	    {
#ifndef USE_TLS
                if ((r == 4)||(r == 5)) continue;
#endif
	    	kill(pids[r],SIGINT);
			kill(pids[r],SIGTERM);
	    }
    }
    //asteptam moartea	copiilor
    while (wait(0)>0);
    return 1;
}

int cleanup(int how)
{
    LOG("pid %d cleaning up.is_main=%d is_udp=%d is_tls=%d is_timer=%d\n",getpid(),is_main,is_udp,is_tls,is_timer);
    cleanup_vector();
#ifdef USE_TLS
    destroy_shm();    
#endif

    if (is_main) 
    {
	if (how == 0) cleanup_childs();
	if (how == 0)
	    if (pid_file) 
    		LOG("unlink returned %d\n",unlink(pid_file));
    }
    
    //closing sockets
    if (bind_address)
	{
	    if (bind_address->socket > 0) close(bind_address->socket);
	    free(bind_address);
	}
    if (bind_address_port)
    {
	    if (bind_address_port->socket > 0) close(bind_address_port->socket);
	    free(bind_address_port);
	}
    if (alternate_address)
	{
	    //close socket
	    if (alternate_address->socket > 0) close(alternate_address->socket);	    
	    free(alternate_address);
	}
    if (alternate_address_port)
	{
	    //close socket
	    if (alternate_address_port->socket > 0) close(alternate_address_port->socket);	    
	    free(alternate_address_port);
	}
#ifdef USE_TLS
    if (tls_bind_address)
	{
	    if (tls_bind_address->socket > 0) close(tls_bind_address->socket);	
	    free(tls_bind_address);
	}	
#endif
    
    return 0;
}

void handle_sigs(int sem)
{
    if (sem == SIGHUP)
	{
	    LOG("pid %d received SIGHUP\n",getpid());
	    return ;
	}
    //LOG("pid %d received %d\n",getpid(),sem);
    if ((sem == SIGTERM)||(sem == SIGINT))
    {
	cleanup(0);   
	exit(0); 
    }
}

struct socket_info * duplicate_sock_info(struct socket_info* original)
{
    struct socket_info *res;
    
    res = NULL;
    res = (struct socket_info *)malloc(sizeof(struct socket_info));
    if (res == NULL)
	return NULL;
    memcpy(res,original,sizeof(struct socket_info));
    return res;
}

int initialize_server()
{
    int r;
    int f,s;
    

    //we locate two interfaces available, from which none is the loopback    
    f = s = -1;
    if ((first_interface == -1)&&(second_interface == -1))
{
    for (r=0;r<sock_no;r++)
    {
        if (!sock_info[r].is_lo)
            {
                //break;
		if (f != -1) //the second
		    {
			s = r;
			LOG("Using [%.*s]:%d as alternate bind address\n",sock_info[r].name.len,sock_info[r].name.s,default_port);                
			break;
		    }
		else
		    {
		        LOG("Using [%.*s]:%d as main bind address\n",sock_info[r].name.len,sock_info[r].name.s,default_port);                 
			f = r;                
		    }
            }
        else
            {
                LOG("NOT using [%.*s]:%d as main bind address.Loopback reason.\n",sock_info[r].name.len,sock_info[r].name.s,default_port);                
            }
    }
}
    else
    {
	//we set the interfaces by command line argument -i
	f = first_interface;
	s = second_interface;
    }    

    if ((f == -1)||(s == -1))
	{
	    LOG("Unable to obtain two (2) addresses.\n");
	    return -1;
	}
    //saving the ports
    if ((bind_address = duplicate_sock_info(&sock_info[f])) == NULL) goto init_error1;
    bind_address->port_no = default_port;
    
    if ((bind_address_port = duplicate_sock_info(&sock_info[f])) == NULL) goto init_error1;
    bind_address_port->port_no = default_alternate_port;
    
    if ((alternate_address = duplicate_sock_info(&sock_info[s])) == NULL) goto init_error1;
    alternate_address->port_no = default_port;
    
    if ((alternate_address_port = duplicate_sock_info(&sock_info[s])) == NULL) goto init_error1;
    alternate_address_port->port_no = default_alternate_port;
    
    if (udp_init(bind_address) == -1) 
        {   
            LOG("Unable to udp_init bind_address\n");
            //goto error;
	    return -1;
        }
    if (udp_init(bind_address_port) == -1) 
        {   
            LOG("Unable to udp_init bind_address_port\n");
            //goto error;
	    return -2;
        }
    if (udp_init(alternate_address) == -1) 
        {   
            LOG("Unable to udp_init alternate_address\n");
            //goto error;
	    return -1;
        }
    if (udp_init(alternate_address_port) == -1) 
        {   
            LOG("Unable to udp_init alternate_address_port\n");
            //goto error;
	    return -2;
        }
	
    LOG("udp_init succeeded\n");
#ifdef USE_TLS    
    if (init_shm(1) < 0)
	{
	    LOG("init_server:failing init_shm\n");
	    cleanup(0);
	    return -1;
	}
#endif
    LOG("initializing server ... ok\n");
    return 0;
init_error1:
    cleanup(0);
    return -1;    
}

int child_function(int id)
{
    struct socket_info *b,*bp,*a,*ap;
    int sleep_time;
    
    is_main = 0;
    b = bind_address;
    bp = bind_address_port;
    a = alternate_address;
    ap = alternate_address_port;

    //each of the childs has the main address different from the other
    if (id == 1) 
	{
	    bind_address = b;
	    bind_address_port = bp;
	    alternate_address = a;
	    alternate_address_port = ap;
	}
    if (id == 2) 
	{
	    bind_address = bp;
	    bind_address_port = b;
	    alternate_address = ap;
	    alternate_address_port = a;
	}
    if (id == 3) 
	{
	    bind_address = a;
	    bind_address_port = ap;
	    alternate_address = b;
	    alternate_address_port = bp;
	}
    if (id == 4) 
	{
	    bind_address = ap;
	    bind_address_port = a;
	    alternate_address = bp;
	    alternate_address_port = b;
	}

    if (id <= 4)
    {
    is_udp = 1;
    LOG("Child %d [%d] started ...\n",id,getpid());	
    LOG("Listening on:\n");
    LOG("\tb [%d]	%.*s:%d\n",id,bind_address->name.len,bind_address->name.s,bind_address->port_no);
    LOG("\tbp[%d]	%.*s:%d\n",id,bind_address_port->name.len,bind_address_port->name.s,bind_address_port->port_no);
    LOG("\ta [%d]	%.*s:%d\n",id,alternate_address->name.len,alternate_address->name.s,alternate_address->port_no);
    LOG("\tap[%d]	%.*s:%d\n",id,alternate_address_port->name.len,alternate_address_port->name.s,alternate_address_port->port_no);
    
    /*
    for(i=1;i<THREADS_PER_SOCKET;i++)
	{
	    fork();
	}
    */	
    return udp_rcv_loop();

    }

#ifdef USE_TLS    
    //start the TLS server
    if (id == 5)
    {
	//tls server
	is_tls = 1;
	init_tls();
	tls_bind_address = duplicate_sock_info(bind_address);
		
	if (tls_init(tls_bind_address) != 1) 
            {
                LOG("TLS bind failed:trying after 25 seconds\n");
                sleep(10);
                if (tls_init(tls_bind_address) != 1) 
                {
                    LOG("Second TLS bind failed.Givving Up\n");
                    for(;;) pause();
                   
                }
                else LOG("TLS succeeded from second attempt\n");
            }
	return tls_rcv_loop();

    }
#endif

#ifdef USE_TLS
    //start the timer
    if (id == 6)
    {
	//timer server scope is to detect expired credentials
	is_timer = 1;
	LOG("[%d] timer activated\n",getpid());
		
	sleep_time = -1;
	while(1)
	{

	    if (sleep_time == -1) sleep(EXPIRE-TIMER_RESOLUTION);//EXPIRE-TIMER_RESOLUTION is better
	    else sleep(sleep_time+10);//to be sure it expired
	    remove_old_entries(&sleep_time);

	    LOG("[%d] timer activates now sleep_time=%d\n",getpid(),sleep_time);
	}
				

    }
#endif
    return 1;
}

int start_server()
{
    int r;
    int pid;
    
    
    r = initialize_server();
    if (r < 0)
	{
	    LOG("Initialazing failed ... code %d\n",r);
	    return -1;
	}
    //we start the 6 processes:
    // 4 listen on udp, one on TLS and one is a timer	
    for (r=0;r<MAX_PROCESSES;r++)
    {
                pid = fork();
		if (pid<0)	    
		    {
			LOG("start_server:cannot fork\n");
			return -2;
		    }
		    else
			if (pid == 0) //child
			    {
				child_function(r+1);
			    }
			    else //dad
			    {
				//LOG("Child %d started[%d]\n",r+1,pid);
				pids[r] = pid;
			    }
    }
	if (dont_fork == 1)
	{
	    for(;;)    
    	        pause();
	}
	else
	{
	    sleep(10);//to be sure
	    cleanup(1);
	    return 0;
	}
    	    		    
		
    //LOG("starting server ... ok\n");
        
    return 0;
}
#if COMPILE_SERVER
int main(int argc,char **argv)
{
    int r; 
    char *options;    
    //char tmp[11];
    char *tmp;
    char c;    
    
    options="P:p:i:a:n:u:g:w:c:vhDEws:";
	
	while((c=getopt(argc,argv,options))!=-1){
		switch(c){
			case 'i':
					//choose interfaces
					first_interface = optarg[0]-'1';
					second_interface = optarg[2]-'1';
					fprintf(stderr,"using intefaces:%d and %d\n",first_interface,second_interface);
					break;
			case 'p':
					tmp = 0;
					default_port = strtol(optarg, &tmp, 10);
					if (tmp &&(*tmp)){
						fprintf(stderr, "bad port number: -p [%s] %d\n", optarg,default_port);
						goto error;
					}
					break;
			case 'a':
					tmp = 0;
					default_alternate_port = strtol(optarg, &tmp, 10);
					if (tmp &&(*tmp)){
						fprintf(stderr, "bad port number: -p %s\n", optarg);
						goto error;
					}
					break;

			case 'n':
					children_no=strtol(optarg, &tmp, 10);
					if ((tmp==0) ||(*tmp)){
						fprintf(stderr, "bad process number: -n %s\n",optarg);
						goto error;
					}
					break;
			case 'D':
					dont_fork=0;
					break;
			case 'E':
					log_stderr=1;
					break;
			case 'v':
					printf("version: %s\n", version);
                			printf("compiled: %s\n",compiled);			
					exit(0);
					break;
            
			case 'h':
					printf("%s",help_msg);
					exit(0);
					break;
			case 'w':
					working_dir=optarg;
					break;
			case 't':
					chroot_dir=optarg;
					break;
			case 'u':
					user=optarg;
					break;
			case 'g':
					group=optarg;
					break;
			case 'P':
					pid_file=optarg;
					break;
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
                  
			case '?':
					if (isprint(optopt))
						fprintf(stderr, "Unknown option `-%c´.\n", optopt);
					else
						fprintf(stderr, 
								"Unknown option character `\\x%x´.\n",
								optopt);
					goto error;
			case ':':
					fprintf(stderr, 
								"Option `-%c´ requires an argument.\n",
								optopt);
					goto error;
			default:
					abort();
		}
	}


    if (dont_fork == 0) 
    {
	daemonize();
    }


    
    if (sock_no == 0)
    if (add_interfaces(0,AF_INET,0) == -1) //ipv4 interfaces
        {
            LOG("error finding addresses\n");
            return -1;
        }
    
    for (r=0; r<sock_no;)
    {
		if (add_interfaces(sock_info[r].name.s, AF_INET,sock_info[r].port_no)!=-1)
        {
			/* success => remove current entry (shift the entire array)*/
			free(sock_info[r].name.s);
			memmove(&sock_info[r], &sock_info[r+1],(sock_no-r)*sizeof(struct socket_info));
			sock_no --;
			continue;
		}
		r++;
	}
    LOG("Located interfaces \n");
    for(r=0;r<sock_no;r++)
    {    
	LOG("    [%.*s] ", sock_info[r].name.len,sock_info[r].name.s);
        LOG("ip->");print_ip(&(sock_info[r].address));
        LOG("\n");
    }
    
    LOG("Before daemonize pid is [%d] parent [%d]\n",getpid(),getppid());
   
    /* INSTALL SIGNAL HANDLERS HERE, SO WE SHOULD NOT RECEIVE SIGNALS FROM daemonize */
    signal(SIGINT,handle_sigs);
    signal(SIGTERM,handle_sigs);
    signal(SIGHUP,handle_sigs);
    signal(SIGPIPE,handle_sigs);
    signal(SIGCHLD,handle_sigs);

    /* create the childs */
    r = start_server();
    
    return (0);
error:
    cleanup(0);
    return -1;
    //dealocari
}

#endif
#endif //WIN32
