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
#include "utils.h"
#include "common.h"
#include "ip_addr.h"
#include "globals.h"


#ifndef WIN32
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#endif


#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <signal.h>

#include <string.h>
#include <errno.h>


//#include <sys/mman.h>
#include <sys/stat.h>

#ifdef WIN32
#include <lmerr.h>

void
DisplayErrorText(DWORD dwLastError)
{
    HMODULE hModule = NULL; // default to system source
    LPSTR MessageBuffer;
    DWORD dwBufferLength;

    DWORD dwFormatFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_IGNORE_INSERTS |
        FORMAT_MESSAGE_FROM_SYSTEM ;

    //
    // If dwLastError is in the network range, 
    //  load the message source.
    //

    if(dwLastError >= NERR_BASE && dwLastError <= MAX_NERR) {
        hModule = LoadLibraryEx(
            TEXT("netmsg.dll"),
            NULL,
            LOAD_LIBRARY_AS_DATAFILE
            );

        if(hModule != NULL)
            dwFormatFlags |= FORMAT_MESSAGE_FROM_HMODULE;
    }

    //
    // Call FormatMessage() to allow for message 
    //  text to be acquired from the system 
    //  or from the supplied module handle.
    //

    if(dwBufferLength = FormatMessageA(
        dwFormatFlags,
        hModule, // module to get message from (NULL == system)
        dwLastError,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // default language
        (LPSTR) &MessageBuffer,
        0,
        NULL
        ))
    {
        DWORD dwBytesWritten;

        //
        // Output message string on stderr.
        //
        WriteFile(
            GetStdHandle(STD_ERROR_HANDLE),
            MessageBuffer,
            dwBufferLength,
            &dwBytesWritten,
            NULL
            );

        //
        // Free the buffer allocated by the system.
        //
        LocalFree(MessageBuffer);
    }

    //
    // If we loaded a message source, unload it.
    //
    if(hModule != NULL)
        FreeLibrary(hModule);
}

#endif
#ifndef WIN32

/* daemon init, return 0 on success, -1 on error */
int daemonize()
{
	FILE *pid_stream;
	pid_t pid;
	int r, p;


	p=-1;


	if (chroot_dir&&(chroot(chroot_dir)<0))
    {
		LOG("Cannot chroot to %s: %s\n", chroot_dir, strerror(errno));
		goto error;
	}
/*	
	if (chdir(info.working_dir)<0)
    {
		LOG("cannot chdir to %s: %s\n", info.working_dir, strerror(errno));
		goto error;
	}

    // CHANGE UID
	if (info.gid&&(setgid(info.gid)<0))
    {
		LOG("cannot change gid to %d: %s\n", info.gid, strerror(errno));
		goto error;
	}
	
	if(info.uid&&(setuid(info.uid)<0))
    {
		LOG("cannot change uid to %d: %s\n", info.uid, strerror(errno));
		goto error;
	}
*/
	/* fork to become!= group leader*/
	if ((pid=fork())<0)
    {
		LOG("Cannot fork:%s\n", strerror(errno));
		goto error;
	}else if (pid!=0){
		/* parent process => exit*/
        //fclose(f);
		exit(0);
	}
	/* become session leader to drop the ctrl. terminal */

	if (setsid()<0)
    {
		LOG("setsid failed: %s\n",strerror(errno));
	}
	/* fork again to drop group  leadership */
	if ((pid=fork())<0)
    {
		LOG("Cannot  fork:%s\n", strerror(errno));
		goto error;
	}
    else 
        if (pid!=0)
        {
            /*parent process => exit */
            //fclose(f);
            exit(0);
        }

	/* added by noh: create a pid file for the main process */
	if (pid_file!=0)
    {
		
		if ((pid_stream=fopen(pid_file, "r"))!=NULL){
			fscanf(pid_stream, "%d", &p);
			fclose(pid_stream);
			if (p==-1){
				LOG("pid file %s exists, but doesn't contain a valid pid number\n",pid_file);
				goto error;
			}
			if (kill((pid_t)p, 0)==0 || errno==EPERM){
				LOG("running process found in the pid file %s\n",pid_file);
				goto error;
			}else{
				LOG("pid file contains old pid, replacing pid\n");
			}
		}
		pid=getpid();
		if ((pid_stream=fopen(pid_file, "w"))==NULL){
			LOG("unable to create pid file %s: %s\n", pid_file, strerror(errno));
			goto error;
		}else{
			fprintf(pid_stream, "%i\n", (int)pid);
			fclose(pid_stream);
		}
	}
	
	/* try to replace stdin, stdout & stderr with /dev/null */

	if (freopen("/dev/null", "r", stdin)==0)
	{
		LOG("unable to replace stdin with /dev/null: %s\n",strerror(errno));
		// continue, leave it open 
	};

	if (freopen("/dev/null", "w", stdout)==0)
	{
		LOG("unable to replace stdout with /dev/null: %s\n",strerror(errno));
	// continue, leave it open 
	};
	// close stderr only if log_stderr=0 
	if ((!log_stderr) &&(freopen("/dev/null", "w", stderr)==0))
	{
		LOG("unable to replace stderr with /dev/null: %s\n",strerror(errno));
		// continue, leave it open
	};
	
	/* close any open file descriptors */
	//closelog();
	for (r=3;r<MAX_FD; r++)
	{
		close(r);
	}
	
	if (log_stderr==0)		
		//openlog("mystund", LOG_PID|LOG_CONS, LOG_DAEMON);
		/* LOG_CONS, LOG_PERRROR ? */
	return  0;

error:
	return -1;
}

/* add all family type addresses of interface if_name to the socket_info array
 * if if_name==0, adds all addresses on all interfaces
 * WARNING: it only works with ipv6 addresses on FreeBSD
 * return: -1 on error, 0 on success
 */
int add_interfaces(char* if_name, int family, unsigned short port)
{
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
			/*	( (ifr.ifr_addr.sa_family==AF_INET)?sizeof(struct sockaddr_in):((ifr.ifr_addr.sa_family==AF_INET6)?sizeof(struct sockaddr_in6):sizeof(struct sockaddr)) )*/
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
		
		
		
		if ((if_name==0)||
			(strncmp(if_name, ifr.ifr_name, sizeof(ifr.ifr_name))==0))
        {
			
				/*add address*/
			if (sock_no<MAX_LISTEN)
			{
				sockaddr2ip_addr(&addr,(struct sockaddr*)(p+(long)&((struct ifreq*)0)->ifr_addr));
				if ((tmp=ip_addr2a(&addr))==0) goto error;
				/* fill the strings*/
            			sock_info[sock_no].address = addr;
				sock_info[sock_no].name.s=(char*)malloc(strlen(tmp)+1);
				if(sock_info[sock_no].name.s==0)
            			{
					fprintf(stderr, "Out of memory.\n");
					goto error;
				}
				/* fill in the new name and port */
				sock_info[sock_no].name.len=strlen(tmp);
				strncpy(sock_info[sock_no].name.s, tmp,sock_info[sock_no].name.len+1);
				sock_info[sock_no].port_no=port;
				/* mark if loopback */
				if (ifrcopy.ifr_flags & IFF_LOOPBACK) 
					sock_info[sock_no].is_lo=1;
				sock_no++;
				ret=0;
			}else
			{
				fprintf(stderr, "Too many addresses (max %d)\n", MAX_LISTEN);
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
}

#endif //win32
#ifdef USE_TLS
#include <openssl/hmac.h>
#endif

//ATTENTION:i should pad the input with 0 until new len divides 64:pag28 of STUN RFC
int compute_hmac(char* hmac,char* input, int length, const char* key, int sizeKey)
{
   unsigned int resultSize=0;
   int newlen;
   char *newinput;
   int alocated;
   
   alocated = 0;
   if (length % 64 == 0) 
    {
	newlen = length;
	newinput = input;
	alocated = 0;
    }
    else 
    {
	newlen = length;
	while (newlen % 64 != 0) newlen++;
	newinput = NULL;
	newinput = (char *)malloc(newlen);
	if (newinput == NULL) return -1;
	memset(newinput,0,newlen);
	memcpy(newinput,input,length);
	alocated = 1;
    }

#ifdef USE_TLS    
   HMAC(EVP_sha1(), key, sizeKey, 
        (const unsigned char*)(newinput), newlen, 
        (unsigned char*)(hmac), &resultSize);
#endif
   if (alocated)  free(newinput);	
   
   if (resultSize != 20) 
    {
	LOG("compute_hmac:returned lenght != 20\n");
	return -1;
    }
    return 1;
}


void
to_hex(const char* buffer, int bufferSize, char* output) 
{
   static char hexmap[] = "0123456789abcdef";
   const char* p = buffer;
   char* r = output;
   int i;
   for (i=0; i < bufferSize; i++)
   {
      unsigned char temp = *p++;
	   
      int hi = (temp & 0xf0)>>4;
      int low = (temp & 0xf);
      
      *r++ = hexmap[hi];
      *r++ = hexmap[low];
   }
   *r = 0;
}

