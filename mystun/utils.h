/*
 * $Id: utils.h,v 1.5 2004/01/18 21:40:09 gabriel Exp $
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

#ifndef __utils_h
#define __utils_h

/*
#ifndef WIN32
#include <sys/types.h>
#include <unistd.h>
#endif
*/
#define MAX_FD 32 //number of file descriptors we are going to close
#define MAX_LISTEN 16 //maximum number of listening addresses


//transform a process into a deamon
int daemonize();
//locate computer interfaces
int add_interfaces(char* if_name, int family, unsigned short port);

int compute_hmac(char* hmac,char* input, int length, const char* key, int sizeKey);
void to_hex(const char* buffer, int bufferSize, char* output);

#ifdef WIN32
void DisplayErrorText(int);
#endif

#endif

