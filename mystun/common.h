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
#ifndef __common_h
#define __common_h

#include <stdio.h>

#ifndef WIN32
#define LOG(fmt, args...) fprintf(stdout,fmt, ##args);
#define LOGL(lev,fmt, args...) fprintf(stdout,fmt, ##args);
#define DBG(fmt, args...) LOG(fmt, ## args)
#else
#define LOG printf
#define DBG printf
#define LOGL printf

/*
#define LOG(lev, fmt, args...) \
			do { \
				if (debug>=(lev)){ \
					if (log_stderr) dprint (fmt, ## args); \
					else { \
						switch(lev){ \
							case L_CRIT: \
								syslog(LOG_CRIT | L_FAC, fmt, ##args); \
								break; \
							case L_ALERT: \
								syslog(LOG_ALERT | L_FAC, fmt, ##args); \
								break; \
							case L_ERR: \
								syslog(LOG_ERR | L_FAC, fmt, ##args); \
								break; \
							case L_WARN: \
								syslog(LOG_WARNING | L_FAC, fmt, ##args); \
								break; \
							case L_NOTICE: \
								syslog(LOG_NOTICE | L_FAC, fmt, ##args); \
								break; \
							case L_INFO: \
								syslog(LOG_INFO | L_FAC, fmt, ##args); \
								break; \
							case L_DBG: \
								syslog(LOG_DEBUG | L_FAC, fmt, ##args); \
								break; \
						} \
					} \
				} \
			}while(0)


*/

#endif			
#endif
