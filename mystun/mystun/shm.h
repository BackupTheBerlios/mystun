<<<<<<< shm.h
/*
 * $Id: shm.h,v 1.1 2003/12/19 00:24:49 gabriel Exp $
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
=======
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
>>>>>>> 1.1.1.2
#ifndef __shm_h
#define __shm_h

#include <time.h>
#include "stun_types.h"

#define MAX_STRUCTS	200 //number of passwords we store in memory
#define EXPIRE		10*60 //a password expires after 10 minutes

typedef	struct
    {
	time_t expire; //the time when the entry expires = now+EXPIRE
	char username[USERNAME_LEN];
	char password[PASSWORD_LEN];
    }	shm_struct;


int init_shm(unsigned int count);
int destroy_shm();


int add_entry(shm_struct *);
int locate_entry(char *username,char **password);
int remove_old_entries(int *sleep_time);//removes expired entries, used by timer process
#endif
