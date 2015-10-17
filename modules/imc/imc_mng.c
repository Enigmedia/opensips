/*
 * $Id: imc_mng.c 8503 2011-10-19 09:14:49Z razvancrainea $
 *
 * imc module - instant messaging conferencing implementation
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * ---------
 *  2006-10-06  first version (anca)
 */


#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../dprint.h"

#include "imc_mng.h"
#include "../../db/db.h"
/* imc hash table */
extern imc_hentry_p _imc_htable;
extern int imc_hash_size;
extern char imc_cmd_start_char;

extern str rooms_table;
extern str members_table;
extern db_con_t *imc_db;
extern db_func_t imc_dbf;

extern str imc_col_username;
extern str imc_col_domain;
extern str imc_col_flag;
extern str imc_col_room;
extern str imc_col_name;

#define imc_get_hentry(_hid, _size) ((_hid)&(_size-1))

#define GROUPS_MAX_LINE_LEN 1024

/**
 * hash thable init
 */
int imc_htable_init(void)
{
	int i;

	if(imc_hash_size<=0)
	{
		LM_ERR("invalid hash table size\n");
		return -1;
	}
	_imc_htable = (imc_hentry_p)shm_malloc(imc_hash_size*sizeof(imc_hentry_t));
	if(_imc_htable == NULL)
	{
		LM_ERR("no more shm memory\n");
		return -1;
	}
	memset(_imc_htable, 0, imc_hash_size*sizeof(imc_hentry_t));
	for(i=0; i<imc_hash_size; i++)
	{
		if (lock_init(&_imc_htable[i].lock)==0)
		{
			LM_CRIT("failed to initialize lock [%d]\n", i);
			goto error;
		}
	}
	
	return 0;

error:
	if(_imc_htable!=NULL)
	{
		shm_free(_imc_htable);
		_imc_htable = NULL;
	}

	return -1;
}

/**
 * destroy hash table
 */
int imc_htable_destroy(void)
{
	int i;
	imc_room_p irp = NULL, irp_temp=NULL;
	if(_imc_htable==NULL)
		return -1;
	
	for(i=0; i<imc_hash_size; i++)
	{
		lock_destroy(&_imc_htable[i].lock);
		if(_imc_htable[i].rooms==NULL)
			continue;
			irp = _imc_htable[i].rooms;
			while(irp){
				irp_temp = irp->next;
				imc_del_room(&irp->name, &irp->domain, 0); // 0, no borra la base de datos
				irp = irp_temp;
			}
	}
	shm_free(_imc_htable);
	_imc_htable = NULL;
	return 0;
}

/**
 * add room
 */
imc_room_p imc_add_room(str* name, str* domain, int flags)
{
	imc_room_p irp = NULL;
	int size;
	int hidx;
	
	LM_DBG("Adding room %s %s\n",name->s, domain->s);

	if(name == NULL || name->s==NULL || name->len<=0
			|| domain == NULL || domain->s==NULL || domain->len<=0)
	{
		LM_ERR("invalid parameters\n");
		return NULL;
	}

	/* struct size + "sip:" + name len + "@" + domain len + '\0' */
	size = sizeof(imc_room_t) + (name->len+domain->len+6)*sizeof(char);
	irp = (imc_room_p)shm_malloc(size);
	if(irp==NULL)
	{
		LM_ERR("no more shm memory left\n");
		return NULL;
	}
	memset(irp, 0, size);
	
	irp->uri.len = 4 /*sip:*/ + name->len + 1 /*@*/ + domain->len;
	irp->uri.s = (char*)(((char*)irp)+sizeof(imc_room_t));
	memcpy(irp->uri.s, "sip:", 4);
	memcpy(irp->uri.s+4, name->s, name->len);
	irp->uri.s[4+name->len] = '@';
	memcpy(irp->uri.s+5+name->len, domain->s, domain->len);
	irp->uri.s[irp->uri.len] = '\0';

	irp->name.len = name->len; // Vaya pachulín tienen aquí... len = 8, s=12345678@domain.com
	irp->name.s = irp->uri.s+4;
	irp->domain.len = domain->len;
	irp->domain.s = irp->uri.s+5+name->len;
	
	irp->flags  = flags;
	irp->hashid = core_case_hash(&irp->name, &irp->domain, 0);

	hidx = imc_get_hentry(irp->hashid, imc_hash_size);
	
	lock_get(&_imc_htable[hidx].lock);
	
	if(_imc_htable[hidx].rooms!=NULL)
	{
		irp->next = _imc_htable[hidx].rooms;
		_imc_htable[hidx].rooms->prev = irp;
		_imc_htable[hidx].rooms = irp;
	} else {
		_imc_htable[hidx].rooms = irp;
	}	
	
	LM_DBG("Added room %s %s\n",name->s, domain->s);

	return irp;
}

/**
 * release room
 */
int imc_release_room(imc_room_p room)
{
	unsigned int hidx;
	
	if(room==NULL)
	{
		LM_ERR("invalid parameters\n");
		return -1;
	}
	
	hidx = imc_get_hentry(room->hashid, imc_hash_size);
	lock_release(&_imc_htable[hidx].lock);

	return 0;
}

/**
 * search room
 */
imc_room_p imc_get_room(str* name, str* domain)
{
	imc_room_p irp = NULL;
	unsigned int hashid;
	int hidx;
	
	if(name == NULL || name->s==NULL || name->len<=0
			|| domain == NULL || domain->s==NULL || domain->len<=0)
	{
		LM_ERR("invalid parameters\n");
		return NULL;
	}
	
	hashid = core_case_hash(name, domain, 0);
	
	hidx = imc_get_hentry(hashid, imc_hash_size);

	lock_get(&_imc_htable[hidx].lock);
	irp = _imc_htable[hidx].rooms;

	while(irp)
	{
		if(irp->hashid==hashid && irp->name.len==name->len
				&& irp->domain.len==domain->len
				&& !strncasecmp(irp->name.s, name->s, name->len)
				&& !strncasecmp(irp->domain.s, domain->s, domain->len))
		{
			LM_DBG("room found: %s %s\n", name->s, domain->s);
			return irp;
		}
		irp = irp->next;
	}

	/* no room */
	lock_release(&_imc_htable[hidx].lock);

	return NULL;
}

/**
 * delete room
 * erase_database == 1, borra también de base de datos
 */
int imc_del_room(str* name, str* domain, char erase_database)
{
	imc_room_p irp = NULL;
	imc_member_p imp=NULL, imp_temp=NULL;
	unsigned int hashid;
	int hidx;	
	
	db_key_t mq_cols[3];
	db_val_t mq_vals[3];
	db_key_t rq_cols[2];
	db_val_t rq_vals[2];

	mq_cols[0] = &imc_col_username;
	mq_vals[0].type = DB_STR;
	mq_vals[0].nul = 0;

	mq_cols[1] = &imc_col_domain;
	mq_vals[1].type = DB_STR;
	mq_vals[1].nul = 0;

	mq_cols[2] = &imc_col_room;
	mq_vals[2].type = DB_STR;
	mq_vals[2].nul = 0;


	rq_cols[0] = &imc_col_name;
	rq_vals[0].type = DB_STR;
	rq_vals[0].nul = 0;

	rq_cols[1] = &imc_col_domain;
	rq_vals[1].type = DB_STR;
	rq_vals[1].nul = 0;


	if(name == NULL || name->s==NULL || name->len<=0
			|| domain == NULL || domain->s==NULL || domain->len<=0)
	{
		LM_ERR("invalid parameters\n");
		return -1;
	}
	
	hashid = core_case_hash(name, domain, 0);
	
	hidx = imc_get_hentry(hashid, imc_hash_size);
	
	lock_get(&_imc_htable[hidx].lock);
	irp = _imc_htable[hidx].rooms;
	while(irp)
	{
		if(irp->hashid==hashid && irp->name.len==name->len
				&& irp->domain.len==domain->len
				&& !strncasecmp(irp->name.s, name->s, name->len)
				&& !strncasecmp(irp->domain.s, domain->s, domain->len))
		{
			if(irp->prev==NULL)
				_imc_htable[hidx].rooms = irp->next;
			else
				irp->prev->next = irp->next;
			if(irp->next!=NULL)
				irp->next->prev = irp->prev;

			/* delete members */
			if(imc_dbf.use_table(imc_db, &members_table)< 0)
			{
				LM_ERR("use table failed\n ");
				goto done;
			}
			imp = irp->members;
			while(imp){

				if(erase_database == 1)
				{
					mq_vals[0].val.str_val = imp->user;
					mq_vals[1].val.str_val = imp->domain;
					mq_vals[2].val.str_val = irp->uri;
					if(imc_dbf.delete(imc_db, mq_cols, 0, mq_vals, 3)<0)
					{
						LM_ERR("failed to delete from table %s, imp %.*s, uri: %.*s \n",
														members_table.s, imp->user.len, imp->user.s, irp->uri.len, irp->uri.s);
						goto done;
					}
					else
					{
						LM_DBG("delete from table %s, imp %.*s, uri: %.*s \n",
														members_table.s, imp->user.len, imp->user.s, irp->uri.len, irp->uri.s);
					}
				}

				imp_temp = imp->next;
				shm_free(imp);
				imp = imp_temp;
			}		

			if(erase_database == 1)
			{
				rq_vals[0].val.str_val = irp->name;
				rq_vals[1].val.str_val = irp->domain;

				if(imc_dbf.use_table(imc_db, &rooms_table)< 0)
				{
					LM_ERR("use_table failed\n");
					goto done;
				}
				if(imc_dbf.delete(imc_db, rq_cols, 0, rq_vals, 2)<0)
				{
					LM_ERR("failed from delete in table %s, room %.*s \n", rooms_table.s, irp->name.len, irp->name.s);
					goto done;
				}
				else
				{
					LM_DBG("deleted from table %s, room %.*s \n", rooms_table.s, irp->name.len, irp->name.s);
				}
			}

			if(irp->alias.s != NULL)
			{
				shm_free(irp->alias.s);
			}
			shm_free(irp);

			goto done;
		}
		irp = irp->next;
	}

done:	
	lock_release(&_imc_htable[hidx].lock);

	return 0;
}



/**
 * delete room
 * erase_database == 1, borra también de base de datos
 */
int imc_set_room_alias(str* name, str* domain, char erase_database)
{
	imc_room_p irp = NULL;
	imc_member_p imp=NULL, imp_temp=NULL;
	unsigned int hashid;
	int hidx;

	db_key_t mq_cols[3];
	db_val_t mq_vals[3];
	db_key_t rq_cols[2];
	db_val_t rq_vals[2];

	mq_cols[0] = &imc_col_username;
	mq_vals[0].type = DB_STR;
	mq_vals[0].nul = 0;

	mq_cols[1] = &imc_col_domain;
	mq_vals[1].type = DB_STR;
	mq_vals[1].nul = 0;

	mq_cols[2] = &imc_col_room;
	mq_vals[2].type = DB_STR;
	mq_vals[2].nul = 0;


	rq_cols[0] = &imc_col_name;
	rq_vals[0].type = DB_STR;
	rq_vals[0].nul = 0;

	rq_cols[1] = &imc_col_domain;
	rq_vals[1].type = DB_STR;
	rq_vals[1].nul = 0;


	if(name == NULL || name->s==NULL || name->len<=0
			|| domain == NULL || domain->s==NULL || domain->len<=0)
	{
		LM_ERR("invalid parameters\n");
		return -1;
	}

	hashid = core_case_hash(name, domain, 0);

	hidx = imc_get_hentry(hashid, imc_hash_size);

	lock_get(&_imc_htable[hidx].lock);
	irp = _imc_htable[hidx].rooms;
	while(irp)
	{
		if(irp->hashid==hashid && irp->name.len==name->len
				&& irp->domain.len==domain->len
				&& !strncasecmp(irp->name.s, name->s, name->len)
				&& !strncasecmp(irp->domain.s, domain->s, domain->len))
		{
			if(irp->prev==NULL)
				_imc_htable[hidx].rooms = irp->next;
			else
				irp->prev->next = irp->next;
			if(irp->next!=NULL)
				irp->next->prev = irp->prev;

			/* delete members */
			if(imc_dbf.use_table(imc_db, &members_table)< 0)
			{
				LM_ERR("use table failed\n ");
				goto done;
			}
			imp = irp->members;
			while(imp){

				if(erase_database == 1)
				{
					mq_vals[0].val.str_val = imp->user;
					mq_vals[1].val.str_val = imp->domain;
					mq_vals[2].val.str_val = irp->uri;
					if(imc_dbf.delete(imc_db, mq_cols, 0, mq_vals, 3)<0)
					{
						LM_ERR("failed to delete from table %s, imp %.*s, uri: %.*s \n",
														members_table.s, imp->user.len, imp->user.s, irp->uri.len, irp->uri.s);
						goto done;
					}
					else
					{
						LM_DBG("delete from table %s, imp %.*s, uri: %.*s \n",
														members_table.s, imp->user.len, imp->user.s, irp->uri.len, irp->uri.s);
					}
				}

				imp_temp = imp->next;
				shm_free(imp);
				imp = imp_temp;
			}

			if(erase_database == 1)
			{
				rq_vals[0].val.str_val = irp->name;
				rq_vals[1].val.str_val = irp->domain;

				if(imc_dbf.use_table(imc_db, &rooms_table)< 0)
				{
					LM_ERR("use_table failed\n");
					goto done;
				}
				if(imc_dbf.delete(imc_db, rq_cols, 0, rq_vals, 2)<0)
				{
					LM_ERR("failed from delete in table %s, room %.*s \n", rooms_table.s, irp->name.len, irp->name.s);
					goto done;
				}
				else
				{
					LM_DBG("deleted from table %s, room %.*s \n", rooms_table.s, irp->name.len, irp->name.s);
				}
			}

			shm_free(irp);

			goto done;
		}
		irp = irp->next;
	}

done:
	lock_release(&_imc_htable[hidx].lock);

	return 0;
}

/**
 * add member
 */
imc_member_p imc_add_member(imc_room_p room, str* user, str* domain, int flags)
{
	imc_member_p imp = NULL;
	int size;
	
	if(room==NULL || user == NULL || user->s==NULL || user->len<=0
			|| domain == NULL || domain->s==NULL || domain->len<=0)
	{
		LM_ERR("invalid parameters\n");
		return NULL;
	}
	
	/* struct size + "sip:" + user name len + "@" + domain len + '\0' */
	size = sizeof(imc_member_t) + (user->len+domain->len+6)*sizeof(char);
	imp = (imc_member_p)shm_malloc(size);
	if(imp== NULL)
	{
		LM_ERR("out of shm memory\n");
		return NULL;
	}
	memset(imp, 0, size);
	
	imp->uri.len = 4 /*sip:*/ + user->len + 1 /*@*/ + domain->len;
	imp->uri.s = (char*)(((char*)imp)+sizeof(imc_member_t));
	memcpy(imp->uri.s, "sip:", 4);
	memcpy(imp->uri.s+4, user->s, user->len);
	imp->uri.s[4+user->len] = '@';
	memcpy(imp->uri.s+5+user->len, domain->s, domain->len);
	imp->uri.s[imp->uri.len] = '\0';
	
	LM_DBG("[uri]= %.*s\n", imp->uri.len, imp->uri.s);
	imp->user.len = user->len;
	imp->user.s = imp->uri.s+4;
	
	LM_DBG("[user]= %.*s\n", imp->user.len, imp->user.s);
	imp->domain.len = domain->len;
	imp->domain.s = imp->uri.s+5+user->len;

	imp->flags  = flags;
	imp->hashid = core_case_hash(&imp->user, &imp->domain, 0);

	room->nr_of_members++;
	
	if(room->members==NULL)
		room->members = imp;
	else {
		imp->next = room->members->next;
		if((room->members)->next!=NULL)
			((room->members)->next)->prev = imp;
		imp->prev = room->members;
		
		room->members->next=imp;
	}

	LM_DBG("%s %p flags=%d, %.*s \n",__FUNCTION__, imp, imp->flags, imp->uri.len, imp->uri.s);

	return imp;
}

/**
 * search memeber
 */
imc_member_p imc_get_member(imc_room_p room, str* user, str* domain)
{
	imc_member_p imp = NULL;
	unsigned int hashid;

	if(room==NULL || user == NULL || user->s==NULL || user->len<=0
			|| domain == NULL || domain->s==NULL || domain->len<=0)
	{
		LM_ERR("invalid parameters\n");
		return NULL;
	}
	
	hashid = core_case_hash(user, domain, 0);
	imp = room->members;
	while(imp)
	{
		if(imp->hashid==hashid && imp->user.len==user->len
				&& imp->domain.len==domain->len
				&& !strncasecmp(imp->user.s, user->s, user->len)
				&& !strncasecmp(imp->domain.s, domain->s, domain->len))
		{
			LM_DBG("found member\n");
			return imp;
		}
		imp = imp->next;
	}

	return NULL;
}

/**
 * delete member
 */
int imc_del_member(imc_room_p room, str* user, str* domain, char erase_database)
{
	imc_member_p imp = NULL;
	unsigned int hashid;
	
	db_key_t mq_cols[3];
	db_val_t mq_vals[3];

	mq_cols[0] = &imc_col_username;
	mq_vals[0].type = DB_STR;
	mq_vals[0].nul = 0;

	mq_cols[1] = &imc_col_domain;
	mq_vals[1].type = DB_STR;
	mq_vals[1].nul = 0;

	mq_cols[2] = &imc_col_room;
	mq_vals[2].type = DB_STR;
	mq_vals[2].nul = 0;


	if(room==NULL || user == NULL || user->s==NULL || user->len<=0
			|| domain == NULL || domain->s==NULL || domain->len<=0)
	{
		LM_ERR("invalid parameters\n");
		return -1;
	}
	
	hashid = core_case_hash(user, domain, 0);
	imp = room->members;
	while(imp)
	{
		if(imp->hashid==hashid && imp->user.len==user->len
				&& imp->domain.len==domain->len
				&& !strncasecmp(imp->user.s, user->s, user->len)
				&& !strncasecmp(imp->domain.s, domain->s, domain->len))
		{
			if(imp->prev==NULL)
				room->members = imp->next;
			else
				imp->prev->next = imp->next;
			if(imp->next!=NULL)
				imp->next->prev = imp->prev;

			if(erase_database == 1)
			{
				mq_vals[0].val.str_val = imp->user;
				mq_vals[1].val.str_val = imp->domain;
				mq_vals[2].val.str_val = room->uri;
				if(imc_dbf.delete(imc_db, mq_cols, 0, mq_vals, 3)<0)
				{
					LM_ERR("failed to delete from table %s, imp %.*s, uri: %.*s \n",
													members_table.s, imp->user.len, imp->user.s, room->uri.len, room->uri.s);
				}
				else
				{
					LM_DBG("delete from table %s, imp %.*s, uri: %.*s \n",
													members_table.s, imp->user.len, imp->user.s, room->uri.len, room->uri.s);
				}
			}

			shm_free(imp);
			room->nr_of_members--;
			return 0;
		}
		imp = imp->next;
	}
	
	return 0;
}


char* strcat_copy(const char *str1, const char *str2) {
    int str1_len, str2_len;
    char *new_str;

    /* null check */

    str1_len = strlen(str1);
    str2_len = strlen(str2);

    new_str = pkg_malloc(str1_len + str2_len + 1);

    /* null check */

    memcpy(new_str, str1, str1_len);
    memcpy(new_str + str1_len, str2, str2_len + 1);

    return new_str;
}

/**
 *
 */
int imc_handle_groups_internal(struct sip_uri *src, str *body)
{
	char body_buf[GROUPS_MAX_LINE_LEN];
	int i;
	imc_member_p member = 0;
	imc_room_p irp = NULL, irp_temp=NULL;
	char *p;
	char *result = NULL;
	if(_imc_htable==NULL)
		return -1;

	p =body_buf;

	snprintf(p, GROUPS_MAX_LINE_LEN, "Rooms:\n");
	p = p + strlen(p);

	for(i=0; i<imc_hash_size; i++)
	{
		lock_get(&_imc_htable[i].lock);
		if(_imc_htable[i].rooms==NULL)
		{
			lock_release(&_imc_htable[i].lock);
			continue;
		}
		irp = _imc_htable[i].rooms;
		while(irp){
			irp_temp = irp->next;
			/* verify if the user is a member of the room */
			member = imc_get_member(irp, &src->user, &src->host);

			if(member != NULL)
			{
				if(member->flags & IMC_MEMBER_OWNER)
				{
					*p++ = '*';
				}
				else if(member->flags & IMC_MEMBER_ADMIN)
				{
					*p++ = '~';
				}

				snprintf(p, GROUPS_MAX_LINE_LEN, "sip:%.*s@%.*s %.*s\n",irp->name.len,irp->name.s,irp->domain.len,irp->domain.s,irp->alias.len, irp->alias.s);

				if(result!=NULL)
				{
					char* resultAux = strcat_copy(result, body_buf);
					pkg_free(result);
					result = resultAux;
				}
				else
				{
					result = pkg_malloc(strlen(body_buf) + 1);
					memcpy(result,body_buf,strlen(body_buf)+1);
				}
				p =body_buf;
			}
			irp = irp_temp;
		}
		lock_release(&_imc_htable[i].lock);
	}

	body->s   = result;
	body->len = strlen(result);

	return 0;
}

