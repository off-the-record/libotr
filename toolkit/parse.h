/*
 *  Off-the-Record Messaging Toolkit
 *  Copyright (C) 2004-2005  Nikita Borisov and Ian Goldberg
 *                           <otr@cypherpunks.ca>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of version 2 of the GNU General Public License as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __PARSE_H__
#define __PARSE_H__

#include <gcrypt.h>

typedef struct s_KeyExchMsg {
    unsigned char *raw;         /* The base64-decoded data; must be free()d */
    unsigned char reply;
    gcry_mpi_t p, q, g, e;
    unsigned int keyid;
    gcry_mpi_t y;
    gcry_mpi_t r, s;
    unsigned char *sigstart;    /* Pointers into the "raw" array.  Don't */
    unsigned char *sigend;      /*   free() these. */
} * KeyExchMsg;

typedef struct s_DataMsg {
    unsigned char *raw;         /* The base64-decoded data; must be free()d */
    size_t rawlen;
    unsigned int sender_keyid;
    unsigned int rcpt_keyid;
    gcry_mpi_t y;
    unsigned char ctr[8];
    unsigned char *encmsg;      /* A copy; must be free()d */
    size_t encmsglen;
    unsigned char mac[20];
    unsigned char *mackeys;     /* A copy; must be free()d */
    size_t mackeyslen;
    unsigned char *macstart;    /* Pointers into the "raw" array.  Don't */
    unsigned char *macend;      /*   free() these. */
} * DataMsg;

/* Dump an unsigned int to a FILE * */
void dump_int(FILE *stream, const char *title, unsigned int val);

/* Dump an mpi to a FILE * */
void dump_mpi(FILE *stream, const char *title, gcry_mpi_t val);

/* Dump data to a FILE * */
void dump_data(FILE *stream, const char *title, const unsigned char *data,
	size_t datalen);

/* Parse a Key Exchange Message into a newly-allocated KeyExchMsg structure */
KeyExchMsg parse_keyexch(const char *msg);

/* Deallocate a KeyExchMsg and all of the data it points to */
void free_keyexch(KeyExchMsg keyexch);

/* Parse a Data Message into a newly-allocated DataMsg structure */
DataMsg parse_datamsg(const char *msg);

/* Recalculate the MAC on the message, base64-encode the resulting MAC'd
 * message, and put on the appropriate header and footer.  Return a
 * newly-allocated pointer to the result, which the caller will have to
 * free(). */
char *remac_datamsg(DataMsg datamsg, unsigned char mackey[20]);

/* Assemble a new Data Message from its pieces.  Return a
 * newly-allocated string containing the base64 representation. */
char *assemble_datamsg(unsigned char mackey[20], unsigned int sender_keyid,
	unsigned int rcpt_keyid, gcry_mpi_t y, unsigned char ctr[8],
	unsigned char *encmsg, size_t encmsglen, unsigned char *mackeys,
	size_t mackeyslen);

/* Deallocate a DataMsg and all of the data it points to */
void free_datamsg(DataMsg datamsg);

/* Convert a string of hex chars to a buffer of unsigned chars. */
void argv_to_buf(unsigned char **bufp, size_t *lenp, char *arg);

#endif
