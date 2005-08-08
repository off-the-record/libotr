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

/* system headers */
#include <stdio.h>
#include <stdlib.h>

/* libotr headers */
#include "proto.h"

/* toolkit headers */
#include "readotr.h"
#include "parse.h"

static void parse(const char *msg)
{
    OTRMessageType mtype = otrl_proto_message_type(msg);
    KeyExchMsg keyexch;
    DataMsg datamsg;

    switch(mtype) {
	case OTR_QUERY:
	    printf("OTR Query:\n\t%s\n\n", msg);
	    break;
	case OTR_KEYEXCH:
	    keyexch = parse_keyexch(msg);
	    if (!keyexch) {
		printf("Invalid Key Exchange Message\n\n");
		break;
	    }
	    printf("Key Exchange Message:\n");
	    dump_int(stdout, "\tReply", keyexch->reply);
	    dump_mpi(stdout, "\tDSA p", keyexch->p);
	    dump_mpi(stdout, "\tDSA q", keyexch->q);
	    dump_mpi(stdout, "\tDSA g", keyexch->g);
	    dump_mpi(stdout, "\tDSA e", keyexch->e);
	    dump_int(stdout, "\tKeyID", keyexch->keyid);
	    dump_mpi(stdout, "\tDH y", keyexch->y);
	    dump_mpi(stdout, "\tSIG r", keyexch->r);
	    dump_mpi(stdout, "\tSIG s", keyexch->s);
	    printf("\n");
	    free_keyexch(keyexch);
	    break;
	case OTR_DATA:
	    datamsg = parse_datamsg(msg);
	    if (!datamsg) {
		printf("Invalid Data Message\n\n");
		break;
	    }
	    printf("Data Message:\n");
	    dump_int(stdout, "\tSender keyid", datamsg->sender_keyid);
	    dump_int(stdout, "\tRcpt keyid", datamsg->rcpt_keyid);
	    dump_mpi(stdout, "\tDH y", datamsg->y);
	    dump_data(stdout, "\tCounter", datamsg->ctr, 8);
	    dump_data(stdout, "\tEncrypted message", datamsg->encmsg,
		    datamsg->encmsglen);
	    dump_data(stdout, "\tMAC", datamsg->mac, 20);
	    if (datamsg->mackeyslen > 0) {
		size_t len = datamsg->mackeyslen;
		unsigned char *mks = datamsg->mackeys;
		unsigned int i = 0;
		printf("\tRevealed MAC keys:\n");

		while(len > 19) {
		    char title[20];
		    sprintf(title, "\t\tKey %u", ++i);
		    dump_data(stdout, title, mks, 20);
		    mks += 20; len -= 20;
		}
	    }

	    printf("\n");
	    free_datamsg(datamsg);
	    break;
	case OTR_ERROR:
	    printf("OTR Error:\n\t%s\n\n", msg);
	    break;
	case OTR_TAGGEDPLAINTEXT:
	    printf("Tagged plaintext message:\n\t%s\n\n", msg);
	    break;
	case OTR_NOTOTR:
	    printf("Not an OTR message:\n\t%s\n\n", msg);
	    break;
	case OTR_UNKNOWN:
	    printf("Unrecognized OTR message:\n\t%s\n\n", msg);
	    break;
    }
    fflush(stdout);
}

static void usage(const char *progname)
{
    fprintf(stderr, "Usage: %s\n"
"Read Off-the-Record (OTR) Key Exchange and/or Data messages from stdin\n"
"and display their contents in a more readable format.\n", progname);
    exit(1);
}

int main(int argc, char **argv)
{
    char *otrmsg = NULL;

    if (argc != 1) {
	usage(argv[0]);
    }

    while ((otrmsg = readotr(stdin)) != NULL) {
	parse(otrmsg);
	free(otrmsg);
    }

    return 0;
}
