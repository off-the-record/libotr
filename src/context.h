/*
 *  Off-the-Record Messaging library
 *  Copyright (C) 2004-2009  Ian Goldberg, Chris Alexander, Willy Lew,
 *  			     Nikita Borisov
 *                           <otr@cypherpunks.ca>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of version 2.1 of the GNU Lesser General
 *  Public License as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __CONTEXT_H__
#define __CONTEXT_H__

#include "context_priv.h"

#include <gcrypt.h>

#include "dh.h"
#include "auth.h"
#include "sm.h"

typedef enum {
    OTRL_MSGSTATE_PLAINTEXT,           /* Not yet started an encrypted
					  conversation */
    OTRL_MSGSTATE_ENCRYPTED,           /* Currently in an encrypted
					  conversation */
    OTRL_MSGSTATE_FINISHED             /* The remote side has sent us a
					  notification that he has ended
					  his end of the encrypted
					  conversation; prevent any
					  further messages from being
					  sent to him. */
} OtrlMessageState;

typedef struct s_fingerprint {
    struct s_fingerprint *next;        /* The next fingerprint in the list */
    struct s_fingerprint **tous;       /* A pointer to the pointer to us */
    unsigned char *fingerprint;        /* The fingerprint, or NULL */
    struct context *context;           /* The context to which we belong */
    char *trust;                       /* The trust level of the fingerprint */
} Fingerprint;

typedef struct context {
    struct context * next;             /* Linked list pointer */
    struct context ** tous;            /* A pointer to the pointer to us */

    /* Context information that is meant for internal use */

    ConnContextPriv *context_priv;

    /* Context information that is meant for application use */

    char * username;                   /* The user this context is for */
    char * accountname;                /* The username is relative to
					  this account... */
    char * protocol;                   /* ... and this protocol */

    OtrlMessageState msgstate;         /* The state of message disposition
					  with this user */
    OtrlAuthInfo auth;                 /* The state of ongoing
					  authentication with this user */

    Fingerprint fingerprint_root;      /* The root of a linked list of
					  Fingerprints entries */
    Fingerprint *active_fingerprint;   /* Which fingerprint is in use now?
                                          A pointer into the above list */

    unsigned char sessionid[20];       /* The sessionid and bold half */
    size_t sessionid_len;              /* determined when this private */
    OtrlSessionIdHalf sessionid_half;  /* connection was established. */

    unsigned int protocol_version;     /* The version of OTR in use */

    enum {
	OFFER_NOT,
	OFFER_SENT,
	OFFER_REJECTED,
	OFFER_ACCEPTED
    } otr_offer;          /* Has this correspondent repsponded to our
			     OTR offers? */

    /* Application data to be associated with this context */
    void *app_data;
    /* A function to free the above data when we forget this context */
    void (*app_data_free)(void *);

    OtrlSMState *smstate;              /* The state of the current
                                          socialist millionaires exchange */
} ConnContext;

#include "userstate.h"

/* Look up a connection context by name/account/protocol from the given
 * OtrlUserState.  If add_if_missing is true, allocate and return a new
 * context if one does not currently exist.  In that event, call
 * add_app_data(data, context) so that app_data and app_data_free can be
 * filled in by the application, and set *addedp to 1. */
ConnContext * otrl_context_find(OtrlUserState us, const char *user,
	const char *accountname, const char *protocol, int add_if_missing,
	int *addedp,
	void (*add_app_data)(void *data, ConnContext *context), void *data);

/* Find a fingerprint in a given context, perhaps adding it if not
 * present. */
Fingerprint *otrl_context_find_fingerprint(ConnContext *context,
	unsigned char fingerprint[20], int add_if_missing, int *addedp);

/* Set the trust level for a given fingerprint */
void otrl_context_set_trust(Fingerprint *fprint, const char *trust);

/* Force a context into the OTRL_MSGSTATE_FINISHED state. */
void otrl_context_force_finished(ConnContext *context);

/* Force a context into the OTRL_MSGSTATE_PLAINTEXT state. */
void otrl_context_force_plaintext(ConnContext *context);

/* Forget a fingerprint (so long as it's not the active one.  If it's a
 * fingerprint_root, forget the whole context (as long as
 * and_maybe_context is set, and it's PLAINTEXT).  Also, if it's not
 * the fingerprint_root, but it's the only fingerprint, and we're
 * PLAINTEXT, forget the whole context if and_maybe_context is set. */
void otrl_context_forget_fingerprint(Fingerprint *fprint,
	int and_maybe_context);

/* Forget a whole context, so long as it's PLAINTEXT. */
void otrl_context_forget(ConnContext *context);

/* Forget all the contexts in a given OtrlUserState. */
void otrl_context_forget_all(OtrlUserState us);

#endif
