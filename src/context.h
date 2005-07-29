/*
 *  Off-the-Record Messaging library
 *  Copyright (C) 2004-2005  Nikita Borisov and Ian Goldberg
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

#include "gcrypt.h"
#include "dh.h"

typedef enum {
    CONN_UNCONNECTED,
    CONN_SETUP,
    CONN_CONNECTED
} ConnectionState;

typedef struct fingerprint {
    struct fingerprint *next;          /* The next fingerprint in the list */
    struct fingerprint **tous;         /* A pointer to the pointer to us */
    unsigned char *fingerprint;        /* The fingerprint, or NULL */
    struct context *context;           /* The context to which we belong */
    char *trust;                       /* The trust level of the fingerprint */
} Fingerprint;

typedef struct context {
    struct context * next;             /* Linked list pointer */
    struct context ** tous;            /* A pointer to the pointer to us */

    char * username;                   /* The user this context is for */
    char * accountname;                /* The username is relative to
					  this account... */
    char * protocol;                   /* ... and this protocol */
    ConnectionState state;             /* The state of our connection to this
					  user */
    Fingerprint fingerprint_root;      /* The root of a linked list of
					  Fingerprints entries */
    Fingerprint *active_fingerprint;   /* Which fingerprint is in use now?
                                          A pointer into the above list */
    unsigned int their_keyid;          /* current keyid used by other side;
                                          this is set to 0 if we get a
					  OTRL_TLV_DISCONNECTED message from
					  them. */
    gcry_mpi_t their_y;                /* Y[their_keyid] (their DH pubkey) */
    gcry_mpi_t their_old_y;            /* Y[their_keyid-1] (their prev DH
					  pubkey) */
    unsigned int our_keyid;            /* current keyid used by us */
    DH_keypair our_dh_key;             /* DH key[our_keyid] */
    DH_keypair our_old_dh_key;         /* DH key[our_keyid-1] */

    DH_sesskeys sesskeys[2][2];        /* sesskeys[i][j] are the session keys
					  derived from DH key[our_keyid-i]
					  and mpi Y[their_keyid-j] */

    unsigned char sessionid[20];       /* The sessionid and direction */
    SessionDirection sessiondir;       /* determined when this private
					  connection was established. */

    unsigned char *preshared_secret;   /* A secret you share with this
					  user, in order to do
					  authentication. */
    size_t preshared_secret_len;       /* The length of the above secret. */

    /* saved mac keys to be revealed later */
    unsigned int numsavedkeys;
    unsigned char *saved_mac_keys;

    /* generation number: increment every time we go private, and never
     * reset to 0 (unless we remove the context entirely) */
    unsigned int generation;

    time_t lastsent;      /* The last time a Data Message was sent */
    char *lastmessage;    /* The plaintext of the last Data Message sent */
    int may_retransmit;   /* Is the last message eligible for
			     retransmission? */

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
} ConnContext;

#include "userstate.h"

/* Strings describing the connection states */
extern const char *otrl_context_statestr[];

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

/* Set the preshared secret for a given fingerprint.  Note that this
 * currently only stores the secret in the ConnContext structure, but
 * doesn't yet do anything with it. */
void otrl_context_set_preshared_secret(ConnContext *context,
	const unsigned char *secret, size_t secret_len);

/* Force a context into the CONN_SETUP state (so that it only has local
 * DH keys). */
void otrl_context_force_setup(ConnContext *context);

/* Force a context into the CONN_UNCONNECTED state. */
void otrl_context_force_disconnect(ConnContext *context);

/* Forget a fingerprint (so long as it's not the active one.  If it's a
 * fingerprint_root, forget the whole context (as long as
 * and_maybe_context is set, and it's UNCONNECTED).  Also, if it's not
 * the fingerprint_root, but it's the only fingerprint, and we're
 * UNCONNECTED, forget the whole context if and_maybe_context is set. */
void otrl_context_forget_fingerprint(Fingerprint *fprint,
	int and_maybe_context);

/* Forget a whole context, so long as it's UNCONNECTED. */
void otrl_context_forget(ConnContext *context);

/* Forget all the contexts in a given OtrlUserState, forcing them to
 * UNCONNECTED. */
void otrl_context_forget_all(OtrlUserState us);

#endif
