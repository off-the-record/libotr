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

#ifndef __PROTO_H__
#define __PROTO_H__

#include "context.h"
#include "version.h"
#include "tlv.h"

/* If we ever see this sequence in a plaintext message, we'll assume the
 * other side speaks OTR, and try to establish a connection. */
#define OTR_MESSAGE_TAG " \t  \t\t\t\t \t \t \t   \t \t  \t "
    /* This is the bit sequence of the string "OTR", encoded in tabs and
     * spaces. */

typedef enum {
    OTR_NOTOTR,
    OTR_TAGGEDPLAINTEXT,
    OTR_QUERY,
    OTR_KEYEXCH,
    OTR_DATA,
    OTR_ERROR,
    OTR_UNKNOWN
} OTRMessageType;

typedef struct s_OTRKeyExchangeMsg {
    gcry_sexp_t digest_sexp;              /* SHA-1 hash of the raw message,
					     except for the DSA sig; used
					     for checking the sig */
    unsigned char is_reply;               /* Was this a reply to a Key
					     Exchange Message we sent
					     them? */
    unsigned char key_fingerprint[20];    /* The key fingerprint */
    gcry_sexp_t dsa_pubkey;               /* DSA public key */
    unsigned int keyid;                   /* DH key id */
    gcry_mpi_t dh_pubkey;                 /* DH public key */
    gcry_sexp_t dsa_sig;                  /* Signature on packet */
} * OTRKeyExchangeMsg;

/* Initialize the OTR library.  Pass the version of the API you are
 * using. */
void otrl_init(unsigned int ver_major, unsigned int ver_minor,
	unsigned int ver_sub);

/* Shortcut */
#define OTRL_INIT do { \
	otrl_init(OTRL_VERSION_MAJOR, OTRL_VERSION_MINOR, OTRL_VERSION_SUB); \
    } while(0)

/* Return a pointer to a static string containing the version number of
 * the OTR library. */
const char *otrl_version(void);

/* Create a public key block from a private key */
gcry_error_t otrl_proto_make_pubkey(unsigned char **pubbufp, size_t *publenp,
	gcry_sexp_t privkey);

/* Return a pointer to a newly-allocated OTR query message, customized
 * with our name.  The caller should free() the result when he's done
 * with it. */
char *otrl_proto_default_query_msg(const char *ourname);

/* Return the Message type of the given message. */
OTRMessageType otrl_proto_message_type(const char *message);

/* Create a Key Exchange message for our correspondent.  If we need a
 * private key and don't have one, create_privkey will be called.  Use
 * the privkeys from the given OtrlUserState. */
gcry_error_t otrl_proto_create_key_exchange(OtrlUserState us,
	char **messagep, ConnContext *context, unsigned char is_reply,
	void (*create_privkey)(void *create_privkey_data,
	    const char *accountname, const char *protocol),
	void *create_privkey_data);

/* Deallocate an OTRKeyExchangeMsg returned from proto_parse_key_exchange */
void otrl_proto_free_key_exchange(OTRKeyExchangeMsg kem);

/* Parse a purported Key Exchange message.  Possible error code portions
 * of the return value:
 *   GPG_ERR_NO_ERROR:      Success
 *   GPG_ERR_ENOMEM:        Out of memory condition
 *   GPG_ERR_INV_VALUE:     The message was not a well-formed Key Exchange
 *                          message
 *   GPG_ERR_BAD_SIGNATURE: The signature on the message didn't verify
 */
gcry_error_t otrl_proto_parse_key_exchange(OTRKeyExchangeMsg *kemp,
	const char *msg);

/* Deal with a Key Exchange Message once it's been received and passed
 * all the validity and UI ("accept this fingerprint?") tests.
 * context/fprint is the ConnContext and Fingerprint to which it
 * belongs.  Use the given OtrlUserState to look up any necessary
 * private keys.  It is the caller's responsibility to
 * otrl_proto_free_key_exchange(kem) when we're done.  If *messagep gets
 * set to non-NULL by this function, then it's a message that needs to
 * get sent to the correspondent.  If we need a private key and don't
 * have one, create_privkey will be called. */
gcry_error_t otrl_proto_accept_key_exchange(OtrlUserState us,
	ConnContext *context, Fingerprint *fprint, OTRKeyExchangeMsg kem,
	char **messagep,
	void (*create_privkey)(void *create_privkey_data,
	    const char *accountname, const char *protocol),
	void *create_privkey_data);

/* Create an OTR Data message.  Pass the plaintext as msg, and an
 * optional chain of TLVs.  A newly-allocated string will be returned in
 * *encmessagep. */
gcry_error_t otrl_proto_create_data(char **encmessagep, ConnContext *context,
	const char *msg, const OtrlTLV *tlvs);

/* Accept an OTR Data Message in datamsg.  Decrypt it and put the
 * plaintext into *plaintextp, and any TLVs into tlvsp. */
gcry_error_t otrl_proto_accept_data(char **plaintextp, OtrlTLV **tlvsp,
	ConnContext *context, const char *datamsg);

#endif
