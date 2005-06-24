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

/* OTR Protocol implementation.  This file should be independent of
 * gaim, so that it can be used to make other clients. */

/* system headers */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/* libgcrypt headers */
#include <gcrypt.h>

/* libotr headers */
#include "b64.h"
#include "privkey.h"
#include "proto.h"
#include "mem.h"
#include "version.h"
#include "tlv.h"

#undef DEBUG

#ifdef DEBUG
static void debug_data(const char *title, const unsigned char *data,
	size_t len)
{
    size_t i;
    fprintf(stderr, "%s: ", title);
    for(i=0;i<len;++i) {
	fprintf(stderr, "%02x", data[i]);
    }
    fprintf(stderr, "\n");
}

static void debug_int(const char *title, const unsigned char *data)
{
    unsigned int v =
	(data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    fprintf(stderr, "%s: %u (0x%x)\n", title, v, v);
}
#else
#define debug_data(t,b,l)
#define debug_int(t,b)
#endif

#define write_int(x) do { \
	bufp[0] = ((x) >> 24) & 0xff; \
	bufp[1] = ((x) >> 16) & 0xff; \
	bufp[2] = ((x) >> 8) & 0xff; \
	bufp[3] = (x) & 0xff; \
	bufp += 4; lenp -= 4; \
    } while(0)

#define write_mpi(x,nx,dx) do { \
	write_int(nx); \
	gcry_mpi_print(format, bufp, lenp, NULL, (x)); \
	debug_data((dx), bufp, (nx)); \
	bufp += (nx); lenp -= (nx); \
    } while(0)

#define require_len(l) do { \
	if (lenp < (l)) goto invval; \
    } while(0)

#define read_int(x) do { \
	require_len(4); \
	(x) = (bufp[0] << 24) | (bufp[1] << 16) | (bufp[2] << 8) | bufp[3]; \
	bufp += 4; lenp -= 4; \
    } while(0)

#define read_mpi(x) do { \
	size_t mpilen; \
	read_int(mpilen); \
	require_len(mpilen); \
	gcry_mpi_scan(&(x), GCRYMPI_FMT_USG, bufp, mpilen, NULL); \
	bufp += mpilen; lenp -= mpilen; \
    } while(0)

/* Initialize the OTR library.  Pass the version of the API you are
 * using. */
void otrl_init(unsigned int ver_major, unsigned int ver_minor,
	unsigned int ver_sub)
{
    /* The major versions have to match, and you can't be using a newer
     * minor version than we expect. */
    if (ver_major != OTRL_VERSION_MAJOR || ver_minor > OTRL_VERSION_MINOR) {
	fprintf(stderr, "Expected libotr API version %u.%u.%u incompatible "
		"with actual version %u.%u.%u.  Aborting.\n",
		ver_major, ver_minor, ver_sub,
		OTRL_VERSION_MAJOR, OTRL_VERSION_MINOR, OTRL_VERSION_SUB);
	exit(1);
    }

    /* Initialize the memory module */
    otrl_mem_init();

    /* Initialize the DH module */
    otrl_dh_init();
}

/* Return a pointer to a static string containing the version number of
 * the OTR library. */
const char *otrl_version(void)
{
    return OTRL_VERSION;
}

/* Create a public key block from a private key */
gcry_error_t otrl_proto_make_pubkey(unsigned char **pubbufp, size_t *publenp,
	gcry_sexp_t privkey)
{
    gcry_mpi_t p,q,g,y;
    gcry_sexp_t dsas,ps,qs,gs,ys;
    size_t np,nq,ng,ny;
    enum gcry_mpi_format format = GCRYMPI_FMT_USG;
    unsigned char *bufp;
    size_t lenp;

    *pubbufp = NULL;
    *publenp = 0;

    /* Extract the public parameters */
    dsas = gcry_sexp_find_token(privkey, "dsa", 0);
    if (dsas == NULL) {
	return gcry_error(GPG_ERR_UNUSABLE_SECKEY);
    }
    ps = gcry_sexp_find_token(dsas, "p", 0);
    qs = gcry_sexp_find_token(dsas, "q", 0);
    gs = gcry_sexp_find_token(dsas, "g", 0);
    ys = gcry_sexp_find_token(dsas, "y", 0);
    gcry_sexp_release(dsas);
    if (!ps || !qs || !gs || !ys) {
	gcry_sexp_release(ps);
	gcry_sexp_release(qs);
	gcry_sexp_release(gs);
	gcry_sexp_release(ys);
	return gcry_error(GPG_ERR_UNUSABLE_SECKEY);
    }
    p = gcry_sexp_nth_mpi(ps, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(ps);
    q = gcry_sexp_nth_mpi(qs, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(qs);
    g = gcry_sexp_nth_mpi(gs, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(gs);
    y = gcry_sexp_nth_mpi(ys, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(ys);
    if (!p || !q || !g || !y) {
	gcry_mpi_release(p);
	gcry_mpi_release(q);
	gcry_mpi_release(g);
	gcry_mpi_release(y);
	return gcry_error(GPG_ERR_UNUSABLE_SECKEY);
    }

    *publenp = 0;
    gcry_mpi_print(format, NULL, 0, &np, p);
    *publenp += np + 4;
    gcry_mpi_print(format, NULL, 0, &nq, q);
    *publenp += nq + 4;
    gcry_mpi_print(format, NULL, 0, &ng, g);
    *publenp += ng + 4;
    gcry_mpi_print(format, NULL, 0, &ny, y);
    *publenp += ny + 4;

    *pubbufp = malloc(*publenp);
    if (*pubbufp == NULL) {
	gcry_mpi_release(p);
	gcry_mpi_release(q);
	gcry_mpi_release(g);
	gcry_mpi_release(y);
	return gcry_error(GPG_ERR_ENOMEM);
    }
    bufp = *pubbufp;
    lenp = *publenp;

    write_mpi(p,np,"P");
    write_mpi(q,nq,"Q");
    write_mpi(g,ng,"G");
    write_mpi(y,ny,"Y");

    gcry_mpi_release(p);
    gcry_mpi_release(q);
    gcry_mpi_release(g);
    gcry_mpi_release(y);

    return gcry_error(GPG_ERR_NO_ERROR);
}

/* Store some MAC keys to be revealed later */
static gcry_error_t reveal_macs(ConnContext *context,
	DH_sesskeys *sess1, DH_sesskeys *sess2)
{
    unsigned int numnew = sess1->rcvmacused + sess1->sendmacused +
	sess2->rcvmacused + sess2->sendmacused;
    unsigned int newnumsaved;
    unsigned char *newmacs;
    
    /* Is there anything to do? */
    if (numnew == 0) return gcry_error(GPG_ERR_NO_ERROR);

    newnumsaved = context->numsavedkeys + numnew;
    newmacs = realloc(context->saved_mac_keys,
	    newnumsaved * 20);
    if (!newmacs) {
	return gcry_error(GPG_ERR_ENOMEM);
    }
    if (sess1->rcvmacused) {
	memmove(newmacs + context->numsavedkeys * 20, sess1->rcvmackey, 20);
	context->numsavedkeys++;
    }
    if (sess1->sendmacused) {
	memmove(newmacs + context->numsavedkeys * 20, sess1->sendmackey, 20);
	context->numsavedkeys++;
    }
    if (sess2->rcvmacused) {
	memmove(newmacs + context->numsavedkeys * 20, sess2->rcvmackey, 20);
	context->numsavedkeys++;
    }
    if (sess2->sendmacused) {
	memmove(newmacs + context->numsavedkeys * 20, sess2->sendmackey, 20);
	context->numsavedkeys++;
    }
    context->saved_mac_keys = newmacs;

    return gcry_error(GPG_ERR_NO_ERROR);
}

/* Make a new DH key for us, and rotate old old ones.  Be sure to keep
 * the sesskeys array in sync. */
static gcry_error_t rotate_dh_keys(ConnContext *context)
{
    gcry_error_t err;

    /* Rotate the keypair */
    otrl_dh_keypair_free(&(context->our_old_dh_key));
    memmove(&(context->our_old_dh_key), &(context->our_dh_key),
	    sizeof(DH_keypair));

    /* Rotate the session keys */
    err = reveal_macs(context, &(context->sesskeys[1][0]),
	    &(context->sesskeys[1][1]));
    if (err) return err;
    otrl_dh_session_free(&(context->sesskeys[1][0]));
    otrl_dh_session_free(&(context->sesskeys[1][1]));
    memmove(&(context->sesskeys[1][0]), &(context->sesskeys[0][0]),
	    sizeof(DH_sesskeys));
    memmove(&(context->sesskeys[1][1]), &(context->sesskeys[0][1]),
	    sizeof(DH_sesskeys));

    /* Create a new DH key */
    otrl_dh_gen_keypair(DH1536_GROUP_ID, &(context->our_dh_key));
    context->our_keyid++;

    /* Make the session keys */
    if (context->their_y) {
	err = otrl_dh_session(&(context->sesskeys[0][0]),
		&(context->our_dh_key), context->their_y);
	if (err) return err;
    }
    if (context->their_old_y) {
	err = otrl_dh_session(&(context->sesskeys[0][1]),
		&(context->our_dh_key), context->their_old_y);
	if (err) return err;
    }
    return gcry_error(GPG_ERR_NO_ERROR);
}

/* Rotate in a new DH public key for our correspondent.  Be sure to keep
 * the sesskeys array in sync. */
static gcry_error_t rotate_y_keys(ConnContext *context, gcry_mpi_t new_y)
{
    gcry_error_t err;

    /* Rotate the public key */
    gcry_mpi_release(context->their_old_y);
    context->their_old_y = context->their_y;

    /* Rotate the session keys */
    err = reveal_macs(context, &(context->sesskeys[0][1]),
	    &(context->sesskeys[1][1]));
    if (err) return err;
    otrl_dh_session_free(&(context->sesskeys[0][1]));
    otrl_dh_session_free(&(context->sesskeys[1][1]));
    memmove(&(context->sesskeys[0][1]), &(context->sesskeys[0][0]),
	    sizeof(DH_sesskeys));
    memmove(&(context->sesskeys[1][1]), &(context->sesskeys[1][0]),
	    sizeof(DH_sesskeys));

    /* Copy in the new public key */
    context->their_y = gcry_mpi_copy(new_y);
    context->their_keyid++;

    /* Make the session keys */
    err = otrl_dh_session(&(context->sesskeys[0][0]),
	    &(context->our_dh_key), context->their_y);
    if (err) return err;
    err = otrl_dh_session(&(context->sesskeys[1][0]),
	    &(context->our_old_dh_key), context->their_y);
    if (err) return err;

    return gcry_error(GPG_ERR_NO_ERROR);
}

/* Return a pointer to a newly-allocated OTR query message, customized
 * with our name.  The caller should free() the result when he's done
 * with it. */
char *otrl_proto_default_query_msg(const char *ourname)
{
    char *msg;
    /* Don't use g_strdup_printf here, because someone (not us) is going
     * to free() the *message pointer, not g_free() it.  We can't
     * require that they g_free() it, because this pointer will probably
     * get passed to the main IM application for processing (and
     * free()ing). */
    const char *format = "?OTR?\n<b>%s</b> has requested an "
	    "<a href=\"http://www.cypherpunks.ca/otr/\">Off-the-Record "
	    "private conversation</a>.  However, you do not have a plugin "
	    "to support that.\nSee <a href=\"http://www.cypherpunks.ca/otr/\">"
	    "http://www.cypherpunks.ca/otr/</a> for more information.";

    /* Remove "%s", add '\0' */
    msg = malloc(strlen(format) + strlen(ourname) - 1);
    if (!msg) return NULL;
    sprintf(msg, format, ourname);
    return msg;
}

/* Return the Message type of the given message. */
OTRMessageType otrl_proto_message_type(const char *message)
{
    char *otrtag;

    otrtag = strstr(message, "?OTR");

    if (!otrtag) {
	if (strstr(message, OTR_MESSAGE_TAG)) {
	    return OTR_TAGGEDPLAINTEXT;
	} else {
	    return OTR_NOTOTR;
	}
    }

    if (!strncmp(otrtag, "?OTR?", 5)) return OTR_QUERY;
    if (!strncmp(otrtag, "?OTR:AAEK", 9)) return OTR_KEYEXCH;
    if (!strncmp(otrtag, "?OTR:AAED", 9)) return OTR_DATA;
    if (!strncmp(otrtag, "?OTR Error:", 11)) return OTR_ERROR;

    return OTR_UNKNOWN;
}

/* Create a Key Exchange message for our correspondent.  If we need a
 * private key and don't have one, create_privkey will be called.  Use
 * the privkeys from the given OtrlUserState. */
gcry_error_t otrl_proto_create_key_exchange(OtrlUserState us,
	char **messagep, ConnContext *context, unsigned char is_reply,
	void (*create_privkey)(void *create_privkey_data,
	    const char *accountname, const char *protocol),
	void *create_privkey_data)
{
    gcry_mpi_t r, s;
    gcry_sexp_t dsas, rs, ss;
    gcry_sexp_t sigs, hashs;
    size_t nr, ns, buflen, lenp;
    unsigned char *buf, *bufp;
    enum gcry_mpi_format format = GCRYMPI_FMT_USG;
    unsigned char digest[20];
    gcry_mpi_t digestmpi;
    char *base64buf;
    size_t base64len;
    size_t pubkeylen;
    PrivKey *privkey =
	otrl_privkey_find(us, context->accountname, context->protocol);

    *messagep = NULL;

    if (privkey == NULL) {
	/* We've got no private key! */
	if (create_privkey) {
	    create_privkey(create_privkey_data, context->accountname,
		    context->protocol);
	    privkey =
		otrl_privkey_find(us, context->accountname, context->protocol);
	}
    }
    if (privkey == NULL) {
	/* We've still got no private key! */
	return gcry_error(GPG_ERR_UNUSABLE_SECKEY);
    }
    
    /* Make sure we have two keys */
    while (context->our_keyid < 2) {
	rotate_dh_keys(context);
    }

    buflen = 3 + 1 + privkey->pubkey_datalen + 4 + 40;
	/* header, is_reply, pubkey, keyid, sig */
    gcry_mpi_print(format, NULL, 0, &pubkeylen, context->our_old_dh_key.pub);
    buflen += pubkeylen + 4;
    buf = malloc(buflen);
    if (buf == NULL) {
	return gcry_error(GPG_ERR_ENOMEM);
    }
    bufp = buf;
    lenp = buflen;
    memmove(bufp, "\x00\x01\x0a", 3);  /* header */
    debug_data("Header", bufp, 3);
    bufp += 3; lenp -= 3;

    *bufp = is_reply;                  /* is_reply */
    debug_data("Reply", bufp, 1);
    bufp += 1; lenp -= 1;

                                       /* DSA pubkey */
    memmove(bufp, privkey->pubkey_data, privkey->pubkey_datalen);
    debug_data("DSA key", bufp, privkey->pubkey_datalen);
    bufp += privkey->pubkey_datalen; lenp -= privkey->pubkey_datalen;

                                       /* keyid */
    write_int(context->our_keyid - 1);
    debug_int("Keyid", bufp - 4);

                                       /* DH pubkey */
    write_mpi(context->our_old_dh_key.pub, pubkeylen, "Pubkey");

    /* Get a hash of the data to be signed */
    gcry_md_hash_buffer(GCRY_MD_SHA1, digest, buf, bufp-buf);
    gcry_mpi_scan(&digestmpi, GCRYMPI_FMT_USG, digest, 20, NULL);

    /* Calculate the sig */
    gcry_sexp_build(&hashs, NULL, "(%m)", digestmpi);
    gcry_mpi_release(digestmpi);
    gcry_pk_sign(&sigs, hashs, privkey->privkey);
    gcry_sexp_release(hashs);
    dsas = gcry_sexp_find_token(sigs, "dsa", 0);
    gcry_sexp_release(sigs);
    rs = gcry_sexp_find_token(dsas, "r", 0);
    ss = gcry_sexp_find_token(dsas, "s", 0);
    gcry_sexp_release(dsas);
    r = gcry_sexp_nth_mpi(rs, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(rs);
    s = gcry_sexp_nth_mpi(ss, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(ss);
    gcry_mpi_print(format, NULL, 0, &nr, r);
    gcry_mpi_print(format, NULL, 0, &ns, s);
    memset(bufp, 0, 40);
    gcry_mpi_print(format, bufp+(20-nr), lenp, NULL, r);
    debug_data("R", bufp, 20);
    bufp += 20; lenp -= 20;
    gcry_mpi_print(format, bufp+(20-ns), lenp, NULL, s);
    debug_data("S", bufp, 20);
    bufp += 20; lenp -= 20;

    assert(lenp == 0);

    gcry_mpi_release(r);
    gcry_mpi_release(s);

    /* Make the base64-encoding. */
    base64len = ((buflen + 2) / 3) * 4;
    base64buf = malloc(5 + base64len + 1 + 1);
    assert(base64buf != NULL);
    memmove(base64buf, "?OTR:", 5);
    otrl_base64_encode(base64buf+5, buf, buflen);
    base64buf[5 + base64len] = '.';
    base64buf[5 + base64len + 1] = '\0';

    free(buf);

    *messagep = base64buf;

    return gcry_error(GPG_ERR_NO_ERROR);
}

/* Deallocate an OTRKeyExchangeMsg returned from proto_parse_key_exchange */
void otrl_proto_free_key_exchange(OTRKeyExchangeMsg kem)
{
    if (!kem) return;
    gcry_sexp_release(kem->digest_sexp);
    gcry_sexp_release(kem->dsa_pubkey);
    gcry_mpi_release(kem->dh_pubkey);
    gcry_sexp_release(kem->dsa_sig);
    free(kem);
}

/* Parse a purported Key Exchange message.  Possible error code portions
 * of the return value:
 *   GPG_ERR_NO_ERROR:      Success
 *   GPG_ERR_ENOMEM:        Out of memory condition
 *   GPG_ERR_INV_VALUE:     The message was not a well-formed Key Exchange
 *                          message
 *   GPG_ERR_BAD_SIGNATURE: The signature on the message didn't verify
 */
gcry_error_t otrl_proto_parse_key_exchange(OTRKeyExchangeMsg *kemp,
	const char *msg)
{
    char *otrtag, *endtag;
    unsigned char *rawmsg, *bufp;
    size_t msglen, rawlen, lenp;
    gcry_mpi_t p,q,g,e,r,s;
    unsigned char hash_of_msg[20];
    gcry_mpi_t hashmpi;
    const unsigned char *fingerprintstart, *fingerprintend;
    const unsigned char *signaturestart, *signatureend;
    OTRKeyExchangeMsg kem = calloc(1, sizeof(struct s_OTRKeyExchangeMsg));

    if (!kem) {
	*kemp = NULL;
	return gcry_error(GPG_ERR_ENOMEM);
    }

    otrtag = strstr(msg, "?OTR:");
    if (!otrtag) {
	*kemp = NULL;
	otrl_proto_free_key_exchange(kem);
	return gcry_error(GPG_ERR_INV_VALUE);
    }
    endtag = strchr(otrtag, '.');
    if (endtag) {
	msglen = endtag-otrtag;
    } else {
	msglen = strlen(otrtag);
    }

    /* Base64-decode the message */
    rawlen = ((msglen-5) / 4) * 3;   /* maximum possible */
    rawmsg = malloc(rawlen);
    if (!rawmsg && rawlen > 0) {
	*kemp = NULL;
	otrl_proto_free_key_exchange(kem);
	return gcry_error(GPG_ERR_ENOMEM);
    }
    rawlen = otrl_base64_decode(rawmsg, otrtag+5, msglen-5);  /* actual size */

    bufp = rawmsg;
    lenp = rawlen;

    signaturestart = bufp;

    require_len(3);
    if (memcmp(bufp, "\x00\x01\x0a", 3)) {
	/* Invalid header */
	goto invval;
    }
    bufp += 3; lenp -= 3;

    require_len(1);
    kem->is_reply = *bufp;
    if (kem->is_reply != 0 && kem->is_reply != 1) {
	/* Malformed is_reply field */
	goto invval;
    }
    bufp += 1; lenp -= 1;

    fingerprintstart = bufp;
    /* Read the DSA public key and calculate its fingerprint. */
    read_mpi(p);
    read_mpi(q);
    read_mpi(g);
    read_mpi(e);
    fingerprintend = bufp;
    gcry_md_hash_buffer(GCRY_MD_SHA1, kem->key_fingerprint,
	    fingerprintstart, fingerprintend-fingerprintstart);

    /* Create the pubkey S-expression. */
    gcry_sexp_build(&(kem->dsa_pubkey), NULL,
	    "(public-key (dsa (p %m)(q %m)(g %m)(y %m)))",
	    p, q, g, e);
    gcry_mpi_release(p);
    gcry_mpi_release(q);
    gcry_mpi_release(g);
    gcry_mpi_release(e);

    /* Read the key id */
    read_int(kem->keyid);
    if (kem->keyid == 0) {
	/* Not a legal value */
	goto invval;
    }

    /* Read the DH public key */
    read_mpi(kem->dh_pubkey);

    /* Hash the message so we can check the signature */
    signatureend = bufp;
    gcry_md_hash_buffer(GCRY_MD_SHA1, hash_of_msg,
	    signaturestart, signatureend-signaturestart);
    /* Turn the hash into an mpi, then into a sexp */
    gcry_mpi_scan(&hashmpi, GCRYMPI_FMT_USG, hash_of_msg, 20, NULL);
    gcry_sexp_build(&(kem->digest_sexp), NULL, "(%m)", hashmpi);
    gcry_mpi_release(hashmpi);

    /* Read the signature */
    require_len(40);
    gcry_mpi_scan(&r, GCRYMPI_FMT_USG, bufp, 20, NULL);
    gcry_mpi_scan(&s, GCRYMPI_FMT_USG, bufp+20, 20, NULL);
    lenp -= 40;
    gcry_sexp_build(&(kem->dsa_sig), NULL, "(sig-val (dsa (r %m)(s %m)))",
	    r, s);
    gcry_mpi_release(r);
    gcry_mpi_release(s);

    /* That should be everything */
    if (lenp != 0) goto invval;

    /* Verify the signature */
    if (gcry_pk_verify(kem->dsa_sig, kem->digest_sexp, kem->dsa_pubkey)) {
	/* It failed! */
	otrl_proto_free_key_exchange(kem);
	free(rawmsg);
	*kemp = NULL;
	return gcry_error(GPG_ERR_BAD_SIGNATURE);
    }

    free(rawmsg);
    *kemp = kem;
    return gcry_error(GPG_ERR_NO_ERROR);
invval:
    otrl_proto_free_key_exchange(kem);
    free(rawmsg);
    *kemp = NULL;
    return gcry_error(GPG_ERR_INV_VALUE);
}

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
	void *create_privkey_data)
{
    gcry_error_t err;
    char *savedmessage = context->lastmessage;
    int savedmay_retransmit = context->may_retransmit;
    time_t savedtime = context->lastsent;
    ConnectionState state = context->state;
    *messagep = NULL;
    context->lastmessage = NULL;

    switch(state) {
	case CONN_CONNECTED:
	    if (kem->is_reply == 0) {
		/* Send a Key Exchange message to the correspondent */
		err = otrl_proto_create_key_exchange(us, messagep, context, 1,
			create_privkey, create_privkey_data);
		if (err) return err;
	    }
	    if (context->their_keyid > 0 &&
		    ((kem->keyid == context->their_keyid &&
			!gcry_mpi_cmp(kem->dh_pubkey, context->their_y))
		    || (kem->keyid == (context->their_keyid - 1) &&
			!gcry_mpi_cmp(kem->dh_pubkey, context->their_old_y)))) {
		/* We've already seen this key of theirs, so all is
		 * good. */
		break;
	    }
	    /* It's an entirely different session; our correspondent has
	     * gone away and come back. */
	    otrl_context_force_setup(context);

	    /* FALLTHROUGH */
	case CONN_UNCONNECTED:
	case CONN_SETUP:
	    if (state == CONN_UNCONNECTED ||
		    (state == CONN_SETUP && kem->is_reply == 0)) {
		/* Send a Key Exchange message to the correspondent */
		err = otrl_proto_create_key_exchange(us, messagep, context, 1,
			create_privkey, create_privkey_data);
		if (err) return err;
	    }
	    context->their_keyid = kem->keyid;
	    gcry_mpi_release(context->their_y);
	    context->their_y = gcry_mpi_copy(kem->dh_pubkey);
	    err = otrl_dh_session(&(context->sesskeys[0][0]),
		    &(context->our_dh_key), context->their_y);
	    if (err) return err;
	    err = otrl_dh_session(&(context->sesskeys[1][0]),
		    &(context->our_old_dh_key), context->their_y);
	    if (err) return err;
	    context->state = CONN_CONNECTED;
	    memmove(context->sessionid, context->sesskeys[1][0].dhsecureid,
		    20);
	    context->sessiondir = context->sesskeys[1][0].dir;
	    context->active_fingerprint = fprint;
	    context->generation++;
	    context->lastmessage = savedmessage;
	    context->may_retransmit = savedmay_retransmit;
	    context->lastsent = savedtime;
	    break;
    }

    return gcry_error(GPG_ERR_NO_ERROR);
}

/* Create an OTR Data message.  Pass the plaintext as msg, and an
 * optional chain of TLVs.  A newly-allocated string will be returned in
 * *encmessagep. */
gcry_error_t otrl_proto_create_data(char **encmessagep, ConnContext *context,
	const char *msg, OtrlTLV *tlvs)
{
    size_t justmsglen = strlen(msg);
    size_t msglen = justmsglen + 1 + otrl_tlv_seriallen(tlvs);
    size_t buflen;
    size_t pubkeylen;
    unsigned char *buf = NULL;
    unsigned char *bufp;
    size_t lenp;
    DH_sesskeys *sess = &(context->sesskeys[1][0]);
    gcry_error_t err;
    size_t reveallen = 20 * context->numsavedkeys;
    size_t base64len;
    char *base64buf = NULL;
    char *msgbuf = NULL;
    enum gcry_mpi_format format = GCRYMPI_FMT_USG;
    char *msgdup;

    /* Make sure we're actually supposed to be able to encrypt */
    if (context->state != CONN_CONNECTED || context->their_keyid == 0) {
	return gcry_error(GPG_ERR_CONFLICT);
    }

    /* We need to copy the incoming msg, since it might be an alias for
     * context->lastmessage, which we'll be freeing soon. */
    msgdup = gcry_malloc_secure(justmsglen + 1);
    if (msgdup == NULL) {
	return gcry_error(GPG_ERR_ENOMEM);
    }
    strcpy(msgdup, msg);

    *encmessagep = NULL;

    /* Header, send keyid, recv keyid, counter, msg len, msg
     * len of revealed mac keys, revealed mac keys, MAC */
    buflen = 3 + 4 + 4 + 8 + 4 + msglen + 4 + reveallen + 20;
    gcry_mpi_print(format, NULL, 0, &pubkeylen, context->our_dh_key.pub);
    buflen += pubkeylen + 4;
    buf = malloc(buflen);
    msgbuf = gcry_malloc_secure(msglen);
    if (buf == NULL || msgbuf == NULL) {
	free(buf);
	gcry_free(msgbuf);
	gcry_free(msgdup);
	return gcry_error(GPG_ERR_ENOMEM);
    }
    memmove(msgbuf, msgdup, justmsglen);
    msgbuf[justmsglen] = '\0';
    otrl_tlv_serialize(msgbuf + justmsglen + 1, tlvs);
    bufp = buf;
    lenp = buflen;
    memmove(bufp, "\x00\x01\x03", 3);  /* header */
    debug_data("Header", bufp, 3);
    bufp += 3; lenp -= 3;
    write_int(context->our_keyid-1);                    /* sender keyid */
    debug_int("Sender keyid", bufp-4);
    write_int(context->their_keyid);                    /* recipient keyid */
    debug_int("Recipient keyid", bufp-4);

    write_mpi(context->our_dh_key.pub, pubkeylen, "Y");      /* Y */

    otrl_dh_incctr(sess->sendctr);
    memmove(bufp, sess->sendctr, 8);      /* Counter (top 8 bytes only) */
    debug_data("Counter", bufp, 8);
    bufp += 8; lenp -= 8;

    write_int(msglen);                        /* length of encrypted data */
    debug_int("Msg len", bufp-4);

    err = gcry_cipher_reset(sess->sendenc);
    if (err) goto err;
    err = gcry_cipher_setctr(sess->sendenc, sess->sendctr, 16);
    if (err) goto err;
    err = gcry_cipher_encrypt(sess->sendenc, bufp, msglen, msgbuf, msglen);
    if (err) goto err;                              /* encrypted data */
    debug_data("Enc data", bufp, msglen);
    bufp += msglen;
    lenp -= msglen;

    gcry_md_reset(sess->sendmac);
    gcry_md_write(sess->sendmac, buf, bufp-buf);
    memmove(bufp, gcry_md_read(sess->sendmac, GCRY_MD_SHA1), 20);
    debug_data("MAC", bufp, 20);
    bufp += 20;                                         /* MAC */
    lenp -= 20;

    write_int(reveallen);                     /* length of revealed MAC keys */
    debug_int("Revealed MAC length", bufp-4);

    if (reveallen > 0) {
	memmove(bufp, context->saved_mac_keys, reveallen);
	debug_data("Revealed MAC data", bufp, reveallen);
	bufp += reveallen; lenp -= reveallen;
	free(context->saved_mac_keys);
	context->saved_mac_keys = NULL;
	context->numsavedkeys = 0;
    }

    assert(lenp == 0);

    /* Make the base64-encoding. */
    base64len = ((buflen + 2) / 3) * 4;
    base64buf = malloc(5 + base64len + 1 + 1);
    if (base64buf == NULL) {
	err = GPG_ERR_ENOMEM;
	goto err;
    }
    memmove(base64buf, "?OTR:", 5);
    otrl_base64_encode(base64buf+5, buf, buflen);
    base64buf[5 + base64len] = '.';
    base64buf[5 + base64len + 1] = '\0';

    free(buf);
    gcry_free(msgbuf);
    *encmessagep = base64buf;
    gcry_free(context->lastmessage);
    context->lastmessage = NULL;
    context->may_retransmit = 0;
    if (msglen > 0) {
	const char *prefix = "[resent] ";
	size_t prefixlen = strlen(prefix);
	if (!strncmp(prefix, msgdup, prefixlen)) {
	    /* The prefix is already there.  Don't add it again. */
	    prefix = "";
	    prefixlen = 0;
	}
	context->lastmessage = gcry_malloc_secure(prefixlen + justmsglen + 1);
	if (context->lastmessage) {
	    strcpy(context->lastmessage, prefix);
	    strcat(context->lastmessage, msgdup);
	}
    }
    gcry_free(msgdup);
    return gcry_error(GPG_ERR_NO_ERROR);
err:
    free(buf);
    gcry_free(msgbuf);
    gcry_free(msgdup);
    *encmessagep = NULL;
    return err;
}

/* Accept an OTR Data Message in datamsg.  Decrypt it and put the
 * plaintext into *plaintextp, and any TLVs into tlvsp. */
gcry_error_t otrl_proto_accept_data(char **plaintextp, OtrlTLV **tlvsp,
	ConnContext *context, const char *datamsg)
{
    char *otrtag, *endtag;
    gcry_error_t err;
    unsigned char *rawmsg = NULL;
    size_t msglen, rawlen, lenp;
    unsigned char *macstart, *macend;
    unsigned char *bufp;
    unsigned int sender_keyid, recipient_keyid;
    gcry_mpi_t sender_next_y = NULL;
    unsigned char ctr[8];
    unsigned int datalen, reveallen;
    unsigned char *data = NULL;
    unsigned char *nul = NULL;
    unsigned char givenmac[20];
    DH_sesskeys *sess;

    *plaintextp = NULL;
    *tlvsp = NULL;
    otrtag = strstr(datamsg, "?OTR:");
    if (!otrtag) {
	goto invval;
    }
    endtag = strchr(otrtag, '.');
    if (endtag) {
	msglen = endtag-otrtag;
    } else {
	msglen = strlen(otrtag);
    }

    /* Base64-decode the message */
    rawlen = ((msglen-5) / 4) * 3;   /* maximum possible */
    rawmsg = malloc(rawlen);
    if (!rawmsg && rawlen > 0) {
	err = gcry_error(GPG_ERR_ENOMEM);
	goto err;
    }
    rawlen = otrl_base64_decode(rawmsg, otrtag+5, msglen-5);  /* actual size */

    bufp = rawmsg;
    lenp = rawlen;

    macstart = bufp;
    require_len(3);
    if (memcmp(bufp, "\x00\x01\x03", 3)) {
	/* Invalid header */
	goto invval;
    }
    bufp += 3; lenp -= 3;

    read_int(sender_keyid);
    read_int(recipient_keyid);
    read_mpi(sender_next_y);
    require_len(8);
    memmove(ctr, bufp, 8);
    bufp += 8; lenp -= 8;
    read_int(datalen);
    require_len(datalen);
    data = malloc(datalen+1);
    if (!data) {
	err = gcry_error(GPG_ERR_ENOMEM);
	goto err;
    }
    memmove(data, bufp, datalen);
    data[datalen] = '\0';
    bufp += datalen; lenp -= datalen;
    macend = bufp;
    require_len(20);
    memmove(givenmac, bufp, 20);
    bufp += 20; lenp -= 20;
    read_int(reveallen);
    require_len(reveallen);
    /* Just skip over the revealed MAC keys, which we don't need.  They
     * were published for deniability of transcripts. */
    bufp += reveallen; lenp -= reveallen;

    /* That should be everything */
    if (lenp != 0) goto invval;

    /* We don't take any action on this message (especially rotating
     * keys) until we've verified the MAC on this message.  To that end,
     * we need to know which keys this message is claiming to use. */
    if (context->their_keyid == 0 ||
	    (sender_keyid != context->their_keyid &&
		sender_keyid != context->their_keyid - 1) ||
	    (recipient_keyid != context->our_keyid &&
	     recipient_keyid != context->our_keyid - 1) ||
	    sender_keyid == 0 || recipient_keyid == 0) {
	goto conflict;
    }

    if (sender_keyid == context->their_keyid - 1 &&
	    context->their_old_y == NULL) {
	goto conflict;
    }

    /* These are the session keys this message is claiming to use. */
    sess = &(context->sesskeys
	    [context->our_keyid - recipient_keyid]
	    [context->their_keyid - sender_keyid]);

    gcry_md_reset(sess->rcvmac);
    gcry_md_write(sess->rcvmac, macstart, macend-macstart);
    if (memcmp(givenmac, gcry_md_read(sess->rcvmac, GCRY_MD_SHA1), 20)) {
	/* The MACs didn't match! */
	goto conflict;
    }
    sess->rcvmacused = 1;

    /* Check to see that the counter is increasing; i.e. that this isn't
     * a replay. */
    if (otrl_dh_cmpctr(ctr, sess->rcvctr) <= 0) {
	goto conflict;
    }

    /* Decrypt the message */
    memmove(sess->rcvctr, ctr, 8);
    err = gcry_cipher_reset(sess->rcvenc);
    if (err) goto err;
    err = gcry_cipher_setctr(sess->rcvenc, sess->rcvctr, 16);
    if (err) goto err;
    err = gcry_cipher_decrypt(sess->rcvenc, data, datalen, NULL, 0);
    if (err) goto err;

    /* See if either set of keys needs rotating */

    if (recipient_keyid == context->our_keyid) {
	/* They're using our most recent key, so generate a new one */
	err = rotate_dh_keys(context);
	if (err) goto err;
    }

    if (sender_keyid == context->their_keyid) {
	/* They've sent us a new public key */
	err = rotate_y_keys(context, sender_next_y);
	if (err) goto err;
    }

    gcry_mpi_release(sender_next_y);
    *plaintextp = data;

    /* See if there are TLVs */
    nul = data;
    while (nul < data+datalen && *nul) ++nul;
    /* If we stopped before the end, skip the NUL we stopped at */
    if (nul < data+datalen) ++nul;
    *tlvsp = otrl_tlv_parse(nul, (data+datalen)-nul);

    free(rawmsg);
    return gcry_error(GPG_ERR_NO_ERROR);

invval:
    err = gcry_error(GPG_ERR_INV_VALUE);
    goto err;
conflict:
    err = gcry_error(GPG_ERR_CONFLICT);
    goto err;
err:
    gcry_mpi_release(sender_next_y);
    free(data);
    free(rawmsg);
    return err;
}
