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

/* system headers */
#include <stdlib.h>

/* libgcrypt headers */
#include <gcrypt.h>

/* libotr headers */
#include "dh.h"

static const char* DH1536_MODULUS_S = "0x"
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";
static const char *DH1536_GENERATOR_S = "0x02";
static const int DH1536_MOD_LEN_BITS = 1536;
static const int DH1536_MOD_LEN_BYTES = 192;

static gcry_mpi_t DH1536_MODULUS = NULL;
static gcry_mpi_t DH1536_GENERATOR = NULL;

/*
 * Call this once, at plugin load time.  It sets up the modulus and
 * generator MPIs.
 */
void otrl_dh_init(void)
{
    gcry_mpi_scan(&DH1536_MODULUS, GCRYMPI_FMT_HEX, DH1536_MODULUS_S, 0, NULL);
    gcry_mpi_scan(&DH1536_GENERATOR, GCRYMPI_FMT_HEX, DH1536_GENERATOR_S,
	    0, NULL);
}

/*
 * Deallocate the contents of a DH_keypair (but not the DH_keypair
 * itself)
 */
void otrl_dh_keypair_free(DH_keypair *kp)
{
    gcry_mpi_release(kp->priv);
    gcry_mpi_release(kp->pub);
    kp->priv = NULL;
    kp->pub = NULL;
}

/*
 * Generate a DH keypair for a specified group.
 */ 
gcry_error_t otrl_dh_gen_keypair(unsigned int groupid, DH_keypair *kp)
{
    unsigned char *secbuf = NULL;
    gcry_mpi_t privkey = NULL;

    if (groupid != DH1536_GROUP_ID) {
	/* Invalid group id */
	return gcry_error(GPG_ERR_INV_VALUE);
    }

    /* Generate the secret key: a random 320-bit value */
    secbuf = gcry_random_bytes_secure(40, GCRY_STRONG_RANDOM);
    gcry_mpi_scan(&privkey, GCRYMPI_FMT_USG, secbuf, 40, NULL);
    gcry_free(secbuf);

    kp->groupid = groupid;
    kp->priv = privkey;
    kp->pub = gcry_mpi_new(DH1536_MOD_LEN_BITS);
    gcry_mpi_powm(kp->pub, DH1536_GENERATOR, privkey, DH1536_MODULUS);
    return gcry_error(GPG_ERR_NO_ERROR);
}

/*
 * Construct session keys from a DH keypair and someone else's public
 * key.
 */
gcry_error_t otrl_dh_session(DH_sesskeys *sess, const DH_keypair *kp,
	gcry_mpi_t y)
{
    gcry_mpi_t gab;
    size_t gablen;
    unsigned char *gabdata;
    unsigned char *hashdata;
    unsigned char sendbyte, rcvbyte;
    gcry_error_t err = gcry_error(GPG_ERR_NO_ERROR);

    otrl_dh_session_blank(sess);

    if (kp->groupid != DH1536_GROUP_ID) {
	/* Invalid group id */
	return gcry_error(GPG_ERR_INV_VALUE);
    }

    /* Calculate the shared secret MPI */
    gab = gcry_mpi_new(DH1536_MOD_LEN_BITS);
    gcry_mpi_powm(gab, y, kp->priv, DH1536_MODULUS);

    /* Output it in the right format */
    gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &gablen, gab);
    gabdata = gcry_malloc_secure(gablen + 5);
    if (!gabdata) {
	gcry_mpi_release(gab);
	return gcry_error(GPG_ERR_ENOMEM);
    }
    gabdata[1] = (gablen >> 24) & 0xff;
    gabdata[2] = (gablen >> 16) & 0xff;
    gabdata[3] = (gablen >> 8) & 0xff;
    gabdata[4] = gablen & 0xff;
    gcry_mpi_print(GCRYMPI_FMT_USG, gabdata+5, gablen, NULL, gab);
    gcry_mpi_release(gab);

    /* Calculate the session id */
    hashdata = gcry_malloc_secure(20);
    if (!hashdata) {
	gcry_free(gabdata);
	return gcry_error(GPG_ERR_ENOMEM);
    }
    gabdata[0] = 0x00;
    gcry_md_hash_buffer(GCRY_MD_SHA1, sess->dhsecureid, gabdata, gablen+5);

    /* Are we the "high" or "low" end of the connection? */
    if ( gcry_mpi_cmp(kp->pub, y) > 0 ) {
	sess->dir = SESS_DIR_HIGH;
	sendbyte = 0x01;
	rcvbyte = 0x02;
    } else {
	sess->dir = SESS_DIR_LOW;
	sendbyte = 0x02;
	rcvbyte = 0x01;
    }

    /* Calculate the sending encryption key */
    gabdata[0] = sendbyte;
    gcry_md_hash_buffer(GCRY_MD_SHA1, hashdata, gabdata, gablen+5);
    err = gcry_cipher_open(&(sess->sendenc), GCRY_CIPHER_AES,
	    GCRY_CIPHER_MODE_CTR, GCRY_CIPHER_SECURE);
    if (err) goto err;
    err = gcry_cipher_setkey(sess->sendenc, hashdata, 16);
    if (err) goto err;

    /* Calculate the sending MAC key */
    gcry_md_hash_buffer(GCRY_MD_SHA1, sess->sendmackey, hashdata, 16);
    err = gcry_md_open(&(sess->sendmac), GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
    if (err) goto err;
    err = gcry_md_setkey(sess->sendmac, sess->sendmackey, 20);
    if (err) goto err;

    /* Calculate the receiving encryption key */
    gabdata[0] = rcvbyte;
    gcry_md_hash_buffer(GCRY_MD_SHA1, hashdata, gabdata, gablen+5);
    err = gcry_cipher_open(&(sess->rcvenc), GCRY_CIPHER_AES,
	    GCRY_CIPHER_MODE_CTR, GCRY_CIPHER_SECURE);
    if (err) goto err;
    err = gcry_cipher_setkey(sess->rcvenc, hashdata, 16);
    if (err) goto err;

    /* Calculate the receiving MAC key (and save it in the DH_sesskeys
     * struct, so we can reveal it later) */
    gcry_md_hash_buffer(GCRY_MD_SHA1, sess->rcvmackey, hashdata, 16);
    err = gcry_md_open(&(sess->rcvmac), GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
    if (err) goto err;
    err = gcry_md_setkey(sess->rcvmac, sess->rcvmackey, 20);
    if (err) goto err;

    gcry_free(gabdata);
    gcry_free(hashdata);
    return gcry_error(GPG_ERR_NO_ERROR);
err:
    otrl_dh_session_free(sess);
    gcry_free(gabdata);
    gcry_free(hashdata);
    return err;
}

/*
 * Deallocate the contents of a DH_sesskeys (but not the DH_sesskeys
 * itself)
 */
void otrl_dh_session_free(DH_sesskeys *sess)
{
    gcry_cipher_close(sess->sendenc);
    gcry_cipher_close(sess->rcvenc);
    gcry_md_close(sess->sendmac);
    gcry_md_close(sess->rcvmac);

    otrl_dh_session_blank(sess);
}

/*
 * Blank out the contents of a DH_sesskeys (without releasing it)
 */
void otrl_dh_session_blank(DH_sesskeys *sess)
{
    sess->sendenc = NULL;
    sess->sendmac = NULL;
    sess->rcvenc = NULL;
    sess->rcvmac = NULL;
    memset(sess->dhsecureid, 0, 20);
    memset(sess->sendctr, 0, 16);
    memset(sess->rcvctr, 0, 16);
    memset(sess->sendmackey, 0, 20);
    memset(sess->rcvmackey, 0, 20);
    sess->sendmacused = 0;
    sess->rcvmacused = 0;
}

/* Increment the top half of a counter block */
void otrl_dh_incctr(unsigned char *ctr)
{
    int i;
    for (i=8;i;--i) {
	if (++ctr[i-1]) break;
    }
}

/* Compare two counter values (8 bytes each).  Return 0 if ctr1 == ctr2,
 * < 0 if ctr1 < ctr2 (as unsigned 64-bit values), > 0 if ctr1 > ctr2. */
int otrl_dh_cmpctr(const unsigned char *ctr1, const unsigned char *ctr2)
{
    int i;
    for (i=0;i<8;++i) {
	int c = ctr1[i] - ctr2[i];
	if (c) return c;
    }
    return 0;
}
