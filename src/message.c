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
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* libgcrypt headers */
#include <gcrypt.h>

/* libotr headers */
#include "privkey.h"
#include "proto.h"
#include "message.h"

/* How long after sending a packet should we wait to send a heartbeat? */
#define HEARTBEAT_INTERVAL 60

/* How old are messages allowed to be in order to be candidates for
 * resending in response to a rekey? */
#define RESEND_INTERVAL 60

/* Deallocate a message allocated by other otrl_message_* routines. */
void otrl_message_free(char *message)
{
    free(message);
}

/* Handle a message about to be sent to the network.  It is safe to pass
 * all messages about to be sent to this routine.  add_appdata is a
 * function that will be called in the event that a new ConnContext is
 * created.  It will be passed the data that you supplied, as well as a
 * pointer to the new ConnContext.  You can use this to add
 * application-specific information to the ConnContext using the
 * "context->app" field, for example.  If you don't need to do this, you
 * can pass NULL for the last two arguments of otrl_message_sending.  
 *
 * tlvs is a chain of OtrlTLVs to append to the private message.  It is
 * usually correct to just pass NULL here.
 *
 * If this routine returns non-zero, then the library tried to encrypt
 * the message, but for some reason failed.  DO NOT send the message in
 * the clear in that case.
 * 
 * If *messagep gets set by the call to something non-NULL, then you
 * should replace your message with the contents of *messagep, and
 * send that instead.  Call otrl_message_free(*messagep) when you're
 * done with it. */
gcry_error_t otrl_message_sending(OtrlUserState us,
	const OtrlMessageAppOps *ops,
	void *opdata, const char *accountname, const char *protocol,
	const char *recipient, const char *message, OtrlTLV *tlvs,
	char **messagep,
	void (*add_appdata)(void *data, ConnContext *context),
	void *data)
{
    struct context * context;
    char * msgtosend;
    gcry_error_t err;
    OtrlPolicy policy = OTRL_POLICY_DEFAULT;
    int context_added = 0;

    *messagep = NULL;

    if (!accountname || !protocol || !recipient || !message || !messagep)
        return gcry_error(GPG_ERR_NO_ERROR);

    /* See if we have a fingerprint for this user */
    context = otrl_context_find(us, recipient, accountname, protocol,
	    1, &context_added, add_appdata, data);

    /* Update the context list if we added one */
    if (context_added && ops->update_context_list) {
	ops->update_context_list(opdata);
    }

    /* Check the policy */
    if (ops->policy) {
	policy = ops->policy(opdata, context);
    }

    /* Should we go on at all? */
    if (policy == OTRL_POLICY_NEVER) {
        return gcry_error(GPG_ERR_NO_ERROR);
    }

    /* If this is an OTR Query message, don't encrypt it. */
    if (otrl_proto_message_type(message) == OTR_QUERY) {
	/* Replace the "?OTR?" with a custom message */
	char *bettermsg = otrl_proto_default_query_msg(accountname);
	if (bettermsg) {
	    *messagep = bettermsg;
	}
	return gcry_error(GPG_ERR_NO_ERROR);
    }

    if (policy == OTRL_POLICY_ALWAYS && context->state != CONN_CONNECTED) {
	/* We're trying to send an unencrypted message with policy
	 * ALWAYS.  Don't do that, but try to start up OTR instead. */
	if (context->lastmessage) {
	    gcry_free(context->lastmessage);
	    if (ops->notify) {
		const char *format = "You attempted to send another "
		    "unencrypted message to %s";
		char *primary = malloc(strlen(format) + strlen(recipient) - 1);
		if (primary) {
		    sprintf(primary, format, recipient);
		    ops->notify(opdata, OTRL_NOTIFY_ERROR, accountname,
			    protocol, recipient, "OTR Policy Violation",
			    primary,
			    "Unencrypted messages to this recipient are not "
			    "allowed.  Attempting to start a private "
			    "conversation.\n\nYour message will be "
			    "retransmitted when the private conversation "
			    "starts, but the previously saved message has "
			    "been discarded.");
		    free(primary);
		}
	    }
	} else {
	    if (ops->notify) {
		const char *format = "You attempted to send an "
		    "unencrypted message to %s";
		char *primary = malloc(strlen(format) + strlen(recipient) - 1);
		if (primary) {
		    sprintf(primary, format, recipient);
		    ops->notify(opdata, OTRL_NOTIFY_WARNING, accountname,
			    protocol, recipient, "OTR Policy Violation",
			    primary,
			    "Unencrypted messages to this recipient are not "
			    "allowed.  Attempting to start a private "
			    "conversation.\n\nYour message will be "
			    "retransmitted when the private conversation "
			    "starts.");
		    free(primary);
		}
	    }
	}
	context->lastmessage = gcry_malloc_secure(strlen(message) + 1);
	if (context->lastmessage) {
	    char *bettermsg = otrl_proto_default_query_msg(accountname);
	    strcpy(context->lastmessage, message);
	    context->lastsent = time(NULL);
	    context->may_retransmit = 2;
	    if (bettermsg) {
		*messagep = bettermsg;
		return gcry_error(GPG_ERR_NO_ERROR);
	    } else {
		return gcry_error(GPG_ERR_ENOMEM);
	    }
	}
    }

    if (policy == OTRL_POLICY_OPPORTUNISTIC || policy == OTRL_POLICY_ALWAYS) {
	if (context->state == CONN_UNCONNECTED &&
		context->otr_offer != OFFER_REJECTED) {
	    /* See if this user can speak OTR.  Append the OTR_MESSAGE_TAG
	     * to the plaintext message, and see if he responds. */
	    size_t msglen = strlen(message);
	    char *taggedmsg = malloc(msglen + strlen(OTR_MESSAGE_TAG) + 1);
	    if (taggedmsg) {
		strcpy(taggedmsg, message);
		strcpy(taggedmsg + msglen, OTR_MESSAGE_TAG);
		*messagep = taggedmsg;
		if (context) {
		    context->otr_offer = OFFER_SENT;
		}
	    }
	}
    }

    /* If we're not going to encrypt anything, just return here. */
    if (context->state != CONN_CONNECTED) {
        return gcry_error(GPG_ERR_NO_ERROR);
    }

    /* If the other side has disconnected, inform the user and don't
     * send the message. */
    if (context->their_keyid == 0) {
	*messagep = strdup("");
	if (ops->notify) {
	    const char *fmt = "%s has already closed his private connection "
		"to you";
	    char *primary = malloc(strlen(fmt) + strlen(recipient) - 1);
	    if (primary) {
		sprintf(primary, fmt, recipient);
		ops->notify(opdata, OTRL_NOTIFY_ERROR, 
			accountname, protocol, recipient,
			"Private connection closed", primary,
			"Your message was not sent.  Either close your "
			"private connection to him, or refresh it.");
	    }
	}
	if (!(*messagep)) {
	    return gcry_error(GPG_ERR_ENOMEM);
	}
        return gcry_error(GPG_ERR_NO_ERROR);
    }

    /* Create the new, encrypted message */
    err = otrl_proto_create_data(&msgtosend, context, message, tlvs);
    if (!err) {
	context->lastsent = time(NULL);
	*messagep = msgtosend;
    } else {
	/* Uh, oh.  Whatever we do, *don't* send the message in the
	 * clear. */
	*messagep = strdup("?OTR Error: Error occurred encrypting message");
	if (ops->notify) {
	    ops->notify(opdata, OTRL_NOTIFY_ERROR, 
		    accountname, protocol, recipient,
		    "Error encrypting message",
		    "An error occurred when encrypting your message",
		    "The message was not sent.");
	}
	if (!(*messagep)) {
	    return gcry_error(GPG_ERR_ENOMEM);
	}
    }
    return err;
}

/* If err == 0, send the message to the given user.  Otherwise, display
 * an appripriate error dialog.  Return the value of err that was
 * passed. */
static gcry_error_t send_or_error(const OtrlMessageAppOps *ops, void *opdata,
	gcry_error_t err, const char *accountname, const char *protocol,
	const char *who, const char *msg)
{
    if (!err) {
	if (msg && *msg) {
	    if (ops->inject_message) {
		ops->inject_message(opdata, accountname, protocol, who, msg);
	    }
	}
    } else {
	const char *buf_format = "Error creating OTR Key "
		"Exchange Message: %s";
	const char *strerr = gcry_strerror(err);
	char *buf = malloc(strlen(buf_format) + strlen(strerr) - 1);
	if (buf) {
	    sprintf(buf, buf_format, strerr);
	}
	if (ops->notify) {
	    ops->notify(opdata, OTRL_NOTIFY_ERROR, accountname, protocol,
		    who, "OTR error", buf, NULL);
	}
	free(buf);
    }
    return err;
}

/* Return 1 if this Key Exchange Message caused us to rekey; that is,
 * either we were in CONN_CONNECTED, and we're again in CONN_CONNECTED,
 * but with new keys, or else we weren't in CONN_CONNECTED before and
 * now we are. */
static int process_kem(OtrlUserState us, const OtrlMessageAppOps *ops,
	void *opdata, ConnContext *context, Fingerprint *fprint,
	OTRKeyExchangeMsg kem)
{
    gcry_error_t err;
    char *msgtosend;
    ConnectionState state = context->state;
    unsigned int generation = context->generation;
    int retval = 0;

    if (fprint == NULL) {
	/* We now need to add this fingerprint */
	int added = 0;
	fprint = otrl_context_find_fingerprint(context, kem->key_fingerprint,
		1, &added);
	if (added) {
	    /* This may not be the case, in the event that multiple
	     * dialogs for the same fingerprint are open at the same
	     * time. */
	    if (ops->write_fingerprints) {
		ops->write_fingerprints(opdata);
	    }
	}
    }
    
    /* OK, we've received a Key Exchange Message, with a known
     * fingerprint. */
    err = otrl_proto_accept_key_exchange(us, context, fprint, kem, &msgtosend,
	    ops->create_privkey, opdata);
    send_or_error(ops, opdata, err, context->accountname, context->protocol,
	    context->username, msgtosend);
    free(msgtosend);
    if (ops->update_context_list) {
	ops->update_context_list(opdata);
    }

    /* See if we need to inform the user of a change to a secure state */
    if ((state != CONN_CONNECTED && context->state == CONN_CONNECTED)
	    || generation != context->generation) {
	if (ops->gone_secure) {
	    ops->gone_secure(opdata, context);
	}
	retval = 1;
    }

    /* See if we need to inform the user of a change out of a secure
     * state.  (This should only happen if we're in the CONNECTED state,
     * the correspondent has disconnected (and lost session state), we
     * receive a new Key Exchange message from him, but there's some
     * sort of error when setting up our new connection state. */
    if (state == CONN_CONNECTED && context->state != CONN_CONNECTED) {
	if (ops->gone_insecure) {
	    ops->gone_insecure(opdata, context);
	}
    }

    /* See if we need to inform the user that a Key Exchange has been
     * received, but it's just for the (unchanged) old connection. */
    if (state == CONN_CONNECTED && context->state == CONN_CONNECTED &&
	    generation == context->generation) {
	if (ops->still_secure) {
	    ops->still_secure(opdata, context, kem->is_reply);
	}
    }

    return retval;
}

/* Handle a message just received from the network.  It is safe to pass
 * all received messages to this routine.  add_appdata is a function
 * that will be called in the event that a new ConnContext is created.
 * It will be passed the data that you supplied, as well as
 * a pointer to the new ConnContext.  You can use this to add
 * application-specific information to the ConnContext using the
 * "context->app" field, for example.  If you don't need to do this, you
 * can pass NULL for the last two arguments of otrl_message_receiving.  
 *
 * If otrl_message_receiving returns 1, then the message you received
 * was an internal protocol message, and no message should be delivered
 * to the user.
 *
 * If it returns 0, then check if *messagep was set to non-NULL.  If
 * so, replace the received message with the contents of *messagep, and
 * deliver that to the user instead.  You must call
 * otrl_message_free(*messagep) when you're done with it.  If tlvsp is
 * non-NULL, *tlvsp will be set to a chain of any TLVs that were
 * transmitted along with this message.  You must call
 * otrl_tlv_free(*tlvsp) when you're done with those.
 *
 * If otrl_message_receiving returns 0 and *messagep is NULL, then this
 * was an ordinary, non-OTR message, which should just be delivered to
 * the user without modification. */
int otrl_message_receiving(OtrlUserState us, const OtrlMessageAppOps *ops,
	void *opdata, const char *accountname, const char *protocol,
	const char *sender, const char *message, char **newmessagep,
	OtrlTLV **tlvsp,
	void (*add_appdata)(void *data, ConnContext *context),
	void *data)
{
    ConnContext * context;
    OTRMessageType msgtype;
    int context_added = 0;
    ConnectionState state;
    OtrlPolicy policy = OTRL_POLICY_DEFAULT;
    int ignore_message = -1;
    int fragment_assembled = 0;
    char *unfragmessage = NULL;

    if (!accountname || !protocol || !sender || !message || !newmessagep)
        return 0;

    *newmessagep = NULL;
    if (tlvsp) *tlvsp = NULL;

    /* Find our context and state with this correspondent */
    context = otrl_context_find(us, sender, accountname,
	    protocol, 1, &context_added, add_appdata, data);

    /* Update the context list if we added one */
    if (context_added && ops->update_context_list) {
	ops->update_context_list(opdata);
    }

    /* Check the policy */
    if (ops->policy) {
	policy = ops->policy(opdata, context);
    }

    /* Should we go on at all? */
    if (policy == OTRL_POLICY_NEVER) {
        return 0;
    }

    /* See if we have a fragment */
    switch(otrl_proto_fragment_accumulate(&unfragmessage, context, message)) {
	case OTRL_FRAGMENT_UNFRAGMENTED:
	    /* Do nothing */
	    break;
	case OTRL_FRAGMENT_INCOMPLETE:
	    /* We've accumulated this fragment, but we don't have a
	     * complete message yet */
	    return 1;
	case OTRL_FRAGMENT_COMPLETE:
	    /* We've got a new complete message, in unfragmessage. */
	    fragment_assembled = 1;
	    message = unfragmessage;
	    break;
    }

    /* What type of message is it?  Note that this just checks the
     * header; it's not necessarily a _valid_ message of this type. */
    msgtype = otrl_proto_message_type(message);
    state = context->state;

    /* See if they responded to our OTR offer */
    if (policy == OTRL_POLICY_OPPORTUNISTIC || policy == OTRL_POLICY_ALWAYS) {
	if (msgtype != OTR_NOTOTR) {
	    context->otr_offer = OFFER_ACCEPTED;
	} else if (context->otr_offer == OFFER_SENT) {
	    context->otr_offer = OFFER_REJECTED;
	}
    }

    switch(msgtype) {
	char *tag;
	case OTR_QUERY:
	    switch(state) {
		char *msgtosend;
		gcry_error_t err;
		case CONN_UNCONNECTED:
		case CONN_SETUP:
		    err = otrl_proto_create_key_exchange(us, &msgtosend,
			    context, 0, ops->create_privkey, opdata);

		    if (!send_or_error(ops, opdata, err, accountname,
				protocol, sender, msgtosend)) {
			context->state = CONN_SETUP;
			if (ops->update_context_list) {
			    ops->update_context_list(opdata);
			}
		    }
		    free(msgtosend);
		    break;
		case CONN_CONNECTED:
		    /* Just reply with a Key Exchange message, but stay
		     * in the CONNECTED state. */
		    err = otrl_proto_create_key_exchange(us, &msgtosend,
			    context, 0, ops->create_privkey, opdata);
		    send_or_error(ops, opdata, err, accountname, protocol,
			    sender, msgtosend);
		    free(msgtosend);
		    break;
	    }
	    /* Don't display the Query message to the user. */
	    if (ignore_message == -1) ignore_message = 1;
	    break;
	case OTR_KEYEXCH:
	    switch(state) {
		gcry_error_t err;
		OTRKeyExchangeMsg kem;
		Fingerprint *found_print;
		case CONN_UNCONNECTED:
		case CONN_SETUP:
		case CONN_CONNECTED:
		    /* Even if we're currently CONNECTED, receiving a
		     * Key Exchange message means the other side has
		     * lost the connection for some reason.  (Or else
		     * that we sent them an explicit OTR Query message.)
		     * Just accept the message as usual (with all the
		     * fingerprint checks, and
		     * otrl_proto_accept_key_exchange() will deal with
		     * keeping the state consistent. */
		    err = otrl_proto_parse_key_exchange(&kem, message);
		    found_print = NULL;

		    if (err) {
			const char *buf_format = "We received a malformed "
				"Key Exchange message from %s.";
			char *buf = malloc(strlen(buf_format) + strlen(sender)
				- 1);
			if (buf) {
			    sprintf(buf, buf_format, sender);
			}
			if (ops->notify) {
			    ops->notify(opdata, OTRL_NOTIFY_ERROR,
				    accountname, protocol, sender,
				    "OTR Error", buf, NULL);
			}
			free(buf);
			ignore_message = 1;
			break;
		    }

		    /* See if we're talking to ourselves */
		    if ((context->state == CONN_SETUP ||
				context->state == CONN_CONNECTED) &&
			    (!gcry_mpi_cmp(kem->dh_pubkey,
					   context->our_old_dh_key.pub)))
		    {
			/* Yes, we are. */
			if (ops->notify) {
			    ops->notify(opdata, OTRL_NOTIFY_ERROR,
				accountname, protocol, sender, "OTR Error",
				"We are receiving our own OTR messages.",
				"You are either trying to talk to yourself, "
				"or someone is reflecting your messages back "
				"at you.");
			}
			ignore_message = 1;
			break;
		    }

		    found_print = otrl_context_find_fingerprint(context,
			    kem->key_fingerprint, 0, NULL);

		    if (!found_print) {
			/* Inform the user of the new fingerprint */
			if (ops->new_fingerprint) {
			    ops->new_fingerprint(opdata, us,
				    accountname, protocol, sender, kem);
			}
			process_kem(us, ops, opdata, context, NULL, kem);
			otrl_proto_free_key_exchange(kem);
		    } else {
			time_t now;
			int rekeyed = process_kem(us, ops, opdata,
				context, found_print, kem);
			otrl_proto_free_key_exchange(kem);

			/* If we just rekeyed in response to a Key
			 * Exchange Message, see if there's a message
			 * we sent recently that should be resent. */
			if (rekeyed) now = time(NULL);
			if (rekeyed && context->lastmessage != NULL &&
				context->their_keyid > 0 &&
				context->may_retransmit &&
				context->lastsent >= (now - RESEND_INTERVAL)) {
			    char *resendmsg;
			    int resending = (context->may_retransmit == 1);

			    /* Re-encrypt the message with the new keys */
			    err = otrl_proto_create_data(&resendmsg,
				    context, context->lastmessage, NULL);
			    if (!err) {
				const char *format = "<b>The last message "
				    "to %s was resent.</b>";
				char *buf;

				/* Resend the message */
				if (ops->inject_message) {
				    ops->inject_message(opdata, accountname,
					    protocol, sender, resendmsg);
				}
				free(resendmsg);
				context->lastsent = now;

				if (!resending) {
				    /* We're actually just sending it
				     * for the first time. */
				    ignore_message = 1;
				} else {
				    /* Let the user know we resent it */
				    buf = malloc(strlen(format) +
					    strlen(context->username) - 1);
				    if (buf) {
					sprintf(buf, format,
						context->username);
					if (ops->display_otr_message) {
					    if (!ops->display_otr_message(
							opdata, accountname,
							protocol, sender,
							buf)) {
						ignore_message = 1;
					    }
					}
					if (ignore_message != 1) {
					    *newmessagep = buf;
					    ignore_message = 0;
					} else {
					    free(buf);
					}
				    }
				}
			    }
			}
		    }
		    break;
	    }
	    /* Don't deliver the Key Exchange message to the user */
	    if (ignore_message == -1) ignore_message = 1;
	    break;
	case OTR_DATA:
	    switch(state) {
		gcry_error_t err;
		OtrlTLV *tlvs;
		char *plaintext;
		char *buf;
		char *format;
		char *msgtosend;
		case CONN_UNCONNECTED:
		case CONN_SETUP:
		    /* Don't use g_strdup_printf here, because someone
		     * (not us) is going to free() the *newmessagep pointer,
		     * not g_free() it. */
		    format = "<b>The encrypted message received from %s is "
			"unreadable, as you are not currently communicating "
			"privately.</b>";
		    buf = malloc(strlen(format) + strlen(context->username)
			    - 1);  /* Remove "%s", add username + '\0' */
		    if (buf) {
			sprintf(buf, format, context->username);
			if (ops->display_otr_message) {
			    if (!ops->display_otr_message(opdata, accountname,
					protocol, sender, buf)) {
				ignore_message = 1;
			    }
			}
			if (ignore_message != 1) {
			    *newmessagep = buf;
			    ignore_message = 0;
			} else {
			    free(buf);
			}
		    }
		    format = "?OTR Error: You sent encrypted "
			    "data to %s, who wasn't expecting it.";
		    buf = malloc(strlen(format) + strlen(context->accountname)
			    - 1);
		    if (buf) {
			sprintf(buf, format, context->accountname);
			if (ops->inject_message) {
			    ops->inject_message(opdata, accountname, protocol,
				    sender, buf);
			}
			free(buf);
		    }

		    if (policy == OTRL_POLICY_OPPORTUNISTIC ||
			    policy == OTRL_POLICY_ALWAYS) {
			/* Send a key exchange message to try to start up
			 * the secure conversation */
			err = otrl_proto_create_key_exchange(us, &msgtosend,
				context, 0, ops->create_privkey, opdata);
			if (!send_or_error(ops, opdata, err, accountname,
				    protocol, sender, msgtosend)) {
			    context->state = CONN_SETUP;
			    if (ops->update_context_list) {
				ops->update_context_list(opdata);
			    }
			}
			free(msgtosend);
		    }

		    break;
		case CONN_CONNECTED:
		    err = otrl_proto_accept_data(&plaintext, &tlvs, context,
			    message);
		    if (err) {
			format = "We received a malformed "
				"data message from %s.";
			buf = malloc(strlen(format) + strlen(sender) - 1);
			if (buf) {
			    sprintf(buf, format, sender);
			    if (ops->notify) {
				ops->notify(opdata, OTRL_NOTIFY_ERROR,
					accountname, protocol, sender,
					"OTR Error", buf, NULL);
			    }
			    free(buf);
			}
			if (ops->inject_message) {
			    ops->inject_message(opdata, accountname, protocol,
				    sender, "?OTR Error: You transmitted "
					    "a malformed data message");
			}
			ignore_message = 1;
			break;
		    }

		    /* If the other side told us he's disconnected his
		     * private connection, make a note of that so we
		     * don't try sending anything else to him. */
		    if (otrl_tlv_find(tlvs, OTRL_TLV_DISCONNECTED)) {
			context->their_keyid = 0;
		    }
		    
		    if (plaintext[0] == '\0') {
			/* If it's a heartbeat (an empty message), don't
			 * display it to the user, but log a debug message. */
			format = "Heartbeat received from %s.\n";
			buf = malloc(strlen(format) + strlen(sender) - 1);
			if (buf) {
			    sprintf(buf, format, sender);
			    if (ops->log_message) {
				ops->log_message(opdata, buf);
			    }
			    free(buf);
			}
			ignore_message = 1;
		    } else if (ignore_message == 0 &&
			    context->their_keyid > 0) {
			/* If it's *not* a heartbeat, and we haven't
			 * sent anything in a while, also send a
			 * heartbeat. */
			time_t now = time(NULL);
			if (context->lastsent < (now - HEARTBEAT_INTERVAL)) {
			    char *heartbeat;

			    /* Create the heartbeat message */
			    err = otrl_proto_create_data(&heartbeat,
				    context, "", NULL);
			    if (!err) {
				/* Send it, and log a debug message */
				if (ops->inject_message) {
				    ops->inject_message(opdata, accountname,
					    protocol, sender, heartbeat);
				}
				free(heartbeat);

				context->lastsent = now;

				/* Log a debug message */
				format = "Heartbeat sent to %s.\n";
				buf = malloc(strlen(format) + strlen(sender)
					- 1);
				if (buf) {
				    sprintf(buf, format, sender);
				    if (ops->log_message) {
					ops->log_message(opdata, buf);
				    }
				    free(buf);
				}
			    }
			}
		    }

		    /* Return the TLVs even if ignore_message == 1 so
		     * that we can attach TLVs to heartbeats. */
		    if (tlvsp) {
			*tlvsp = tlvs;
		    } else {
			otrl_tlv_free(tlvs);
		    }

		    if (ignore_message != 1) {
			*newmessagep = plaintext;
			ignore_message = 0;
		    } else {
			free(plaintext);
		    }
		    break;
	    }
	    break;
	case OTR_ERROR:
	    switch(state) {
		gcry_error_t err;
		char *msgtosend;
		case CONN_UNCONNECTED:
		case CONN_SETUP:
		    if (policy == OTRL_POLICY_OPPORTUNISTIC ||
			    policy == OTRL_POLICY_ALWAYS) {
			/* The other end clearly supports OTR, so try to
			 * start up a private conversation */
			err = otrl_proto_create_key_exchange(us, &msgtosend,
				context, 0, ops->create_privkey, opdata);
			if (!send_or_error(ops, opdata, err, accountname,
				    protocol, sender, msgtosend)) {
			    context->state = CONN_SETUP;
			    if (ops->update_context_list) {
				ops->update_context_list(opdata);
			    }
			}
			free(msgtosend);
		    }
		    break;
		case CONN_CONNECTED:
		    /* Mark the last message we sent as eligible for
		     * retransmission */
		    context->may_retransmit = 1;
		    break;
	    }
	    /* In any event, display the error message, with the
	     * display_otr_message callback, if possible */
	    if (ops->display_otr_message) {
		const char *otrerror = strstr(message, "?OTR Error:");
		if (otrerror) {
		    /* Skip the leading '?' */
		    ++otrerror;
		} else {
		    otrerror = message;
		}
		if (!ops->display_otr_message(opdata, accountname, protocol,
			    sender, otrerror)) {
		    ignore_message = 1;
		}
	    }
	    break;
	case OTR_TAGGEDPLAINTEXT:
	    /* Strip the tag from the message */
	    tag = strstr(message, OTR_MESSAGE_TAG);
	    if (tag) {
		size_t taglen = strlen(OTR_MESSAGE_TAG);
		size_t restlen = strlen(tag + taglen);
		memmove(tag, tag+taglen, restlen+1);
	    }
	    /* FALLTHROUGH */
	case OTR_NOTOTR:
	    switch(state) {
		char *buf;
		char *format;
		case CONN_UNCONNECTED:
		case CONN_SETUP:
		    if (policy == OTRL_POLICY_OPPORTUNISTIC ||
			    policy == OTRL_POLICY_ALWAYS) {
			if (msgtype == OTR_TAGGEDPLAINTEXT) {
			    /* Send a Key Exchange in response */

			    char *msgtosend;
			    gcry_error_t err;

			    err = otrl_proto_create_key_exchange(us,
				    &msgtosend, context, 0,
				    ops->create_privkey, opdata);

			    if (!send_or_error(ops, opdata, err, accountname,
					protocol, sender, msgtosend)) {
				context->state = CONN_SETUP;
				if (ops->update_context_list) {
				    ops->update_context_list(opdata);
				}
			    }
			    free(msgtosend);
			}
		    }

		    /* If the policy is ALWAYS, we must warn about
		     * receiving an unencrypted message, so just
		     * FALLTHROUGH. */

		    if (policy != OTRL_POLICY_ALWAYS) {
			/* Just display the message. */
			break;
		    }
		case CONN_CONNECTED:
		    /* Not fine.  Let both users know. */

		    /* Don't use g_strdup_printf here, because someone
		     * (not us) is going to free() the *message pointer,
		     * not g_free() it. */
		    format = "<b>The following message received from %s was "
			"<i>not</i> encrypted: [</b>%s<b>]</b>";
		    buf = malloc(strlen(format) + strlen(context->username)
			    + strlen(message) - 3);
			    /* Remove "%s%s", add username + message + '\0' */
		    if (buf) {
			sprintf(buf, format, context->username, message);
			if (ops->display_otr_message) {
			    if (!ops->display_otr_message(opdata, accountname,
					protocol, sender, buf)) {
				ignore_message = 1;
			    }
			}
			if (ignore_message != 1) {
			    *newmessagep = buf;
			    ignore_message = 0;
			} else {
			    free(buf);
			}
		    }
		    format = "?OTR Error: You sent unencrypted data to %s, "
			    "who was expecting encrypted messages from you.";
		    buf = malloc(strlen(format) + strlen(context->accountname)
			    - 1);
		    if (buf) {
			sprintf(buf, format, context->accountname);
			if (ops->inject_message) {
			    ops->inject_message(opdata, accountname, protocol,
				    sender, buf);
			}
			free(buf);
		    }

		    break;
	    }
	    break;
	case OTR_UNKNOWN:
	    /* We received an OTR message we didn't recognize.  Ignore
	     * it, but make a log entry. */
	    if (ops->log_message) {
		const char *format = "Unrecognized OTR message received "
		    "from %s.\n";
		char *buf = malloc(strlen(format) + strlen(sender) - 1);
		if (buf) {
		    sprintf(buf, format, sender);
		    ops->log_message(opdata, buf);
		    free(buf);
		}
	    }
	    if (ignore_message == -1) ignore_message = 1;
	    break;
    }

    /* If we reassembled a fragmented message, we need to free the
     * allocated memory now. */
    if (fragment_assembled) {
	free(unfragmessage);
    }

    if (ignore_message == -1) ignore_message = 0;
    return ignore_message;
}

/* Put a connection into the UNCONNECTED state, first sending the
 * other side a notice that we're doing so if we're currently CONNECTED,
 * and we think he's logged in. */
void otrl_message_disconnect(OtrlUserState us, const OtrlMessageAppOps *ops,
	void *opdata, const char *accountname, const char *protocol,
	const char *username)
{
    ConnContext *context = otrl_context_find(us, username, accountname,
	    protocol, 0, NULL, NULL, NULL);

    if (!context) return;

    if (context->state == CONN_CONNECTED && context->their_keyid > 0 &&
	    ops->is_logged_in &&
	    ops->is_logged_in(opdata, accountname, protocol, username) == 1) {
	if (ops->inject_message) {
	    char *encmsg = NULL;
	    gcry_error_t err;
	    OtrlTLV *tlv = otrl_tlv_new(OTRL_TLV_DISCONNECTED, 0, NULL);

	    err = otrl_proto_create_data(&encmsg, context, "", tlv);
	    if (!err) {
		ops->inject_message(opdata, accountname, protocol,
			username, encmsg);
	    }
	    free(encmsg);
	}
    }

    otrl_context_force_disconnect(context);
    if (ops->update_context_list) {
	ops->update_context_list(opdata);
    }
}
