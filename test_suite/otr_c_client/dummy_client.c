#include <pthread.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <errno.h>

#include <gcrypt.h>

#include "proto.h"
#include "privkey.h"
#include "message.h"
#include "context.h"

#ifdef OTR40
#include "instag.h"
#endif

#define PROCESSING_DONE "DONE"

#define DEFAULT_IP "127.0.0.1"
#define DEFAULT_PORT 1536

#define Q_ID_RECEIVED 1
#define Q_ID_RECEIVED_OTR 2
#define Q_ID_ERR 3
#define Q_ID_GONE_SECURE 4

int sockfd = -1;

FILE *logfd = NULL;

OtrlUserState us;
static char* our_account = "default_account";
static char* our_protocol = "default_protocol";

pthread_mutex_t stdout_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;


static OtrlPolicy op_policy(void *opdata, ConnContext *context) {
    return OTRL_POLICY_DEFAULT;
}

static void op_inject(void *opdata, const char *accountname,
	const char *protocol, const char *recipient, const char *message);


char* pass_otr_in_msg(char* account, char* protocol, char* msg);

void write_query_response(uint32_t id, const char* msg);
void write_query_response_s(uint32_t id, unsigned char* buf, uint32_t msg_size);

#ifdef  OTR40
const char* otr_error_message(void *opdata, ConnContext *context, OtrlErrorCode err_code);
void otr_error_message_free(void *opdata, const char *err_msg);
void handle_msg_event(void *opdata, OtrlMessageEvent msg_event, ConnContext *context, const char *message, gcry_error_t err);
#endif

#if defined OTR30 || defined OTR31 || defined OTR32
int display_otr_message(void *opdata, const char *accountname, const char *protocol, const char *username, const char *msg);
#endif

uint32_t all_contexts_to_buf(unsigned char** buf_p);

uint32_t context_to_buf(unsigned char** buf_p, uint32_t protocol_version, char* username, char * accountname, 
                        char * protocol, uint32_t otr_offer, uint32_t msg_state, uint32_t auth_state, 
                        uint32_t our_instance, uint32_t their_instance);

void gone_secure(void *opdata, ConnContext *context);

int max_message_size(void *opdata, ConnContext *context);

#ifdef OTR30
static OtrlMessageAppOps ops = {
    op_policy,
    NULL,
    NULL,
    op_inject,
    NULL,
    display_otr_message,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    gone_secure,
    NULL,
    NULL,
    NULL
};
#endif

#if defined OTR31 || defined OTR32
static OtrlMessageAppOps ops = {
    op_policy,
    NULL,
    NULL,
    op_inject,
    NULL,
    display_otr_message,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    gone_secure,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};
#endif

#ifdef OTR40
static OtrlMessageAppOps ops = {
    op_policy,
    NULL,
    NULL,
    op_inject,
    NULL,
    NULL,
    NULL,
    gone_secure,
    NULL,
    NULL,
    max_message_size,
    NULL,
    NULL,
    NULL,
    otr_error_message,
    otr_error_message_free,
    NULL,
    NULL,
    NULL,
    handle_msg_event,
    NULL,
    NULL,
    NULL
};
#endif

int max_message_size(void *opdata, ConnContext *context) {
#ifdef FRAG40
  return 100;
#else
  return 0;
#endif
}

static void read_fingerprint(char *file) {
  if (otrl_privkey_read_fingerprints(us, file, NULL, NULL)) {
    fprintf(stderr, "Error reading fingerprints");
  }
}

static void read_privkey(char *file) {
  if (otrl_privkey_read(us, file)) {
    fprintf(stderr, "Error reading private key");
  }
}

#ifdef OTR40
static void read_instag(char *file) {
  pthread_mutex_lock(&log_mutex);
  fprintf(logfd, "About to read instance tag: %s \n", file);
  fflush(logfd);
  pthread_mutex_unlock(&log_mutex);
  if (otrl_instag_read(us, file)) {
    fprintf(stderr, "Error reading instance tags");
  }
}
#endif

void waitForEofClear(FILE *f) {
   while (feof(f)) {
      clearerr(f);
      sleep(1);
   }
}

uint32_t read_stdin(char* buf, uint32_t num) {
  uint32_t n_read = 0;
  uint32_t i = 0;
  
  for (i = 0; i < num; i++) {
    unsigned char c = EOF;

    waitForEofClear(stdin);
    c = fgetc(stdin);
  
    if (c == EOF) break;
  
    buf[i] = c;
    n_read++;
  }
  /*waitForEofClear(stdin);
  n_read = read(0, buf, num);*/

  return n_read;
}

uint32_t write_stdout(char* buf, uint32_t num) {
  uint32_t i = 0;
  pthread_mutex_lock(&stdout_mutex);
  
  
  while (i < num) {
    int wrote = fputc((int)buf[i], stdout);
    fflush(stdout);

    if (((unsigned char)wrote) != (unsigned char)(buf[i])) {
      pthread_mutex_lock(&log_mutex);
      fprintf(logfd, "Expected to write %x, returned %x\n", (unsigned char)buf[i], wrote);
      fflush(logfd);
      pthread_mutex_unlock(&log_mutex);
      sleep(1);
      continue;
    }
    
    i++;
  }
  /*i = write(1, buf, num);*/

  pthread_mutex_unlock(&stdout_mutex);
  return i;
}

char* pass_otr_out_msg(uint32_t id, char* account, char* protocol, char* message) {
    char *new_message = NULL;    
    gcry_error_t err;

    pthread_mutex_lock(&log_mutex);
    fprintf(logfd, "Passing to OTR message_sending %s to account %s protocol %s\n", message, account, protocol);
    fflush(logfd);
    pthread_mutex_unlock(&log_mutex);

#ifdef OTR40
#ifdef FRAG40
    err = otrl_message_sending(us, &ops, NULL,
	    our_account, protocol, account, OTRL_INSTAG_BEST, message, NULL, &new_message,
	    OTRL_FRAGMENT_SEND_ALL_BUT_LAST, NULL, NULL, NULL);
#else
    err = otrl_message_sending(us, &ops, NULL,
	    our_account, protocol, account, OTRL_INSTAG_BEST, message, NULL, &new_message,
	    OTRL_FRAGMENT_SEND_SKIP, NULL, NULL, NULL);
#endif
#endif

#if defined OTR30 || defined OTR31 || defined OTR32
    err = otrl_message_sending(us, &ops, NULL,
	    our_account, protocol, account, message, NULL, &new_message,
	    NULL, NULL);
#endif

    if (new_message) {
      char *ourm = strdup(new_message);

      write_query_response(id, new_message); /* send modified message back */ 
      
      otrl_message_free(new_message);
      new_message = ourm;
    }

  if (err) {
    	/* Do not send out plain text */
    	char *ourm = strdup("");
    	new_message = ourm;
  }

  return new_message;
}

void parse_outgoing_msg_otr(uint32_t id, uint32_t *size, unsigned char** buf_ptr) {
  unsigned char* buf = *buf_ptr;
  unsigned char account_len;
  char* account;
  unsigned char protocol_len;
  char* protocol;
  uint32_t msg_len;
  char* msg;
  char* new_msg;

  pthread_mutex_lock(&log_mutex);
  fprintf(logfd, "About to parse outgoing payload for otr\n");
  fflush(logfd);
  pthread_mutex_unlock(&log_mutex);

  account_len = buf[0];
  buf++;
  account = malloc(account_len+1);
  strncpy(account, buf, account_len);
  account[account_len] = '\0';
  buf += account_len;

  protocol_len = buf[0];
  buf++;
  protocol = malloc(protocol_len+1);
  strncpy(protocol, buf, protocol_len);
  protocol[protocol_len] = '\0';
  buf += protocol_len;

  msg_len = *((uint32_t*)buf);
  msg_len = ntohl(msg_len);
  buf += 4;

  if (msg_len) {
    pthread_mutex_lock(&log_mutex);
    fprintf(logfd, "Outgoing payload contained msg length %u\n", msg_len);
    fflush(logfd);
    pthread_mutex_unlock(&log_mutex);
    
    msg = malloc(msg_len+1);
    strncpy(msg, buf, msg_len);
    msg[msg_len] = '\0';
    
    pthread_mutex_lock(&log_mutex);
    fprintf(logfd, "Outgoing msg %s\n", msg);
    fflush(logfd);
    pthread_mutex_unlock(&log_mutex);
    
    new_msg = pass_otr_out_msg(id, account, protocol, msg);
    if (new_msg) {
      pthread_mutex_lock(&log_mutex);
      fprintf(logfd, "New msg from OTR: %s len: %u\n", new_msg, strlen(new_msg));
      fflush(logfd);
      pthread_mutex_unlock(&log_mutex);
    }
  }

  if (new_msg) {
    uint32_t new_msg_len = strlen(new_msg);
    uint32_t new_buf_len = 1 + account_len + 1 + protocol_len + 4 + new_msg_len;
    unsigned char* new_buf = malloc(new_buf_len);
    unsigned char* new_buf_head = new_buf;
      
    *size = new_buf_len;
    memcpy(new_buf, *buf_ptr, 1 + account_len + 1 + protocol_len);
    new_buf += 1 + account_len + 1 + protocol_len;
    *((uint32_t*)new_buf) = htonl(new_msg_len);
    new_buf += 4;
    strncpy(new_buf, new_msg, new_msg_len);
    free(new_msg);
    free(*buf_ptr); 
    *buf_ptr = new_buf_head;
    if (msg) free(msg);
  } else {
      *size = strlen(msg);
      *buf_ptr = msg;
  }

  free(account);
  free(protocol);
}



int send_msg(uint32_t size, char* payload) {
  int sent = -1;
  if (sent = send(sockfd, payload, size, 0) != size) {
    fprintf(stderr, "Error sending data (send_msg)\n");
  }
  return sent;
}

int send_msg_otr(uint32_t id, uint32_t size, char** payload) {
  int sent = -1;

  if (!size || !*payload) return sent;

  parse_outgoing_msg_otr(id, &size, (unsigned char**) payload);
  
  if (!size || !*payload) return sent;
  
  sent = send_msg(size, *payload);

  return sent;
}

process_command_privkey(uint32_t size, char* payload) {
  char path[size+1];
  strncpy(path, payload, size);
  path[size] = '\0';
  read_privkey(path);
}

#ifdef OTR40
process_command_instag(uint32_t size, char* payload) {
  char path[size+1];
  strncpy(path, payload, size);
  path[size] = '\0';
  read_instag(path);
}
#endif

void finish_up() {
  close((int)logfd);
  close(sockfd);
  exit(0);
}

void check_finished(uint16_t command) {
  if (command == 0xFFFF) {
    pthread_mutex_lock(&log_mutex);
    fprintf(logfd, "%s", "Read command 0xFFFF, assuming parent is finished\n");
    fflush(logfd);
    pthread_mutex_unlock(&log_mutex);
    finish_up();
  }
}

void write_all_contexts(uint32_t id) {
  unsigned char* buf = NULL;
  uint32_t buf_size = all_contexts_to_buf(&buf);
  
  pthread_mutex_lock(&log_mutex);
  fprintf(logfd, "%s", "***************** dumping all contexts ********************\n");
  fwrite(buf, 1, buf_size, logfd);
  fprintf(logfd, "%s", "\n***************** done dumping contexts ********************\n");
  fflush(logfd);
  pthread_mutex_unlock(&log_mutex);
  
  write_query_response_s(id, buf, buf_size);
  free(buf);
}

void gone_secure(void *opdata, ConnContext *context) {
  unsigned char* buf = NULL;
  uint32_t buf_size = 0;
  
  if (!context) return;
  
  #if defined OTR30 || defined OTR31 || defined OTR32
  buf_size = context_to_buf(&buf, context->protocol_version, context->username, 
                              context->accountname, context->protocol, context->otr_offer, context->msgstate, 
                              context->auth.authstate, 0, 0);
  #endif
    
  #if defined OTR40
  buf_size = context_to_buf(&buf, context->protocol_version, context->username, 
                              context->accountname, context->protocol, context->otr_offer, context->msgstate, 
                              context->auth.authstate, context->our_instance, context->their_instance);
  #endif
  
  pthread_mutex_lock(&log_mutex);
  fprintf(logfd, "Context %s %s %s has gone secure (printing data below)\n", context->username, context->accountname, context->protocol);
  fwrite(buf, 1, buf_size, logfd);
  fprintf(logfd, "%s", "\n");
  fflush(logfd);
  pthread_mutex_unlock(&log_mutex);
  
  write_query_response_s(Q_ID_GONE_SECURE, buf, buf_size);
  free(buf); 
}

void process_command(uint16_t command, 
		     uint32_t id, uint32_t size, char** payload) {
  switch (command) {
  case 0x0000: /* send msg (no OTR) */
    send_msg(size, *payload);
    break;
  case 0x0001: /* send msg */
    #ifdef __DEBUGGING
    pthread_mutex_lock(&log_mutex);
    fprintf(logfd, "%s", "Sending message...\n");
    fflush(logfd);
    pthread_mutex_unlock(&log_mutex);
    #endif
    
    send_msg_otr(id, size, payload);
    break;
  case 0x0002: /* read privkey */ 
    process_command_privkey(size, *payload);
    break;
  case 0x0003: /* write all contexts */
    write_all_contexts(id);
    break;
  #ifdef OTR40
  case 0x004:
    process_command_instag(size, *payload);
    break;
  #endif
  }
  write_query_response(id, PROCESSING_DONE);
}

process_and_write_msg(unsigned char account_len, char* account, 
	    unsigned char protocol_len, char* protocol, 
	    uint32_t msg_len, char* msg, uint32_t q_id) {
  /* re-assemble message as single buffer */
  unsigned char* buf;
  unsigned char* buf_head;
  
  if (msg == NULL || msg_len == 0) return;

  uint32_t total_len = 4 + 4 + 1 + account_len + 1 + protocol_len + 4 + msg_len;
  buf = malloc(total_len);
  buf_head = buf;

  *((uint32_t*)buf) = htonl(q_id);
  buf += 4;

  *((uint32_t*)buf) = htonl(total_len - 8);
  buf += 4;

  buf[0] = account_len;
  buf++;
  strncpy(buf, account, account_len);
  buf += account_len;

  buf[0] = protocol_len;
  buf++;
  strncpy(buf, protocol, protocol_len);
  buf += protocol_len;

  *((uint32_t*)buf) = htonl(msg_len);
  buf += 4;
  strncpy(buf, msg, msg_len);

  uint32_t written = write_stdout(buf_head, total_len);
  
  if (written == total_len) {
    
    #ifdef __DEBUGGING
    pthread_mutex_lock(&log_mutex);
    fprintf(logfd, "%s", "Msg written to stdout\n");
    fflush(logfd);
    pthread_mutex_unlock(&log_mutex);
    #endif
    
  } else {
    pthread_mutex_lock(&log_mutex);
    fprintf(logfd, "Only wrote %u bytes to stdout, expected %u\n", written, total_len);
    fprintf(logfd, "Failed on message from account %s protocol %s contents %s\n", account, protocol, msg);
    fflush(logfd);
    pthread_mutex_unlock(&log_mutex);
    fprintf(stderr, "Only wrote %u bytes to stdout, expected %u\n", written, total_len);
  }
  
  free(buf_head);
}

void* receive_msgs(void* data) {
  int recvd = 0;
  int finished = 0;

  while (1) {
    unsigned char account_len;
    char* account = 0;
    unsigned char protocol_len;
    char* protocol = 0;
    uint32_t msg_len;
    char* msg = 0;
    uint32_t new_msg_len;
    char* new_msg = NULL;
    #ifdef __DEBUGGING
    char print_buf[1024];
    #endif

    if (recvd = recv(sockfd, &account_len, 1, 0) != 1) {
      fprintf(stderr, "account_len: Failed to receive from socket\n");
      break;
    }

    account = malloc(account_len+1);

    if (recvd = recv(sockfd, account, account_len, 0) != account_len) {
      fprintf(stderr, "account: Failed to receive from socket\n");
      break;
    }

    if (recvd = recv(sockfd, &protocol_len, 1, 0) != 1) {
      fprintf(stderr, "protocol_len: Failed to receive from socket\n");
      break;
    }

    protocol = malloc(protocol_len+1);

    if (recvd = recv(sockfd, protocol, protocol_len, 0) != protocol_len) {
      fprintf(stderr, "protocol: Failed to receive from socket\n");
      break;
    }

    if (recvd = recv(sockfd, &msg_len, 4, 0) != 4) {
      fprintf(stderr, "msg_len: Failed to receive from socket\n");
      break;
    }

    msg_len = ntohl(msg_len);
    msg = malloc(msg_len+1);

    if (recvd = recv(sockfd, msg, msg_len, 0) != msg_len) {
      fprintf(stderr, "msg: Failed to receive from socket. length: %u, recvd: %u, %s\n", msg_len, recvd, strerror( errno ));
      break;
    }
    
    #ifdef __DEBUGGING
    sprintf(print_buf, "Received msg: %u %%.%us, from account %u %%.%us protocol %u %%.%us\n", msg_len, msg_len, account_len, account_len, protocol_len, protocol_len);
    pthread_mutex_lock(&log_mutex);
    fprintf(logfd, print_buf, msg, account, protocol);
    fflush(logfd);
    pthread_mutex_unlock(&log_mutex);
    #endif
    
    account[account_len] = '\0';
    protocol[protocol_len] = '\0';
    msg[msg_len] = '\0';

    process_and_write_msg(account_len, account, protocol_len, protocol, msg_len, msg, Q_ID_RECEIVED);

    new_msg = pass_otr_in_msg(account, protocol, msg);

    if (new_msg) {
      new_msg_len = strlen(new_msg);
      process_and_write_msg(account_len, account, protocol_len, protocol, new_msg_len, new_msg, Q_ID_RECEIVED_OTR);
      free(new_msg);
    }
    
    free(msg);
    free(account);
    free(protocol);
  }
}

uint32_t context_to_buf(unsigned char** buf_p, uint32_t protocol_version, char* username, char * accountname, 
                        char * protocol, uint32_t otr_offer, uint32_t msg_state, uint32_t auth_state, 
                        uint32_t our_instance, uint32_t their_instance) {
  uint32_t username_len = strlen(username);
  uint32_t accountname_len = strlen(accountname);
  uint32_t protocol_len = strlen(protocol);
  uint32_t buf_size = 4 + 1 + username_len + 1 + accountname_len + 1 + protocol_len + 4 + 4 + 4 + 4 + 4;
  unsigned char* buf = malloc(buf_size);
  *buf_p = buf;
  
  *((uint32_t*)buf) = htonl(protocol_version);
  buf += 4;
  
  *buf = username_len;
  buf++;
  
  strncpy(buf, username, username_len);
  buf += username_len;
  
  *buf = accountname_len;
  buf++;
  
  strncpy(buf, accountname, accountname_len);
  buf += accountname_len;
  
  *buf = protocol_len;
  buf++;
  
  strncpy(buf, protocol, protocol_len);
  buf += accountname_len;
  
  *((uint32_t*)buf) = htonl(otr_offer);
  buf += 4;
  
  *((uint32_t*)buf) = htonl(msg_state);
  buf += 4;
  
  *((uint32_t*)buf) = htonl(auth_state);
  buf += 4;
  
  *((uint32_t*)buf) = htonl(our_instance);
  buf += 4;
  
  *((uint32_t*)buf) = htonl(their_instance);
  buf += 4;
  
  
  return buf_size;
}

uint32_t all_contexts_to_buf(unsigned char** buf_p) {
  ConnContext *context = us->context_root;
  unsigned char* buf = NULL;
  uint32_t buf_size = 0;
  uint32_t num_contexts = 0;
  
  while (context != NULL) {
    unsigned char* temp_buf;
    
    uint32_t temp_buf_size = 0;
    
    #if defined OTR30 || defined OTR31 || defined OTR32
    temp_buf_size = context_to_buf(&temp_buf, context->protocol_version, context->username, 
                                context->accountname, context->protocol, context->otr_offer, context->msgstate, 
                                context->auth.authstate, 0, 0);
    #endif
    
    #if defined OTR40
    temp_buf_size = context_to_buf(&temp_buf, context->protocol_version, context->username, 
                                context->accountname, context->protocol, context->otr_offer, context->msgstate, 
                                context->auth.authstate, context->our_instance, context->their_instance);
    #endif

    unsigned char* new_buf = malloc(buf_size + temp_buf_size);
    if (buf != NULL) memcpy(new_buf, buf, buf_size);
    memcpy(new_buf + buf_size, temp_buf, temp_buf_size);

    free(buf);
    free(temp_buf);
    buf = new_buf;
    buf_size += temp_buf_size;
    
    context = context->next;
    num_contexts++;
  }
  
  /* precede serialized contexts by number of contexts */
  if (num_contexts) {
    unsigned char* new_buf = malloc(4 + buf_size);
    *((uint32_t *)new_buf) = htonl(num_contexts);
    memcpy(new_buf + 4, buf, buf_size);
    free(buf);
    buf = new_buf;
    buf_size += 4;
  }
  
  *buf_p = buf;
  return buf_size;
}

void op_inject(void *opdata, const char *accountname,
	const char *protocol, const char *recipient, const char *message) {
  unsigned char recipient_len = strlen(recipient);
  unsigned char protocol_len = strlen(protocol);
  uint32_t message_len = strlen(message);
  uint32_t total_len = 1 + recipient_len + 1 + protocol_len + 4 + message_len;
  unsigned char *buf = malloc(total_len);
  unsigned char *buf_head = buf;
  
  pthread_mutex_lock(&log_mutex);
  fprintf(logfd, "Inject called with message %s for account %s protocol %s from account %s\n", message, recipient, protocol, accountname);
  fflush(logfd);
  pthread_mutex_unlock(&log_mutex);

  buf[0] = recipient_len;
  buf++;
  strncpy(buf, recipient, recipient_len);
  buf += recipient_len;
  
  buf[0] = protocol_len;
  buf++;
  strncpy(buf, protocol, protocol_len);
  buf += protocol_len;

  *((uint32_t*)buf) = htonl(message_len);
  buf += 4;
  strncpy(buf, message, message_len);

  send_msg(total_len, buf_head);
  free(buf_head);
}

#ifdef OTR40
const char* otr_error_message(void *opdata, ConnContext *context, OtrlErrorCode err_code) {
  char* msg = "";
  char* result;

  pthread_mutex_lock(&log_mutex);
  fprintf(logfd, "otr_error_message called with err_code %u\n", err_code);
  fflush(logfd);
  pthread_mutex_unlock(&log_mutex);

  switch(err_code) {
  case OTRL_ERRCODE_ENCRYPTION_ERROR:
    msg = "OTRL_ERRCODE_ENCRYPTION_ERROR";
    break;
  case OTRL_ERRCODE_MSG_NOT_IN_PRIVATE:
    msg = "OTRL_ERRCODE_MSG_NOT_IN_PRIVATE";
    break;
  case OTRL_ERRCODE_MSG_UNREADABLE:
    msg = "OTRL_ERRCODE_MSG_UNREADABLE";
    break;
  case OTRL_ERRCODE_MSG_MALFORMED:
    msg = "OTRL_ERRCODE_MSG_MALFORMED";
    break;
  default:
    break;
  }

  /* copy any info from context? */

  result = malloc(strlen(msg)+1);
  strcpy(result, msg);
  
  return result;
}
#endif

void otr_error_message_free(void *opdata, const char *err_msg) {
  free((char*)err_msg);
}

/* msg should be a null-terminated string */
void write_query_response(uint32_t id, const char* msg) {
  write_query_response_s(id, (unsigned char*)msg, strlen(msg));
}

void write_query_response_s(uint32_t id, unsigned char* msg, uint32_t msg_size) {
  uint32_t buf_size = 0;
  unsigned char* buf;
  unsigned char* buf_head;
  
  buf_size = 4 + 4 + msg_size;
  buf = malloc(buf_size);
  buf_head = buf;
  
  pthread_mutex_lock(&log_mutex);
  fprintf(logfd, "Writing query response to stdout -- id %u size %u msg size %u msg %s\n", id, buf_size, msg_size, msg);
  fflush(logfd);
  pthread_mutex_unlock(&log_mutex);
  
  *((uint32_t*)buf) = htonl(id);
  buf += 4;
  
  *((uint32_t*)buf) = htonl((uint32_t)msg_size);
  buf += 4;
  
  memcpy(buf, msg, msg_size);
  
  uint32_t written = buf_size;
  written = write_stdout(buf_head, buf_size);
  
  if (written == buf_size) {
    
    pthread_mutex_lock(&log_mutex);
    fprintf(logfd, "%s", "Msg written to stdout\n");
    fflush(logfd);
    pthread_mutex_unlock(&log_mutex);
    
  } else {
    pthread_mutex_lock(&log_mutex);
    fprintf(logfd, "Only wrote %u bytes to stdout, expected %u\n", written, buf_size);
    fflush(logfd);
    pthread_mutex_unlock(&log_mutex);
    fprintf(stderr, "Only wrote %u bytes to stdout, expected %u\n", written, buf_size);
  }  
  
  free(buf_head);
}

#if defined OTR30 || defined OTR31 || defined OTR32
int display_otr_message(void *opdata, const char *accountname, const char *protocol, const char *username, const char *msg) {
  pthread_mutex_lock(&log_mutex);
  fprintf(logfd, "display_otr_message called with msg %s\n", msg);
  fflush(logfd);
  pthread_mutex_unlock(&log_mutex);
  write_query_response(Q_ID_ERR, msg);
}
#endif

#ifdef OTR40
void handle_msg_event(void *opdata, OtrlMessageEvent msg_event, ConnContext *context, const char *message, gcry_error_t err) {
  char* msg = "";

  switch(msg_event) {
    case OTRL_MSGEVENT_NONE:
      msg = "OTRL_MSGEVENT_NONE";
      break;
    case OTRL_MSGEVENT_ENCRYPTION_REQUIRED:
      msg = "OTRL_MSGEVENT_ENCRYPTION_REQUIRED";
      break;
    case OTRL_MSGEVENT_ENCRYPTION_ERROR:
      msg = "OTRL_MSGEVENT_ENCRYPTION_ERROR";
      break;
    case OTRL_MSGEVENT_CONNECTION_ENDED:
      msg = "OTRL_MSGEVENT_CONNECTION_ENDED";
      break;
    case OTRL_MSGEVENT_SETUP_ERROR:
      msg = "OTRL_MSGEVENT_SETUP_ERROR";
      break;
    case OTRL_MSGEVENT_MSG_REFLECTED:
      msg = "OTRL_MSGEVENT_MSG_REFLECTED";
      break;
    case OTRL_MSGEVENT_MSG_RESENT:
      msg = "OTRL_MSGEVENT_MSG_RESENT";
      break;
    case OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE:
      msg = "OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE";
      break;
    case OTRL_MSGEVENT_RCVDMSG_UNREADABLE:
      msg = "OTRL_MSGEVENT_RCVDMSG_UNREADABLE";
      break;
    case OTRL_MSGEVENT_RCVDMSG_MALFORMED:
      msg = "OTRL_MSGEVENT_RCVDMSG_MALFORMED";
      break;
    case OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD:
      msg = "OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD";
      break;
    case OTRL_MSGEVENT_LOG_HEARTBEAT_SENT:
      msg = "OTRL_MSGEVENT_LOG_HEARTBEAT_SENT";
      break;
    case OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR:
      msg = "OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR";
      break;
    case OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED:
      msg = "OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED";
      break;
    case OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED:
      msg = "OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED";
      break;
    case OTRL_MSGEVENT_RCVDMSG_FOR_OTHER_INSTANCE:
      msg = "OTRL_MSGEVENT_RCVDMSG_FOR_OTHER_INSTANCE";
      break;
  }
  
  pthread_mutex_lock(&log_mutex);
  fprintf(logfd, "Handle_msg_event called with msg_event %s errcode %i message %s \n", msg, gcry_err_code(err), message);
  fflush(logfd);
  pthread_mutex_unlock(&log_mutex);
  
  write_query_response(Q_ID_ERR, msg);
  
}
#endif

char* pass_otr_in_msg(char* account, char* protocol, char* msg)  {
  char *new_message = NULL;
  OtrlTLV *tlvs = NULL;
  uint32_t ignore = 0;

  pthread_mutex_lock(&log_mutex);
  fprintf(logfd, "Passing incoming msg to OTR from account %s protocol %s payload %s\n", account, protocol, msg);
  fflush(logfd);
  pthread_mutex_unlock(&log_mutex);

  #if defined OTR40
  ignore = otrl_message_receiving(us, &ops, NULL,
    our_account, protocol, account, msg,
    &new_message, &tlvs, NULL, NULL, NULL);
  #endif


  #if defined OTR30 || defined OTR31 || defined OTR32
  ignore = otrl_message_receiving(us, &ops, NULL,
    our_account, protocol, account, msg,
    &new_message, &tlvs, NULL, NULL);
  #endif

  if (new_message) {
    char *ourm = malloc(strlen(new_message) + 1);
    if (ourm) {
      strcpy(ourm, new_message);
    }

    otrl_message_free(new_message);
    new_message = ourm;
    
    pthread_mutex_lock(&log_mutex);
    fprintf(logfd, "New message from OTR message_receiving %s\n", new_message);
    fflush(logfd);
    pthread_mutex_unlock(&log_mutex);
  }

  if (ignore) {
    free(new_message);
    new_message = NULL;
  }

  return new_message;
}

int main(int argc, char *argv[]) {
  char* remote_ip = DEFAULT_IP;
  uint32_t remote_port = DEFAULT_PORT;
  struct sockaddr_in addr;

  OTRL_INIT;

  us = otrl_userstate_create();
  
  if (argc > 1) {
    our_account = argv[1];
  }

  if (argc > 2) {
    our_protocol = argv[2];
  }

  if (argc > 3) {
    remote_ip = argv[3];
  }

  if (argc > 4) {
    remote_port = atoi(argv[4]);
  }

  if (argc > 5) {
    logfd = fopen(argv[5], "w");
  } else {
    logfd = fopen(our_account, "w");
  }

  pthread_mutex_lock(&log_mutex);
  fprintf(logfd, "Connecting to dummy_im: %s:%u\n", remote_ip, remote_port);
  fflush(logfd);
  pthread_mutex_unlock(&log_mutex);
  
  if ((sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
    fprintf(stderr, "Cannot create socket\n");
    exit(1);
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(remote_ip);
  addr.sin_port = htons(remote_port);

  if (connect(sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
    fprintf(stderr, "Cannot connect to server\n");
    exit(1);
  }

  pthread_mutex_init(&stdout_mutex, NULL);
  pthread_mutex_init(&log_mutex, NULL);
  

  /* pthread launch thread that receives from socket and wrties to stdout */
  pthread_t t_socker_reader;
  pthread_create(&t_socker_reader, NULL, receive_msgs, (void*) &sockfd);

  /* the main thread will receive commands from stdin and write to socket */
  while(1) {
    unsigned char buf[10];
    uint16_t command = 0;
    uint32_t id = 0;
    uint32_t size = 0;
    char* payload = 0;

    if (read_stdin(buf, 10) != 10) {
      fprintf(stderr, "Error reading from stdin\n");
      return;
    }

    command = ntohs(*((uint16_t*)(buf)));
    id = ntohl(*((uint32_t*)(buf+2)));
    size = ntohl(*((uint32_t*)(buf+6)));
    
    pthread_mutex_lock(&log_mutex);
    fprintf(logfd, "Received command msg: %X id: %u size: %u\n", command, id, size);
    fflush(logfd);
    pthread_mutex_unlock(&log_mutex);

    check_finished(command);
    payload = malloc(size);
    
    if (read_stdin(payload, size) != size) {
      fprintf(stderr, "Error reading from stdin\n");
      return;
    }
    
    pthread_mutex_lock(&log_mutex);
    
    fprintf(logfd, "Received payload\n");
    fflush(logfd);
    pthread_mutex_unlock(&log_mutex);
    
    process_command(command, id, size, &payload);

    free(payload);
  }

}
