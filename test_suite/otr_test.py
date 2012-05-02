#!/usr/bin/python

import sys
import itertools
import re
import Queue

from dummy_im import *
from otr_subprocess import *

client_location_30 = "./otr_c_client/dummy_client_30"
client_location_31 = "./otr_c_client/dummy_client_31"
client_location_32 = "./otr_c_client/dummy_client_32"
client_location_40 = "./otr_c_client/dummy_client_40"

client_locations = [client_location_30, client_location_31, client_location_32, client_location_40]


class otr_test_failed_exception(Exception):    
  def __init__(self, value, p_list=None):
    self.value = value
    self.p_list = p_list
    if p_list is not None:
      for p in p_list:
        q_id = p.send_get_contexts()
        serialized_contexts = p.get_query_blocking(q_id)
        p_contexts = deserialize_contexts(serialized_contexts)
        print("Dumping contexts:")
        dump_contexts(p_contexts)
        print("Dumping raw messages:")
        dump_msg_queue(p.querymap[q_raw_msg])
        print("Dumping otr-processed messages:")
        dump_msg_queue(p.querymap[q_otr_msg])
        print("Dumping error messages:")
        dump_queue(p.querymap[q_err])

  def __str__(self):
    return "Test Failed: " + repr(self.value)

class otr_test:
  def __init__(self, alices, bobs):
    
    self.alices = alices
    self.bobs = bobs
    self.subprocesses = alices + bobs
    
  #no default tests -- always defined by child class
  def run_test(self, options={}):
    return

  def reset_processes(self):
    for p in self.subprocesses:
      p.sigint()
    
    #Give them a moment to terminate on their own if they are willing and able  
    time.sleep(0.5)
      
    for p in self.subprocesses:
      p.reset()    
  
  def check_error_all(self, allowed_events=[]): 
    for p in self.subprocesses:
      p.check_error()
      if not p.querymap[q_err].empty():
        tmp_stack = []
        
        while not p.querymap[q_err].empty():
          item = p.querymap[q_err].get(False)
          if allowed_events.count(item) < 1:
            raise otr_test_failed_exception(item, [p])
          tmp_stack.append(item)
        
        while len(tmp_stack) > 0:
          p.querymap[q_err].put(tmp_stack.pop())
    
        
  def wait_all_gone_encrypted(self):
    for p in self.subprocesses:
      p.get_query_blocking(q_gone_secure) #Wait for "gone encrypted" signal
      print(p.accountname + " " + p.protocol + " went encrypted")
      
  def send_encrypted_and_check(self, senders, receivers, out_msg, options={}):
    for p in list(set(senders)):
      print("About to send encrypted message")
      msg_id = p.send_msg(receivers[0].accountname, receivers[0].protocol, out_msg)
      modified_msg = p.get_query_blocking(msg_id)
      print("Encrypted message sent")

      if modified_msg.find(out_msg) >= 0:
        raise otr_test_failed_exception("Sent message not encrypted", self.subprocesses)
      
    receiver_msgs = []

    for p in list(set(receivers)): #remove duplicates
      print("About to receive raw encrypted message")
      receiver_msgs.append(get_n_messages_blocking(p.querymap[q_raw_data_msg], len(list(set(senders)))))
      
    for msg in receiver_msgs:
      check_contains_message_matches_ex(msg, otr_data_prefix_regex, len(list(set(senders))), self.subprocesses)   

    for i in range(len(list(set(senders)))):      
      print("About to receive decrypted message")
      receiver_recvd = find_first_msg_blocking(receivers, q_otr_msg)
        
      if not check_message_matches(receiver_recvd, re.escape(out_msg)):
        raise otr_test_failed_exception("Received message not decrypted", self.subprocesses)
        
  def check_all_contexts_encrypted(self, options={}):
    for p in self.alices:
      c_id = p.send_get_contexts()
      serialized_contexts = p.get_query_blocking(c_id)
      p_contexts = deserialize_contexts(serialized_contexts)
      check_contexts_for_encrypted(p_contexts, self.num_bob, p)
      
    for p in self.bobs:
      c_id = p.send_get_contexts()
      serialized_contexts = p.get_query_blocking(c_id)
      p_contexts = deserialize_contexts(serialized_contexts)
      check_contexts_for_encrypted(p_contexts, self.num_alice, p)
      
  def init_processes(self, options={}):
    for p in self.subprocesses:
        p.check_error()
    
    privkey = options.get('privkey', 'otr.private_key')
    
    for p in self.subprocesses:
      c_id = p.send_read_privkey(privkey)
      p.get_query_blocking(c_id)
        
    for i, p in enumerate(self.alices):  
      c_id = p.send_read_instag("instance_tags" + str(i) + ".txt")
      p.get_query_blocking(c_id)
      
    for i, p in enumerate(self.bobs):  
      c_id = p.send_read_instag("instance_tags" + str(i) + ".txt")
      p.get_query_blocking(c_id)
        
    for p in self.subprocesses:
      c_id = p.send_init()
      p.get_query_blocking(c_id)
      
    for p in self.subprocesses:
      p.check_error()
    
  def otr_init_msg(self, options={}):
    alice_init_idx = options.get('alice_init_idx', 0)
    msg_id = self.alices[alice_init_idx].send_msg(self.bob_account, self.bob_proto, self.msg1)
    modified_msg = self.alices[alice_init_idx].get_query_blocking(msg_id)
    done = self.alices[alice_init_idx].get_query_blocking(msg_id)
    
    for p in self.bobs:
      msg = p.get_query_blocking(q_otr_msg)
      if check_message_matches(msg, re.escape(self.msg1) + otr_tab_tag):
        raise otr_test_failed_exception("Query tabs not removed", self.subprocesses)
        
      check_message_matches_ex(msg, re.escape(self.msg1), self.subprocesses)

  def otr_init_query(self, options={}):
    msg_id = self.alices[0].send_msg(self.bob_account, self.bob_proto, otr_query)
    modified_msg = self.alices[0].get_query_blocking(msg_id)
    done = ""
    while done.find("DONE") < 0:
      done = self.alices[0].get_query_blocking(msg_id)

    #More to check?
    
#TODO: Make these methods class methods / static methods?
def chomp_auth_msgs(ps):
  for p in ps:
    msgs = get_n_messages_blocking(p.querymap[q_raw_msg], p.querymap[q_raw_msg].qsize())
    for msg in msgs:
      parsed_msg = deserialize_msg(msg)[2]
      if parsed_msg.find("?OTR") != 0:
        p.querymap[q_raw_msg].put(msg)
    
def chomp_msgs(ps, q_idx):
  for p in ps:
    get_n_messages_blocking(p.querymap[q_idx], p.querymap[q_idx].qsize())
    

def wait_gone_encrypted(ps):
  for p in ps:
    p.get_query_blocking(q_gone_secure) #Wait for "gone encrypted" signal

def find_first_msg_blocking(ps, q_idx):
  #We have to spin here until this is implemented: 
  # http://bugs.python.org/issue3831
  result = None
  
  while result is None:
    for p in ps:
      try:
        result = p.querymap[q_idx].get(True, 0.05) #block for 50ms
        break
      except (Queue.Empty) as e:
        continue
  
  return result

def check_message_matches(msg, regex):
  msg = deserialize_msg(msg)
  return re.match(regex, msg[2]) is not None

def check_message_matches_ex(msg, regex, p_list):
  if not check_message_matches(msg, regex):
    raise otr_test_failed_exception("msg failed to match regex -- regex: " + regex + " msg: " + msg[2], p_list)

def check_contains_message_matches_ex(msgs, regex, n, p_list):
  matches = 0
  for msg in msgs:
    if check_message_matches(msg, regex):
      matches += 1
      
  if matches < n:
    raise otr_test_failed_exception("msg failed to match regex " + str(n) + " times -- regex: " + regex + " matches: " + str(matches) + " msgs: " + str(msgs), p_list)


#Given a process's list of contexts, check that num_expected_encrypted are encrypted
def check_contexts_for_encrypted(contexts, num_expected_encrypted, p):
  num_good = 0

  if num_expected_encrypted > 1 and p.client_location != client_location_40: #XXX: support future versions
    raise otr_test_failed_exception("Expected > 1 good contexts on protocol version < 2", [p])
  
  if len(contexts) == 0:
    raise otr_test_failed_exception("Failed: No contexts", [p])
    
  if p.client_location != client_location_40 and num_expected_encrypted == 1 and len(contexts) == 1:
    if not check_context_encrypted(contexts[0], p):
      raise otr_test_failed_exception("Failed: Not encrypted", [p])
    
  else:
    for context in contexts:
      if check_context_encrypted(context, p):
        num_good += 1
        
    if num_good < num_expected_encrypted:
      msg = "Failed: fewer than expected encrypted contexts. Found " + str(num_good) + " Expected " + str(num_expected_encrypted)
      raise otr_test_failed_exception(msg, [p])

def check_offer_accepted(context):
  if context.offer_state != 3:
        raise otr_test_failed_exception("Failed: Offer not given or not accepted")
  
def check_context_encrypted(context, p):
  if context.msg_state == 1:
    return True
  else: 
    return False
