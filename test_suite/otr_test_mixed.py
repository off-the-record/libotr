#!/usr/bin/python

import sys
import itertools
import re
import Queue

from otr_test import *

class otr_test_mixed(otr_test):
  #Supports multiple 4.0 clients or single 3.X clients

  def __init__(self, alices, bobs):
    otr_test.__init__(self, alices, bobs)
    
    self.alice_account = alices[0].accountname
    self.alice_proto = alices[0].protocol
      
    self.bob_account = bobs[0].accountname
    self.bob_proto = bobs[0].protocol
    
    self.num_alice = len(self.alices)
    self.num_bob = len(self.bobs)
  
  def run_test(self, options={}):
    try:
      self.msg1 = options.get('msg1', '%$sup?')
      self.msg2 = options.get('msg2', '^&not much')
      self.msg3 = options.get('msg3', '*(cool')
      
      self.init_processes(options)
      
      if options.get('otr_init_method', 'msg') == 'msg':
        self.otr_init_msg(options)
      elif options.get('otr_init_method', 'msg') == 'query':
        self.otr_init_query()
      
      alice_encrypted_idx = options.get('alice_expected_encrypted_idx', range(len(self.alices)))
      bob_encrypted_idx = options.get('bob_expected_encrypted_idx', range(len(self.bobs)))
      
      alice_encrypted = []
      for i in alice_encrypted_idx:
        alice_encrypted.append(self.alices[i])
      
      bob_encrypted = []
      for i in bob_encrypted_idx:
        bob_encrypted.append(self.bobs[i])
      

      wait_gone_encrypted(alice_encrypted + bob_encrypted)
      time.sleep(1) #Ensure all messages received and processed

      chomp_msgs(alice_encrypted + bob_encrypted, q_raw_msg)

      #Check contexts
      for p in list(set(alice_encrypted)):
        c_id = p.send_get_contexts()
        serialized_contexts = p.get_query_blocking(c_id)
        p_contexts = deserialize_contexts(serialized_contexts)
        check_contexts_for_encrypted(p_contexts, alice_encrypted.count(p), p)
        

      for p in list(set(bob_encrypted)):
        c_id = p.send_get_contexts()
        serialized_contexts = p.get_query_blocking(c_id)
        p_contexts = deserialize_contexts(serialized_contexts)
        check_contexts_for_encrypted(p_contexts, bob_encrypted.count(p), p)
        

      #We only send messages between the 4.0s because the 3.X will be paired with only one partner, and we don't know 
      #for sure which one.
      self.send_encrypted_and_check(return_only_40(bob_encrypted), return_only_40(alice_encrypted), self.msg2, options)

      self.send_encrypted_and_check(return_only_40(alice_encrypted), return_only_40(bob_encrypted), self.msg3, options)

      #Non-4.0 clients will error from unexpected messages, but we are expecting this
      for p in self.subprocesses:
        p.check_error()
        if not p.querymap[q_err].empty() and p.client_location == client_location_40:
          errors = get_n_messages_blocking(p.querymap[q_err], p.querymap[q_err].qsize())
          for error in errors: 
            print("Warning: setup errors detected: " + error)

      print("Test succeeded")
      self.reset_processes()
      
    except (subprocess_exception, otr_test_failed_exception) as e:
      print '***Exception: ', e.value, sys.exc_info()
      self.reset_processes()
      print("Test failed")

def return_only_40(processes):
  result = []
  for p in processes:
    if p.client_location == client_location_40:
      result.append(p)
  
  return result

def test_40_mixed(num_alice_40, num_bob_40, alice_extra_location=None, bob_extra_location=None, options={}):
  alice_accountname = "otrtest3"
  bob_accountname = "otrtest1"
  protocol = "prpl-aim"
  
  alices = get_many_instances(client_location_40, alice_accountname, protocol, num_alice_40, "alice")
  bobs = get_many_instances(client_location_40, bob_accountname, protocol, num_bob_40, "bob")
  
  if alice_extra_location is not None:
    alices.append(otr_subprocess([alice_extra_location, alice_accountname, protocol, im_ip, im_port, "alice" + str(num_alice_40) + ".txt"], 0))
  
  if bob_extra_location is not None:
    bobs.append(otr_subprocess([bob_extra_location, bob_accountname, protocol, im_ip, im_port, "bob" + str(num_bob_40) + ".txt"], 0))
  
  the_test = otr_test_mixed(alices, bobs)
  
  options['otr_init_method'] = 'msg'
  options['allowed_msg_events'] = ["OTRL_MSGEVENT_RCVDMSG_FOR_OTHER_INSTANCE", "OTRL_MSGEVENT_LOG_HEARTBEAT_SENT", "OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD"]
  the_test.run_test(options)
  

def main(args):
  print('Testing 4.0 and other to 4.0')
  server = im_server(int(im_port))
  server.daemon = True
  server.start()
  
  options = {}
  options['alice_init_idx'] = 0
  options['alice_expected_encrypted_idx'] = [0, 0, 1, 1, 2, 2]
  options['bob_expected_encrypted_idx'] = [0, 0, 0, 1, 1, 1, 2]
  
  for location in client_locations:
    if location == client_location_40: continue
    print("Testing with extra Bob location: " + location)
    test_40_mixed(3, 2, None, location, options)
    time.sleep(1)
  
  
  options['alice_expected_encrypted_idx'] = [0, 1]
  options['bob_expected_encrypted_idx'] = [0, 0, 1, 1]
  
  for location in client_locations:
    if location == client_location_40: continue
    print("Testing with extra Alice location: " + location)
    test_40_mixed(2, 2, location, None, options)
    time.sleep(1)
  
  server.set_finished()
  print("Shutting down...")
  
if __name__ == "__main__":
  main(sys.argv)   
   
