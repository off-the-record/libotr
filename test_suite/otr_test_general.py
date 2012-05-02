#!/usr/bin/python

import sys
import itertools
import re
import Queue

from otr_test import *

class otr_test_general(otr_test):
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
      time.sleep(1)
      print("Processes initialized")
      if options.get('otr_init_method', 'msg') == 'msg':
        self.otr_init_msg(options)
      elif options.get('otr_init_method', 'msg') == 'query':
        self.otr_init_query()
      print("About to wait for all to go encrypted")
      self.wait_all_gone_encrypted()
      print("All went encrypted")
      #self.analyze_otr_init(options) #hasn't been updated to support fragments
      time.sleep(5)
      self.check_all_contexts_encrypted(options)
      print("Verified encrypted contexts")
      self.send_encrypted_and_check(self.bobs, self.alices, self.msg2, options)
      print("Sent and verified encrypted message from bobs to alices")
      self.send_encrypted_and_check(self.alices, self.bobs, self.msg3, options)
      print("Sent and verified encrypted message from alices to bobs")
      self.check_error_all(options.get('allowed_msg_events', []))
      print("Test succeeded")
      self.reset_processes()

    except (subprocess_exception, otr_test_failed_exception) as e:
      print '***Exception: ', e, e.value, sys.exc_info()
      self.reset_processes()
      print("Test failed")

  def analyze_otr_init(self, options={}):
    alice_msgs = []
    bob_msgs = []
    
    for p in self.bobs:
      init_msg = p.querymap[q_raw_msg].get()
      
      if options.get('otr_init_method', 'msg') == 'msg':
        check_contains_message_matches_ex([init_msg], re.escape(self.msg1) + otr_tab_tag, 1, self.subprocesses)
      elif options.get('otr_init_method', 'msg') == 'query':
        check_contains_message_matches_ex([init_msg], re.escape(otr_query), 1, self.subprocesses)
      
      bob_msgs.append(get_n_messages_blocking(p.querymap[q_raw_auth_msg], self.num_alice*self.num_bob*2))
      
    for p in self.alices:  
      alice_msgs.append(get_n_messages_blocking(p.querymap[q_raw_auth_msg], self.num_bob + self.num_bob*self.num_alice))

    for msg in bob_msgs:
      check_contains_message_matches_ex(msg, otr_key_prefix_regex, self.num_alice*self.num_bob, self.subprocesses)
      check_contains_message_matches_ex(msg, otr_sign_prefix_regex, self.num_alice*self.num_bob, self.subprocesses)

    for msg in alice_msgs:
      check_contains_message_matches_ex(msg, otr_commit_prefix_regex, self.num_bob, self.subprocesses)
      check_contains_message_matches_ex(msg, otr_reveal_prefix_regex, self.num_bob*self.num_alice, self.subprocesses)

   
def test_all_vers_1_1():
  alice_accountname = "otrtest3"
  bob_accountname = "otrtest1"
  protocol = "prpl-aim"
  
  test_combos = []
  
  for loc1, loc2 in itertools.product(client_locations, repeat=2):
    test_combos.append((loc1, loc2))
  
  for i, (loc1, loc2) in enumerate(test_combos): #otr_subprocess([location, account, protocol, im_ip, im_port, log_tag+str(i)+".txt"], 0)
    alice = otr_subprocess([loc1, alice_accountname, protocol, im_ip, im_port, "alice"+str(i)+".txt"], 0)
    bob = otr_subprocess([loc2, bob_accountname, protocol, im_ip, im_port, "bob"+str(i)+".txt"], 0)
    
    print('Testing ' + loc1 + ' and ' + loc2)
    
    the_test = otr_test_general([alice], [bob])
    options={}
    options['otr_init_method'] = 'msg'
    the_test.run_test(options)
    time.sleep(1)
  
  print('Test complete!')

def test_basic_40():
  #tests single 4.0s
  alice_accountname = "otrtest3"
  bob_accountname = "otrtest1"
  protocol = "prpl-aim"
  
  alices = get_many_instances(client_location_40, alice_accountname, protocol, 1, "alice")
  bobs = get_many_instances(client_location_40, bob_accountname, protocol, 1, "bob")
  
  the_test = otr_test_general(alices, bobs)
  options={}
  options['otr_init_method'] = 'query'
  options['allowed_msg_events'] = ["OTRL_MSGEVENT_LOG_HEARTBEAT_SENT", "OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD"]
  the_test.run_test(options)
  
  print('Test complete!')
  

def test_multi_40():
  #tests multiple 4.0 versions
  alice_accountname = "otrtest3"
  bob_accountname = "otrtest1"
  protocol = "prpl-aim"
  
  alices = get_many_instances(client_location_40, alice_accountname, protocol, 3, "alice")
  bobs = get_many_instances(client_location_40, bob_accountname, protocol, 2, "bob")
  
  the_test = otr_test_general(alices, bobs)
  options={}
  options['otr_init_method'] = 'query'
  options['allowed_msg_events'] = ["OTRL_MSGEVENT_RCVDMSG_FOR_OTHER_INSTANCE", "OTRL_MSGEVENT_LOG_HEARTBEAT_SENT", "OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD"]
  the_test.run_test(options)
  
  print('Test complete!')
  

def main(args):
  server = im_server(int(im_port))
  server.daemon = True
  server.start()
  
  print('Testing basic 4.0 to 4.0')
  test_basic_40()
  
  print('Testing all versions 1 client to 1 client')
  test_all_vers_1_1()
  
  print('Testing multi 4.0 to multi 4.0')
  test_multi_40()
  
  server.set_finished()
  print("Shutting down...")
  
if __name__ == "__main__":
  main(sys.argv)   
   
