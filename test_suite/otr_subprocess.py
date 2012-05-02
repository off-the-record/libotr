#!/usr/bin/python

import re
import sys
import threading
import signal
import select
import time
import Queue
from subprocess import *
from struct import *

otr_tab_tag = " \t  \t\t\t\t \t \t \t  "

otr_query = "?OTR?"

otr_key_prefix_regex = ".*\\?OTR:...K"
otr_commit_prefix_regex = ".*\\?OTR:...C"
otr_sign_prefix_regex = ".*\\?OTR:...S"
otr_reveal_prefix_regex = ".*\\?OTR:...R"

otr_auth_regexs = [otr_key_prefix_regex, otr_commit_prefix_regex, otr_sign_prefix_regex, otr_reveal_prefix_regex]

otr_data_prefix_regex = ".*\\?OTR:...D"

im_ip = "127.0.0.1"
im_port = "1536"

q_raw_msg = 1       #The queue id for received messages that have not gone through OTR
q_otr_msg = 2       #The queue id for received messages that have passed through OTR
q_err = 3           #The queue id for error-type messages from OTR
q_gone_secure = 4   #The queue id for signal of contexts that have gone secure
q_raw_auth_msg = 5
q_raw_data_msg = 6

class otr_context:
  def __init__(self):
    self.protocol_version = None
    self.username = None
    self.accountname = None
    self.protocol = None
    self.offer_state = None
    self.msg_state = None
    self.auth_state = None
    self.our_instance = None
    self.their_instance = None

  def __init__(self, protocol_version, username, accountname, protocol, offer_state, msg_state, auth_state, our_instance, their_instance):
    self.protocol_version = protocol_version
    self.username = username
    self.accountname = accountname
    self.protocol = protocol
    self.offer_state = offer_state
    self.msg_state = msg_state
    self.auth_state = auth_state
    self.our_instance = our_instance
    self.their_instance = their_instance

  def __str__(self):
    return "Protocol version: " + str(self.protocol_version) + "\nUsername: " + str(self.username) + "\nAccount name: "+ \
           str(self.accountname) + "\nProtocol: " + str(self.protocol) + "\nOffer state: " + str(self.offer_state) + \
           "\nMsg state: " + str(self.msg_state) + "\nAuth state: " + str(self.auth_state) + "\nOur instance: " + \
           str(self.our_instance) + "\nTheir instance: " + str(self.their_instance)

class subprocess_exception(Exception):
  def __init__(self, value):
    self.value = value

  def __str__(self):
    return repr(self.value)

class otr_subprocess_read_thread(threading.Thread):
  def __init__(self, otr_subprocess):
    threading.Thread.__init__(self)
    self.subprocess = otr_subprocess
    
  def run(self):
    while True:
      recv_msg_id = read_4b_val(self.subprocess.stdout)
      recv_msg_len = read_4b_val(self.subprocess.stdout)
      recv_msg = self.subprocess.stdout.read(int(recv_msg_len))
      
      if recv_msg_id == q_raw_msg:
        msg = deserialize_msg(recv_msg)
        if re.match(otr_data_prefix_regex, msg[2]) != None:
          self.subprocess.write_query(q_raw_data_msg, recv_msg)
        else:
          for auth_regex in otr_auth_regexs:
            if re.match(auth_regex, msg[2]) != None:
              self.subprocess.write_query(q_raw_auth_msg, recv_msg)
              break
       
      
      #print("Msg len " + str(recv_msg_len) + " contents " + recv_msg)
      
      self.subprocess.write_query(recv_msg_id, recv_msg)

class otr_subprocess(Popen):
  def __init__(self, args, offset=0):
    #The test client takes parameters like accountname, and protocol, and will be found
    #in the args list. 'offset' points to the the location in the list just before the
    #accountname and protocol are listed (and should itself point to where the actual
    #client_location is) 
    
    self.client_location = args[offset]
    self.accountname = args[offset+1]
    self.protocol = args[offset+2]
    
    print(args)
    Popen.__init__(self, args, stdin=PIPE, stdout=PIPE, stderr=PIPE, close_fds=True, universal_newlines=True, bufsize=16384)
    
    self.querycount = 16 # Unique IDs for async queries to C
    self.querycount_lock = threading.Semaphore()
    
    self.querymap = {} # Query ID --> Queues
    self.querymap_lock = threading.Semaphore() # Locks the above map (intended to make the map operations safe, not the underlying queues)
    
    self.querymap[q_raw_msg] = Queue.Queue() # For incoming messages to this process. This data structure is synchronized
    self.querymap[q_otr_msg] = Queue.Queue() # For incoming messages that were process by OTR
    self.querymap[q_err] = Queue.Queue()     # For OTR error messages
    self.querymap[q_gone_secure] = Queue.Queue()
    self.querymap[q_raw_auth_msg] = Queue.Queue()
    self.querymap[q_raw_data_msg] = Queue.Queue()
    
    self.read_thread = otr_subprocess_read_thread(self)
    self.read_thread.daemon = True # Python will exit when only daemonic threads are left
    self.read_thread.start()
  
  def get_query_id(self):
    result = 0
    self.querycount_lock.acquire()
    result = self.querycount
    self.querycount += 1
    self.querycount_lock.release()
    return result

  def reset(self):
    while not self.querymap[q_raw_msg].empty():
      self.querymap[q_raw_msg].get(False)
    while not self.querymap[q_otr_msg].empty():
      self.querymap[q_otr_msg].get(False)
    while not self.querymap[q_err].empty():
      self.querymap[q_err].get(False)

  def write_query(self, id, contents):
    self.querymap_lock.acquire()
    
    queue = self.querymap.get(id)
    
    if queue is None:
      queue = Queue.Queue()
      self.querymap[id] = queue
    
    queue.put(contents)
    
    self.querymap_lock.release()

  def get_query_blocking(self, id):
    self.querymap_lock.acquire()
    
    result = None
    queue = self.querymap.get(id)
    
    if queue is None:
      queue = Queue.Queue()
      self.querymap[id] = queue
      
    self.querymap_lock.release()  
    result = queue.get()

    return result

  def check_error(self):
    inputready,outputready,exceptready = select.select([self.stderr],[],[], 0) #non-blocking poll 
    
    for s in inputready:
      raise subprocess_exception(s.readline())
    
    if self.poll():
      raise subprocess_exception('Subprocess terminated with return code: ' + str(self.returncode))

  def send_init(self):
    new_msg = bytearray()
    acc_len = len(self.accountname)
    proto_len = len(self.protocol)
    full_len = 1 + acc_len + 1 + proto_len

    cmd_type = 0 #cmd type 0 (init)
    
    for b in pack('!H', cmd_type):
      new_msg.append(ord(b))
      
    msg_id = self.get_query_id()
    for b in pack('!I', msg_id):
      new_msg.append(ord(b))
  
    for b in pack('!I', full_len):
      new_msg.append(ord(b))

    new_msg.append(acc_len)
    new_msg.extend(self.accountname)
  
    new_msg.append(proto_len)
    new_msg.extend(self.protocol)
  
    self.stdin.write(new_msg)
    self.stdin.flush()
    time.sleep(0.1)
    self.check_error()
    
    return msg_id
  
  def send_msg(self, dst_acc, dst_proto, msg):
    new_msg = bytearray()
    acc_len = len(dst_acc)
    proto_len = len(dst_proto)
    msg_len = len(msg)
    full_len = 1 + acc_len + 1 + proto_len + 4 + msg_len
  
    cmd_type = 1 #cmd type 1 (message)
    for b in pack('!H', cmd_type):
      new_msg.append(ord(b))

    msg_id = self.get_query_id()
    for b in pack('!I', msg_id):
      new_msg.append(ord(b))

    for b in pack('!I', full_len):
      new_msg.append(ord(b))

    new_msg.append(acc_len)
    new_msg.extend(dst_acc)
  
    new_msg.append(proto_len)
    new_msg.extend(dst_proto)
  
    for b in pack('!I', msg_len):
      new_msg.append(ord(b))
    new_msg.extend(msg)
  
    self.stdin.write(new_msg)
    self.stdin.flush()
    
    time.sleep(0.1)
    self.check_error()
    
    return msg_id

  def send_read_privkey(self, path):
    new_msg = bytearray()

    cmd_type = 2 #cmd type 2 (read privkey)
    
    for b in pack('!H', cmd_type):
      new_msg.append(ord(b))
    
    msg_id = self.get_query_id()
    for b in pack('!I', msg_id):
      new_msg.append(ord(b))
    
    full_len = len(path)

    for b in pack('!I', full_len):
      new_msg.append(ord(b))

    new_msg.extend(path)
    self.stdin.write(new_msg)
    self.stdin.flush()
    
    time.sleep(0.1)
    self.check_error()
    
    return msg_id

  def send_read_instag(self, path):
    new_msg = bytearray()

    cmd_type = 4 #cmd type 4 (read instag)
    
    for b in pack('!H', cmd_type):
      new_msg.append(ord(b))
    
    msg_id = self.get_query_id()
    for b in pack('!I', msg_id):
      new_msg.append(ord(b))
    
    full_len = len(path)

    for b in pack('!I', full_len):
      new_msg.append(ord(b))

    new_msg.extend(path)
    self.stdin.write(new_msg)
    self.stdin.flush()
    
    time.sleep(0.1)
    self.check_error()
    
    return msg_id


  def send_get_contexts(self):
    new_msg = bytearray()

    cmd_type = 3 #cmd type 3 (get contexts)
    
    for b in pack('!H', cmd_type):
      new_msg.append(ord(b))
    
    msg_id = self.get_query_id()
    for b in pack('!I', msg_id):
      new_msg.append(ord(b))
    
    full_len = 1

    for b in pack('!I', full_len):
      new_msg.append(ord(b))

    new_msg.append(ord('\0')) #We don't support zero len so this is dummy data
    self.stdin.write(new_msg)
    self.stdin.flush()
    
    time.sleep(0.1)
    self.check_error()
    
    return msg_id


  def sigint(self):
    self.send_signal(signal.SIGINT)

#TODO: convert following methods to class methods or static methods?

def deserialize_msg(raw_msg):
  i = 0
  
  account_len = (unpack('B', raw_msg[i:i+1]))[0]
  i += 1
  
  account = raw_msg[i:i+account_len]
  i += account_len
  
  protocol_len = (unpack('B', raw_msg[i:i+1]))[0]
  i += 1
  
  protocol = raw_msg[i:i+protocol_len]
  i += protocol_len
  
  msg_len = (unpack('!I',raw_msg[i:i+4]))[0]
  i += 4
  
  msg = raw_msg[i:i+msg_len]
  
  return [account, protocol, msg]

def deserialize_context(contexts, serialized_context):
  i = 0
  
  protocol_version = (unpack('!I',serialized_context[i:i+4]))[0]
  i += 4
  
  username_len = ord(serialized_context[i])
  i += 1
  
  username = serialized_context[i:i+username_len]
  i += username_len
  
  accountname_len = ord(serialized_context[i])
  i += 1
  
  accountname = serialized_context[i:i+accountname_len]
  i += accountname_len
  
  protocol_len = ord(serialized_context[i])
  i += 1
  
  protocol = serialized_context[i:i+protocol_len]
  i += protocol_len
  
  otr_offer = (unpack('!I',serialized_context[i:i+4]))[0]
  i += 4
  
  msg_state = (unpack('!I',serialized_context[i:i+4]))[0]
  i += 4
  
  auth_state = (unpack('!I',serialized_context[i:i+4]))[0]
  i += 4
  
  our_instance = (unpack('!I',serialized_context[i:i+4]))[0]
  i += 4
  
  their_instance = (unpack('!I',serialized_context[i:i+4]))[0]
  i += 4
  
  #if protocol_version < 3:
  #  our_instance = None
  #  their_instance = None
  
  context = otr_context(protocol_version, username, accountname, protocol, otr_offer, msg_state, auth_state, our_instance, their_instance)
  contexts.append(context)
  
  return serialized_context[i:]

def deserialize_contexts(serialized_contexts):
  num_contexts = (unpack('!I',serialized_contexts[0:4]))[0]
  
  serialized_contexts = serialized_contexts[4:]
  contexts = []
  
  for i in range(num_contexts):
    serialized_contexts = deserialize_context(contexts, serialized_contexts)
  
  return contexts  

def get_n_messages_blocking(queue, n):
  result = []
  
  for i in range(n):
    result.append(queue.get())
  
  return result

def read_bytes(stream, num_bytes):
  msg = ''
  while len(msg) < num_bytes:
    chunk = stream.read(num_bytes-len(msg))
    if chunk is None:
      return
    msg = msg + chunk
  return msg

def read_1b_val(stream):
  byte = read_bytes(stream, 1)
  
  if len(byte) == 1:
    return ord(byte)
  else:
    print("Read unexpected length: " + str(len(byte)))
    return

def read_4b_val(stream):
  bytes = read_bytes(stream, 4)
  if len(bytes) == 4:
    val = unpack('!I',bytes) #network byte order
    return int(val[0])
  else: 
    print("Read unexpected length: " + str(len(byte)))
    return

def dump_msg_queue(queue):
  while not queue.empty():
    item = queue.get(False)
    if item is not None:
      item = deserialize_msg(item)
    print('###############')
    print(item)
    print('###############')

def dump_queue(queue):
  while not queue.empty():
    item = queue.get(False)
    print('###############')
    print(str(item))
    print('###############')

def dump_contexts(contexts):
  for context in contexts:
    print('***************')
    print(str(context))
    print('***************')


def get_many_instances(location, account, protocol, num, log_tag):
  result = []
  for i in range(num):
    #result.append(otr_subprocess(['/usr/bin/valgrind', '--tool=memcheck', '--leak-check=yes', '--show-reachable=yes', '--num-callers=20', '--track-fds=yes', '--log-file=valgrind_log' + account + protocol + str(i) + '.txt',  location, account, protocol, im_ip, im_port, log_tag+str(i)+".txt"], 7))
    result.append(otr_subprocess([location, account, protocol, im_ip, im_port, log_tag+str(i)+".txt"], 0))

  return result

if __name__ == "__main__":
  main(sys.argv)
