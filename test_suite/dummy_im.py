#!/usr/bin/python

import time
import sys
import threading
import socket
from struct import *


class client_context():
  def __init__(self, accountname, protocol, client_thread):
    self.accountname = accountname
    self.protocol = protocol
    self.thread = client_thread

class client_thread(threading.Thread):
  def __init__(self, server, socket, debug=False):
    threading.Thread.__init__(self)
    self.server = server
    self.sock = socket
    self.done = False
    self.done_sem = threading.Semaphore()
    self.send_sem = threading.Semaphore()
    self.ctx = None
    self.debug = debug

  def run(self):
    #Registration: 1 byte accountname len, accountname, 1 byte protocol len, protocol
    accountname_len = self.read_1b_val()
    accountname = self.read_bytes(accountname_len)
    
    protocol_len = self.read_1b_val()
    protocol = self.read_bytes(protocol_len)

    if self.debug:
      print('Client accountname: ' + accountname + ' protocol: ' + protocol)

    #create client_context and add to table
    self.ctx = client_context(accountname, protocol, self)
    self.server.add_client(self.ctx)

    while not self.check_client_done():
      try:         #Message: 1 byte accountname len, accountname, 1 byte protocol len, protocol, 4 byte msg len, msg
        accountname_len = self.read_1b_val()
        accountname = self.read_bytes(accountname_len)
      
        protocol_len = self.read_1b_val()
        protocol = self.read_bytes(protocol_len)
      
        msg_len = self.read_4b_val()
        msg = self.read_bytes(msg_len)
      
        if not self.check_client_done():
          self.server.deliver_msg(self.ctx.accountname, self.ctx.protocol, accountname, protocol, msg)

      except:
        if self.debug:
          print('removing client due to error')
        break

    self.server.remove_client(self.ctx)
    self.sock.close()

  def send_msg(self, msg):
    self.send_sem.acquire()
    totalsent = 0
    while not self.check_client_done() and totalsent < len(msg):
      sent = self.sock.send(msg[totalsent:])
      if sent == 0:
        self.set_client_done()
      totalsent = totalsent + sent
    self.send_sem.release()
    if self.debug:
      print 'sent: ', totalsent

  def set_client_done(self):
    self.done_sem.acquire()
    self.done = True
    self.done_sem.release()
    if self.ctx is not None:
      if self.debug:
        print('Client accountname: ' + self.ctx.accountname + ' protocol: ' + self.ctx.protocol + ' is marked as done')
    else: 
      if self.debug:
        print('Uninitialized client disconnected')

  def check_client_done(self):
    done_val = False
    self.done_sem.acquire()
    done_val = self.done
    self.done_sem.release()
    return done_val

  def read_bytes(self, num_bytes):
    msg = ''
    while not self.check_client_done() and len(msg) < num_bytes:
      chunk = self.sock.recv(num_bytes-len(msg))
      if chunk == '':
        self.set_client_done()
        break
      msg = msg + chunk
    return msg

  def read_1b_val(self):
    byte = self.read_bytes(1)
    if len(byte) == 1:
      return ord(byte)
    else: return

  def read_4b_val(self):
    bytes = self.read_bytes(4)
    if len(bytes) == 4:
      val = unpack('!I',bytes)
      return int(val[0])
    else: return


class im_server(threading.Thread):
  def __init__(self, port, debug=False):
    threading.Thread.__init__(self)
    self.port = port
    self.finished = False
    self.clients_sem = threading.Semaphore()
    self.clients = dict()
    self.debug=debug

  def run(self):
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind(('', self.port))
    serversocket.listen(50)
    
    if self.debug:
      print('Server listening...')

    while not self.finished:
      (clientsocket, address) = serversocket.accept()
      if self.debug:
        print('Client connected: ' + str(address))
      cl_thread = client_thread(self, clientsocket, self.debug)
      cl_thread.daemon = True
      cl_thread.start()
    
    serversocket.close()

  def set_finished(self):
    self.finished = True

  def add_client(self, ctx):
    self.clients_sem.acquire()

    if self.debug:
      print('Adding client to dict: ' + str(ctx))
    entry_list = self.clients.get((ctx.accountname, ctx.protocol))
    if entry_list is None:
      entry_list = [ctx]
      self.clients[(ctx.accountname, ctx.protocol)] = entry_list
    else: 
      entry_list.append(ctx)

    self.clients_sem.release()

  def remove_client(self, ctx):
    self.clients_sem.acquire()

    if self.debug:
      print('Removing client from dict: ' + str(ctx))
    entry_list = self.clients.get((ctx.accountname, ctx.protocol))
    if entry_list is not None and entry_list.count(ctx) > 0:
      entry_list.remove(ctx)
      if len(entry_list) == 0:
        del self.clients[(ctx.accountname, ctx.protocol)]

    self.clients_sem.release()

  def deliver_msg(self, src_accountname, src_protocol, dst_accountname, dst_protocol, msg):
    self.clients_sem.acquire()
    new_msg = bytearray()
    new_msg.append(len(src_accountname))
    new_msg.extend(src_accountname)
    new_msg.append(len(src_protocol))
    new_msg.extend(src_protocol)

    for b in pack('!I', len(msg)):
      new_msg.append(ord(b))

    new_msg.extend(msg)
  
    entry_list = self.clients.get((dst_accountname, dst_protocol))
    if entry_list is not None:
      for c in entry_list:
        if self.debug:
          print('Delivering msg from accountname: ' + src_accountname + 
            ' protocol: ' + src_protocol + ' to accountname: ' + dst_accountname + 
            ' protocol: ' + dst_protocol)
        c.thread.send_msg(new_msg)

    self.clients_sem.release()

def main(argv):
  port = 1536
  
  if len(argv) > 0:
    port = int(argv[1])

  server = im_server(port, debug=True)
  #server.daemon = True
  server.start()

if __name__ == "__main__":
  main(sys.argv)

