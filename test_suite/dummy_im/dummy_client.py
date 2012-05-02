#!/usr/bin/python

import sys
import socket
import threading
from struct import *

class kb_thread(threading.Thread):
  def __init__(self, socket):
    threading.Thread.__init__(self)
    self.sock = socket

  def run(self):
    while True:
      msg = getline(sys.stdin)

      account_end = msg.find(' ')
      if account_end < 0: continue
      accountname = msg[:account_end]

      proto_end = msg[account_end+1:].find(' ') + account_end + 1
      if proto_end < 0: continue
      protocol = msg[account_end+1:proto_end]

      msg = msg[proto_end+1:]

      print("Sending msg -- account: " + accountname + " protocol: " + protocol + " msg: " + msg)

      send_msg(self.sock, accountname, protocol, msg)

def getline(stream, delimiter="\n"):
  def _gen():
    while 1:
      line = stream.readline()
      if delimiter in line:
        yield line[0:line.index(delimiter)]
        break
      else:
        yield line
  return "".join(_gen())

def send(sock, msg, length=0):
  if length == 0: length = len(msg)
  totalsent = 0
  while totalsent < length:
    sent = sock.send(msg[totalsent:])
    if sent == 0:
      return
    totalsent = totalsent + sent

def read_bytes(sock, num_bytes):
  msg = ''
  while len(msg) < num_bytes:
    chunk = sock.recv(num_bytes-len(msg))
    if chunk == '':
      return
    msg = msg + chunk
  return msg

def read_1b_val(sock):
  byte = read_bytes(sock, 1)
  if len(byte) == 1:
    return ord(byte)
  else: return

def read_4b_val(sock):
  bytes = read_bytes(sock, 4)
  if len(bytes) == 4:
    val = unpack('!I',bytes)
    return int(val[0])
  else: return

def recv_msg(sock):
  recv_acc_len = read_1b_val(sock)
  recv_acc = read_bytes(sock, recv_acc_len)
  recv_proto_len = read_1b_val(sock)
  recv_proto = read_bytes(sock, recv_proto_len)
  recv_msg_len = read_4b_val(sock)
  recv_msg = read_bytes(sock, recv_msg_len)
  print("Received msg: " + recv_msg)
  return recv_msg

def send_msg(sock, accountname, protocol, msg):
  new_msg = bytearray()
  new_msg.append(len(accountname))
  new_msg.extend(accountname)
  new_msg.append(len(protocol))
  new_msg.extend(protocol)
  for b in pack('!I', len(msg)):
    new_msg.append(ord(b))  
  new_msg.extend(msg)
  send(sock, new_msg)

def main(argv):
  if len(argv) < 3:
    print("Usage: " + argv[0] + " <accountname> <protocol>")
    return

  accountname = argv[1]
  protocol = argv[2]

  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect(("localhost", 1536))

  acc_len = len(accountname)
  packed_acc_len = pack('B', acc_len)

  #init
  send(s, packed_acc_len, 1)
  send(s, accountname)
  send(s, pack('B', len(protocol)), 1)
  send(s, protocol)

  input_handler = kb_thread(s)
  input_handler.start()

  while True:
    recv_msg(s)

if __name__ == "__main__":
  main(sys.argv)

