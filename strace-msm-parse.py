#!/usr/bin/python

import re, string, sys

patterns = {
  'dion': {
    'line': r"^(\[pid\s+[0-9]+\])?\s+([0-9.]+)\s+(.+?)\s*$",
    },
  'daniel': {
    'line': r"^([0-9]+)\s+([0-9.]+)\s+(.+)$",
    'func': r"^(\w+)\((.*)\)\s*=\s*(.+)$",
    'sig': r"^---\s+(.*?)\s+---$",
    },
  'stefan': {
    'line': r"^([0-9]+)\s+(.+)$",
    'func': r"^(\w+)\((.*)\)\s*=\s*([-\w]+)\s*(.*)$",
    'func-unfinished': r"^(\w+)\((.*)\s* <unfinished \.\.\.>$",
    'func-resumed': r"^<\.\.\. (\w+) resumed> (.*)\)\s*=\s*([-\w]+)\s*(.*)$",
    'sig': r"^---\s+(.*?)\s+---$",
    },
  }

p = patterns['stefan']

def debug_on(*text):
  for x in text:
    print x,
  print

def debug_off(*text):
  pass

debug = debug_off

hextable = ''
for i in range(256):
  if chr(i) in string.whitespace:
    hextable += '.'
  elif chr(i) in string.printable:
    hextable += chr(i)
  else:
    hextable += '.'

def hexdump( chars, width=16 ):
  while chars:
    line = chars[0:width]
    chars = chars[width:]
    filler = width - len(line)
    print "%s%s%s" % ( ' '.join( map( lambda c: "%02x" % ord(c), line ) + ['  ']*filler),
                       '   ', line.translate(hextable) + ' '*filler)

PIDs = {}

class PID(object):
  def __init__(self, FDs=None):
    self.funcs = {
      'open': self._open,
      'write': self._write,
      'read': self._read,
      'close': self._close,
      'clone': self._clone,
      }
    self.FHs_closed = []
    if FDs:
      self.FHs = FDs
    else:
      self.FHs = {}
    self.unfinished = None
  def elapse(self, time):
    pass
  def handle(self, data):
    mo = re.match(p['func'], data)
    if mo:
      debug('FUNC:', mo.groups())
      name, params, result, rest = mo.groups()
      if name in pid.funcs:
        pid.funcs[name](params, result)
      return
    mo = re.match(p['func-unfinished'], data)
    if mo:
      debug('FUNC-UNFINISHED:', mo.groups())
      name, params = mo.groups()
      self.unfinished = (name, params)
      return
    mo = re.match(p['func-resumed'], data)
    if mo:
      debug('FUNC-RESUMED:', mo.groups(), self.unfinished)
      name1, params1 = self.unfinished
      self.unfinished = None
      name2, params2, result, rest = mo.groups()
      assert name1 == name2
      name = name1
      params = params1 + params2
      if name in pid.funcs:
        pid.funcs[name](params, result)
      return
    mo = re.match(p['sig'], data)
    if mo:
      debug('SIG:', mo.groups())
      return
    debug('FIXME:', data)
  def _clone(self, params, result):
    if 'CLONE_FILES' in params:
      PIDs[int(result)] = PID(FDs=self.FHs)
  def _open(self, params, result):
    if int(result) < 0:
      debug( "OPEN: ERROR" )
      return
    mo = re.match(r"\"(.*?)(?<!\\)\", ([[\w|_]+)", params)
    debug( mo.groups() )
    filename, flags = mo.groups()
    filename = eval("str('%s')" % filename)
    assert not int(result) in self.FHs
    self.FHs[int(result)] = FH(id=int(result), filename=filename)
    debug( "OPEN:", repr(filename), flags, result )
  def _close(self, params, result):
    (fd,) = eval('('+params+',)')
    if fd not in self.FHs:
      debug( "CLOSE: unkown fd %i" % fd )
      return
    filename = self.FHs[fd].filename
    self.FHs_closed.append(self.FHs[fd])
    del self.FHs[fd]
    debug( "CLOSE:", fd, repr(filename), result )
  def _write(self, params, result):
    mo = re.match(r"([0-9]+), \"(.*?)(?<!\\)\", ([0-9]+)", params)
    debug( mo.groups() )
    fh, data, length = mo.groups()
    fh = int(fh)
    data = eval("str('%s')" % data)
    length = int(length)
    fh = self.FHs.setdefault(fh, FH(id=fh))
    debug( "WRITE:", fh, repr(data), length )
    fh.write(data)
  def _read(self, params, result):
    if int(result) < 0:
      debug( "READ: ERROR" )
      return
    mo = re.match(r"([0-9]+), \"(.*?)(?<!\\)\", ([0-9]+)", params)
    debug( mo.groups() )
    fh, data, length = mo.groups()
    fh = int(fh)
    data = eval("str('%s')" % data)
    length = int(length)
    fh = self.FHs.setdefault(fh, FH(id=fh))
    debug( "READ:", fh, repr(data), length )
    fh.read(data)

class FHBase(object):
  def __init__(self, id=None, filename=None):
    self.id = id
    self.filename = filename
    debug( "NEW FH:", self )
  def __repr__(self):
    return "<file handle %s for %s>" % (self.id, repr(self.filename))
  def read(self, data):
    pass
  def write(self, data):
    pass

class FHLogger(FHBase):
  def __init__(self, id=None, filename=None):
    FHBase.__init__(self, id, filename)
    if filename == '/dev/modemuart':
      self.packets_r = Packetizer()
      self.packets_w = Packetizer()
    else:
      self.packets_r = None
      self.packets_w = None
  def read(self, data):
    packet = None
    if self.packets_w:
      packet = self.packets_r.feed( data )
    #print "RAW: dir=r fd=%i fn='%s' len=%i/0x%x" % (self.id, self.filename, len(data), len(data))
    #hexdump(data)
    if packet:
      print "PACKET: dir=w fd=%i fn='%s' len=%i/0x%x" % (self.id, self.filename, len(packet), len(packet))
      hexdump(packet)
  def write(self, data):
    packet = None
    if self.packets_w:
      packet = self.packets_w.feed( data )
    #print "RAW: dir=w fd=%i fn='%s' len=%i/0x%x" % (self.id, self.filename, len(data), len(data))
    #hexdump(data)
    if packet:
      print "PACKET: dir=w fd=%i fn='%s' len=%i/0x%x" % (self.id, self.filename, len(packet), len(packet))
      hexdump(packet)
  def dump(self):
    datas = []
    for x in self.log:
      dir, data = x
      datas.append(data)
      print "dir=%s fd=%i fn='%s' len=%i/0x%x" % (dir, self.id, self.filename, len(data), len(data))
      hexdump(data)
    datas.sort()
    for data in datas:
      print "fd=%i fn='%s' len=%i/0x%x" % (self.id, self.filename, len(data), len(data))
      hexdump(data)

FH = FHLogger

def crc16fcs(s):
    crcValue=0xffff

    crc16tab_fcs = (
   0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
   0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
   0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
   0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
   0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
   0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
   0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
   0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
   0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
   0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
   0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
   0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
   0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
   0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
   0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
   0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
   0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
   0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
   0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
   0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
   0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
   0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
   0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
   0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
   0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
   0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
   0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
   0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
   0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
   0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
   0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
   0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
)
    for ch in s:
        tmp=crcValue^(ord(ch))
        crcValue=(crcValue>> 8)^crc16tab_fcs[(tmp & 0xff)]
    return crcValue

class Packetizer(object):
  def __init__(self):
    self.input = ''
    self.output = []
  def feed(self, data):
    crcResult=0xf0b8
    self.input += data
    end = self.input.find('\x7e')
    if end >= 0:
      packet = self.input[:end+1]
      if crcResult == crc16fcs(packet[:-1]):
        print "CRC OK"
      else:
        print "CRC bad"
      packet = packet.replace('\x7d\x5d', '\x7d')
      packet = packet.replace('\x7d\x5e', '\x7e')
      self.input = self.input[end+1:]
      self.output.append(packet)
      return packet

for line in file(sys.argv[1]):
  line = line.rstrip('\n')
  if not line or line[0] == ' ':
    continue
  debug( line )
  pid, rest = line.split(None, 1)
  pid = PIDs.setdefault(int(pid), PID())
  pid.handle(rest)

#for pid in PIDs.values():
#  for fh in pid.FHs_closed:
#    fh.dump()
#  for fh in pid.FHs.values():
#    fh.dump()

