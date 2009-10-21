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

def crc16a(s):
    crcValue=0x0000
    crc16tab = (0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280,
0xC241, 0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481,
0x0440, 0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81,
0x0E40, 0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880,
0xC841, 0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81,
0x1A40, 0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80,
0xDC41, 0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680,
0xD641, 0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081,
0x1040, 0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281,
0x3240, 0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480,
0xF441, 0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80,
0xFE41, 0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881,
0x3840, 0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80,
0xEA41, 0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81,
0x2C40, 0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681,
0x2640, 0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080,
0xE041, 0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281,
0x6240, 0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480,
0xA441, 0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80,
0xAE41, 0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881,
0x6840, 0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80,
0xBA41, 0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81,
0x7C40, 0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681,
0x7640, 0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080,
0xB041, 0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280,
0x9241, 0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481,
0x5440, 0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81,
0x5E40, 0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880,
0x9841, 0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81,
0x4A40, 0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80,
0x8C41, 0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680,
0x8641, 0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081,
0x4040)
    for ch in s:
        tmp=crcValue^(ord(ch))
        crcValue=(crcValue>> 8)^crc16tab[(tmp & 0xff)]
    return crcValue

MASK_CCITT  = 0x1021     # CRC-CCITT mask (ISO 3309, used in X25, HDLC)
MASK_CRC16  = 0xA001     # CRC16 mask (used in ARC files)

def crc16(crc, data, mask=MASK_CRC16):
    # data_length = len(data)
    # unpackFormat = '%db' % data_length
    # unpackedData = struct.unpack(unpackFormat, data)
    for char in data:
        c = ord(char)
        c = c << 8

        for j in xrange(8):
            if (crc ^ c) & 0x8000:
                crc = (crc << 1) ^ mask
            else:
                crc = crc << 1
            c = c << 1

    return crc & 0xffff

def crc16b(data):
    crc = 0xFFFF
    for char in data:
        c = ord(char)
        crc ^= c;

        for j in xrange(8):
            if (crc & 1):
                crc = (crc >> 1) ^ MASK_CRC16
            else:
                crc = crc >> 1

    return crc & 0xffff

class Packetizer(object):
  def __init__(self):
    self.input = ''
    self.output = []
  def feed(self, data):
    self.input += data
    end = self.input.find('\x7e')
    if end >= 0:
      packet = self.input[:end+1]
      print hex(crc16(0xFFFF, packet[1:-1], mask=MASK_CCITT))
      print hex(crc16(0xFFFF, packet[1:-1], mask=MASK_CRC16))
      print hex(crc16a(packet[1:-3]))
      print hex(crc16b(packet[1:-3]))
      packet = packet.replace('\x7d\x5d', '\x7d')
      packet = packet.replace('\x7d\x5e', '\x7e')
      #print hex(crc16(0, packet, mask=MASK_CCITT))
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

