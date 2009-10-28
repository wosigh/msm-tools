#!/usr/bin/python

import sys, os, serial, threading, string, serial, select

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


class ModemChannelDumper(object):
    def __init__(self):
        self.baudrate = 115200
        self.serial = None

    def open(self, path):
        self.serial = serial.Serial()
        self.serial.port = str(path)
        self.serial.baudrate = 115200
        self.serial.rtscts = True
        self.serial.xonxoff = False
        self.serial.bytesize = serial.EIGHTBITS
        self.serial.parity = serial.PARITY_NONE
        self.serial.stopbits = serial.STOPBITS_ONE
        self.serial.timeout = None

        try:
            self.serial.open()
        except serial.serialutil.SerialException:
            print "could not open serial port '%s'!" % self.path
            return False

        if not self.serial.isOpen():
            print "could not open serial port '%s'!" % self.path

        self.connected = self.serial.isOpen()
        return self.connected

    def run(self):
        self.thread = threading.Thread(target = self.reader)
        self.thread.setDaemon(True)
        self.thread.start()

        while True:
            continue

    def reader(self):
        while True:
            ret = select.select([self.serial.fd],[],[])
            if ret > 0:
                data = os.read(self.serial.fd, 4096)
                if not len(data):
                    continue
                print "read len=%i" % len(data)
                hexdump(data)
                print "\n"

if __name__ == "__main__":
    channel = ModemChannelDumper()
    channel.open("/dev/modemuart")
    channel.run()

