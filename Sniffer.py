import socket
import struct
import binascii

host = "192.168.0.16"
print('IP: {}'.format(host))

buf = 65565

s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)

s.bind((host,0))
s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
while True:
       packet = s.recvfrom(buf)
       dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', packet[0][:14])
       bytes_str = map("{:02x}".format, dest_mac)
       print(bytes_str)
       #print('{} {}'.format(binascii.hexlify(hdr[0]), binascii.hexlify(hdr[1])))