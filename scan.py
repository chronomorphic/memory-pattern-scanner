import psutil
import ctypes
import re

# Windows API constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04

# Windows API structures and functions
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]

# Open the process to read memory
def open_process(pid):
    kernel32 = ctypes.windll.kernel32
    process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not process:
        raise Exception("Could not open process: %d" % pid)
    return process

# Read memory of the process
def read_memory(process, address, size):
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()
    if ctypes.windll.kernel32.ReadProcessMemory(process, ctypes.c_void_p(address), buffer, size, ctypes.byref(bytes_read)):
        return buffer.raw
    return None

# Find the pattern in memory and print memory contents at found addresses
def find_pattern_in_memory(pid, pattern_bytes, bytes_to_read=32):
    process = open_process(pid)
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()

    while ctypes.windll.kernel32.VirtualQueryEx(process, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        if mbi.State == MEM_COMMIT and mbi.Protect == PAGE_READWRITE:
            memory = read_memory(process, address, mbi.RegionSize)
            if memory:
                offset = memory.find(pattern_bytes)
                while offset != -1:
                    found_address = address + offset
                    print(f"Pattern found at address: {hex(found_address)}")

                    # Read and print memory content at found address
                    memory_content = read_memory(process, found_address, bytes_to_read)
                    if memory_content:
                        print(f"Memory content at {hex(found_address)}: {memory_content.hex()}")
                    
                    # Search for more occurrences in the same region
                    offset = memory.find(pattern_bytes, offset + 1)

        address += mbi.RegionSize
    ctypes.windll.kernel32.CloseHandle(process)

# Convert pattern string (e.g., '\x48\x8B\xC4\x48\x89\x58\x08') to bytes
def convert_pattern(pattern_str):
    # Remove the '\x' and split into byte pairs
    pattern = re.findall(r'\\x([0-9A-Fa-f]{2})', pattern_str)
    return bytes([int(byte, 16) for byte in pattern])

# List running processes
def list_processes():
    for proc in psutil.process_iter(['pid', 'name']):
        print(f"PID: {proc.info['pid']} | Name: {proc.info['name']}")

if __name__ == "__main__":
    list_processes()
    pid = int(input("Enter the PID of the process: "))
    pattern_str = input("Enter the pattern to search (e.g., '\\x48\\x8B\\xC4\\x48\\x89\\x58\\x08'): ")
    pattern = convert_pattern(pattern_str)
    
    # You can specify how many bytes you want to read at the found address (default is 32)
    bytes_to_read = int(input("Enter number of bytes to read at the found address (e.g., 32): ") or 32)
    
    find_pattern_in_memory(pid, pattern, bytes_to_read)
