##############################################################################################
# Copyright 2017 The Johns Hopkins University Applied Physics Laboratory LLC
# All rights reserved.
# Permission is hereby granted, free of charge, to any person obtaining a copy of this 
# software and associated documentation files (the "Software"), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, 
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to 
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
# PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE 
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE 
# OR OTHER DEALINGS IN THE SOFTWARE.
#
# 2020-08-07 - modified to work on IDA 7.x - Alexander Pick (contact@alexander-pick.com)
# 2025-11-03 - modified to work on IDA 9.x, extended - Alexander Pick (contact@alexander-pick.com)

import ida_kernwin
import ida_ida
import ida_bytes
import ida_nalt
import idc
import ida_auto

def make_strings():

    # Ask for parameters interactively
    start_addr = ida_kernwin.ask_addr(
        ida_ida.inf_get_min_ea(),
        "Please enter the starting address for the data to be analyzed."
    )
    end_addr = ida_kernwin.ask_addr(
        ida_ida.inf_get_max_ea(),
        "Please enter the ending address for the data to be analyzed."
    )

    if (
        start_addr is None or end_addr is None
        or start_addr == idc.BADADDR or end_addr == idc.BADADDR
        or start_addr >= end_addr
    ):
        print("[make_strings.py] QUITTING. Entered address values not valid.")
        return

    min_length = ida_kernwin.ask_long(5, "Enter minimum string length:")
    
    if min_length is None or min_length < 1:
        min_length = 5

    print(f"[make_strings.py] STARTING. Scanning range 0x{start_addr:x} - 0x{end_addr:x}, min length {min_length}")

    # Initialize
    num_strings = 0
    total_size = end_addr - start_addr
    current = start_addr
    last_progress_update = start_addr

    ida_kernwin.show_wait_box("Making strings...")

    try:
        while current < end_addr:
            # Throttle progress updates every 0x2000 bytes
            if current - last_progress_update >= 0x2000:
                percent = (current - start_addr) * 100 // total_size
                ida_kernwin.replace_wait_box(f"Processing: 0x{current:x} ({percent}%)")
                last_progress_update = current

            # Try ASCII first
            ascii_len = _detect_ascii_length(current, end_addr)
            unicode_len = _detect_unicode_length(current, end_addr)

            # Determine if either qualifies as a string
            if ascii_len >= min_length or unicode_len >= min_length:
                if unicode_len > ascii_len:
                    str_type = ida_nalt.STRTYPE_C_16
                    str_len = unicode_len * 2  # bytes
                else:
                    str_type = ida_nalt.STRTYPE_TERMCHR
                    str_len = ascii_len

                # Undefine any code or data at this location
                ida_bytes.del_items(current, str_len, ida_bytes.DELIT_SIMPLE)
                ida_auto.auto_wait()  # wait for analysis sync

                # Create the string literal
                if ida_bytes.create_strlit(current, str_len, str_type) == 1:
                    end_str = current + str_len
                    print(f"[make_strings.py] String created at 0x{current:x} - 0x{end_str:x} "
                          f"({'Unicode' if str_type == ida_nalt.STRTYPE_C_16 else 'ASCII'})")
                    num_strings += 1
                    current = end_str
                    continue  # Skip ahead past this string

            # Move to next byte and continue scanning
            current += 1

    finally:
        ida_kernwin.hide_wait_box()

    print(f"[make_strings.py] FINISHED. Created {num_strings} strings in range 0x{start_addr:x} - 0x{end_addr:x}")


def _detect_ascii_length(addr, end_addr):

    curr = addr
    count = 0
    
    while curr < end_addr:
        b = idc.get_wide_byte(curr)
        if (0x1F < b < 0x7F) or (b in (0x09, 0x0A, 0x0D)):  # printable ASCII or whitespace
            count += 1
            curr += 1
        elif b == 0x00 and count > 0:  # null terminator
            return count
        else:
            break
    return 0


def _detect_unicode_length(addr, end_addr):

    curr = addr
    count = 0
    
    while curr + 1 < end_addr:
        lo = idc.get_wide_byte(curr)
        hi = idc.get_wide_byte(curr + 1)
        if lo == 0x00 and hi == 0x00 and count > 0:  # null terminator
            return count
        char_code = lo | (hi << 8)
        if 0x20 <= char_code <= 0x7E or char_code in (0x09, 0x0A, 0x0D):
            count += 1
            curr += 2
        else:
            break
    return 0


if __name__ == "__main__":
    make_strings()
