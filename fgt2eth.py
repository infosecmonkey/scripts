#!/usr/bin/env python3

"""
fgt2eth.py - FortiGate Sniffer to Wireshark Converter
Based on the original fgt2eth.pl Perl script.

Converts FortiGate verbose 3 sniffer output to a format readable by Wireshark/Ethereal.
Supports macOS, Linux, and Windows.
"""

import sys
import re
import os
import argparse
import subprocess
import time
import shutil
import platform
from datetime import datetime
import io

# Configuration
DEFAULT_YEAR = datetime.now().year

def get_platform_paths():
    """Finds wireshark and text2pcap binaries based on OS."""
    text2pcap_cmd = "text2pcap"
    wireshark_cmd = "wireshark"
    
    system = platform.system()
    
    # Common paths to search
    search_paths = []
    
    if system == "Darwin": # macOS
        search_paths = [
            "/Applications/Wireshark.app/Contents/MacOS",
            "/usr/local/bin",
            "/opt/homebrew/bin"
        ]
    elif system == "Windows":
        search_paths = [
            r"C:\Program Files\Wireshark",
            r"C:\Program Files (x86)\Wireshark"
        ]

    # Helper to find executable
    def find_exe(cmd):
        # Check PATH first
        if shutil.which(cmd):
            return cmd
            
        # Check specific paths
        for path in search_paths:
            full_path = os.path.join(path, cmd)
            if system == "Windows" and not full_path.lower().endswith(".exe"):
                full_path += ".exe"
            
            if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                return full_path
        return None

    t2p = find_exe("text2pcap")
    ws = find_exe("wireshark")

    return t2p, ws

class PacketProcessor:
    def __init__(self, infile, outfile, lines_limit=None, demux=False, debug=False, pipe_mode=False):
        self.infile = infile
        self.outfile = outfile
        self.lines_limit = lines_limit
        self.demux = demux
        self.debug = debug
        self.pipe_mode = pipe_mode
        
        self.packet_array = []
        self.eth0_count = 0
        self.skip_packet = False
        self.line_count = 0
        self.file_handlers = {} # For demux map: interface -> (filename, file_handle)
        self.temp_files = []

        # Regex patterns
        self.re_hex = re.compile(r'^(0x[0-9a-f]+[ \t\xa0]+)', re.IGNORECASE)
        self.re_timestamp_rel = re.compile(r'^([0-9]+)\.([0-9]+)\s')
        self.re_timestamp_abs = re.compile(r'^(\d+-\d+-\d+ \d+:\d+:\d+\.\d+)\s')
        self.re_interface = re.compile(r' (\S+) (?:out|in) ')
        self.re_truncated = re.compile(r'truncated-ip - [0-9]+ bytes missing!')

    def log(self, msg):
        if self.debug:
            sys.stderr.write(f"[DEBUG] {msg}\n")

    def get_output_handler(self, current_line):
        """Determines where to write the processed hex dump."""
        if not self.demux:
            # If piping to stdout (wireshark), use stdout
            if self.outfile == '-':
                return sys.stdout
            
            # Otherwise use the main temporary file
            if 'main' not in self.file_handlers:
                # If outfile is specified as 'capture.pcap', we write temp to 'capture.pcap.tmp'
                # If outfile is None (input file based), we use 'inputfile.pcap.tmp'
                base_name = self.infile if self.infile else "capture"
                if self.outfile and self.outfile != '-':
                    base_name = self.outfile
                
                # Strip extension if needed
                if base_name.lower().endswith('.pcap'):
                    base_name = base_name[:-5]
                elif base_name.lower().endswith('.zip'):
                    base_name = base_name[:-4]
                
                tmp_name = f"{base_name}.tmp"
                self.temp_files.append((tmp_name, f"{base_name}.pcap"))
                self.file_handlers['main'] = open(tmp_name, 'w')
            return self.file_handlers['main']

        # Demux logic
        match = self.re_interface.search(current_line)
        intf = match.group(1) if match else "[noIntf]"
        
        if intf not in self.file_handlers:
            base_name = self.infile if self.infile else "capture"
            if self.outfile and self.outfile != '-':
                base_name = self.outfile
            
            # Clean filename
            clean_intf = intf.replace('/', '-')
            tmp_name = f"{base_name}.{clean_intf}.tmp"
            final_name = f"{base_name}.{clean_intf}.pcap"
            
            self.temp_files.append((tmp_name, final_name))
            self.file_handlers[intf] = open(tmp_name, 'w')
            
        return self.file_handlers[intf]

    def convert_timestamp(self, line, fh):
        """Parses timestamp from line and writes text2pcap formatted time."""
        if self.re_truncated.search(line):
            return True # Keep packet

        # Relative timestamp: 123.456
        match_rel = self.re_timestamp_rel.match(line)
        if match_rel:
            secs = int(match_rel.group(1))
            usecs = match_rel.group(2)
            
            # Convert seconds to Days/Hours/Mins
            days = secs // 86400
            secs %= 86400
            hours = secs // 3600
            secs %= 3600
            mins = secs // 60
            secs %= 60
            
            # Format: DD/MM/YYYY HH:MM:SS.ms
            # Note: text2pcap requires specific format.
            formatted_date = f"01/{days+1:02d}/{DEFAULT_YEAR} {hours:02d}:{mins:02d}:{secs:02d}.{usecs}"
            fh.write(f"{formatted_date}\n")
            return False

        # Absolute timestamp: 2025-01-24 11:37:36.123
        match_abs = self.re_timestamp_abs.match(line)
        if match_abs:
            ts_str = match_abs.group(1)
            try:
                # FGT format: YYYY-MM-DD HH:MM:SS.ms
                parts = ts_str.split(' ')
                date_parts = parts[0].split('-') # Y M D
                new_date = f"{date_parts[2]}/{date_parts[1]}/{date_parts[0]}"
                fh.write(f"{new_date} {parts[1]}\n")
            except:
                fh.write(f"{ts_str}\n")
            return False
            
        return False

    def build_packet_array(self, line, file_obj):
        """Reads hex lines until empty line."""
        self.packet_array = []
        
        while line:
            # Clean the line
            line = line.strip()
            if not line:
                break
            
            # Check if it looks like hex data "0x0000"
            if not line.startswith("0x"):
                break
                
            # Remove 0x offset part (0x0000)
            parts = line.split(maxsplit=1)
            if len(parts) > 1:
                hex_part = parts[1]
                # Regex to find the hex bytes
                hex_bytes = re.findall(r'([0-9a-f]{2})', hex_part, re.IGNORECASE)
                # Limit to 16 bytes per line standard
                if len(hex_bytes) > 16:
                    hex_bytes = hex_bytes[:16]
                self.packet_array.extend(hex_bytes)
            
            # Read next line
            pos = file_obj.tell()
            line = file_obj.readline()
            if not line:
                break
            # If next line is a timestamp, we went too far
            if self.re_timestamp_rel.match(line) or self.re_timestamp_abs.match(line):
                file_obj.seek(pos)
                break
                
    def strip_bytes(self, start, count):
        """Removes 'count' bytes starting at index 'start'."""
        if start < len(self.packet_array):
            del self.packet_array[start:start+count]

    def adjust_packet(self):
        """Port of the Perl adjustPacket logic."""
        def get_bytes(start, length):
            if start + length <= len(self.packet_array):
                return "".join(self.packet_array[start:start+length])
            return ""

        # Logic 1: Remove bytes if bytes 14-15 are 0800 or 8893
        chk = get_bytes(14, 2)
        if chk == "0800" or chk == "8893":
            self.strip_bytes(12, 2)

        # Logic 2: Add Ethernet Header if raw IP (starts with 4500/4510)
        chk = get_bytes(0, 2)
        if chk.startswith("4500") or chk.startswith("4510"):
            prefix = ["00"] * 12 + ["08", "00"]
            self.packet_array = prefix + self.packet_array

        # Logic 3: Fix specific internal FGT types
        chk = get_bytes(12, 2)
        if chk == "8890" or chk == "8891":
            self.packet_array[12] = "08"
            self.packet_array[13] = "00"

    def write_packet(self, fh):
        """Writes the packet array to the file handle in text2pcap format."""
        offset = 0
        for i, byte in enumerate(self.packet_array):
            if i % 16 == 0:
                fh.write(f"{offset:06x} ")
            fh.write(f" {byte}")
            offset += 1
            if (i + 1) % 16 == 0:
                fh.write("\n")
        
        if len(self.packet_array) % 16 != 0:
            fh.write("\n")
            
        self.line_count += 1

    def run(self):
        """Main processing loop."""
        if self.infile:
            f = open(self.infile, 'r', errors='replace')
        else:
            f = sys.stdin

        try:
            current_fh = None
            
            while True:
                line = f.readline()
                if not line:
                    break

                if self.re_timestamp_rel.match(line) or self.re_timestamp_abs.match(line):
                    self.skip_packet = False
                    
                    # Demux check
                    if not self.demux and 'eth0' in line:
                        self.eth0_count += 1
                        self.skip_packet = True
                    
                    # Get file handler for this packet
                    current_fh = self.get_output_handler(line)
                    
                    # Process timestamp
                    should_skip = self.convert_timestamp(line, current_fh)
                    if should_skip:
                        self.skip_packet = True
                        
                elif self.re_hex.match(line) and not self.skip_packet:
                    # Found packet data
                    self.build_packet_array(line, f)
                    self.adjust_packet()
                    if current_fh:
                        self.write_packet(current_fh)
                        current_fh.flush() 
                    
                    if self.lines_limit and self.line_count >= self.lines_limit:
                        print("Reached max lines.")
                        break
        finally:
            if self.infile:
                f.close()
            # Close all temp output files
            for fh in self.file_handlers.values():
                if fh != sys.stdout:
                    fh.close()

        if self.eth0_count > 0:
            sys.stderr.write(f"** Skipped {self.eth0_count} packets captured on eth0\n")

        return self.temp_files

def main():
    parser = argparse.ArgumentParser(description="Convert FortiGate sniffer output to PCAP")
    parser.add_argument("-in", dest="infile", required=False, help="Input file (FGT verbose 3 text)")
    parser.add_argument("-out", dest="outfile", help="Output file (.pcap) or '-' for Wireshark pipe")
    # FIX: Added dest="lines_limit" to match the variable used in PacketProcessor
    parser.add_argument("-lines", type=int, dest="lines_limit", help="Stop after N lines")
    parser.add_argument("-demux", action="store_true", help="Create one pcap per interface")
    parser.add_argument("-debug", action="store_true", help="Enable debug output")
    
    args = parser.parse_args()

    if not args.infile:
        # Check if piping into stdin
        if not sys.stdin.isatty():
            args.infile = None # Use stdin
        else:
            parser.print_help()
            sys.exit(1)

    t2p_bin, ws_bin = get_platform_paths()
    if not t2p_bin:
        sys.stderr.write("Error: 'text2pcap' not found. Install Wireshark.\n")
        sys.exit(1)

    # If piping to wireshark
    pipe_mode = (args.outfile == '-')

    if pipe_mode and not ws_bin:
        sys.stderr.write("Error: 'wireshark' not found. Cannot pipe output.\n")
        sys.exit(1)

    processor = PacketProcessor(args.infile, args.outfile, args.lines_limit, args.demux, args.debug, pipe_mode)

    if pipe_mode:
        t2p_cmd = [t2p_bin, "-q", "-t", "%d/%m/%Y %H:%M:%S.", "-", "-"]
        ws_cmd = [ws_bin, "-k", "-i", "-"]

        if args.debug:
            print(f"Executing: {' '.join(t2p_cmd)} | {' '.join(ws_cmd)}")

        try:
            p_ws = subprocess.Popen(ws_cmd, stdin=subprocess.PIPE)
            p_t2p = subprocess.Popen(t2p_cmd, stdin=subprocess.PIPE, stdout=p_ws.stdin)
            
            if args.demux:
                sys.stderr.write("Warning: demux ignored in pipe mode.\n")
            
            # We force the processor to write to the pipe
            processor.demux = False 
            
            # Python 3 Popen stdin expects bytes. TextIOWrapper can wrap it.
            text_wrapper = io.TextIOWrapper(p_t2p.stdin, encoding='utf-8', line_buffering=True)
            processor.file_handlers['main'] = text_wrapper
            
            processor.run()
            
            text_wrapper.close()
            p_t2p.wait()
            p_ws.wait()

        except KeyboardInterrupt:
            pass
        except BrokenPipeError:
            pass
    else:
        # File based mode
        temp_files = processor.run()
        
        # Convert all temp files to pcap
        for tmp_file, final_file in temp_files:
            if args.debug:
                print(f"Converting {tmp_file} to {final_file}...")
            
            cmd = [t2p_bin, "-q", "-t", "%d/%m/%Y %H:%M:%S.", tmp_file, final_file]
            subprocess.call(cmd)
            
            if os.path.exists(tmp_file):
                os.remove(tmp_file)
            
            if args.debug:
                print(f"Created {final_file}")

if __name__ == "__main__":
    main()