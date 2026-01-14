#!/usr/bin/env python3


# Copyright 2014 Matthijs Kooijman <matthijs@stdin.nl>
# Copyright 2024-2025 Stephan Enderlein (modified/improved/extended)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# This script is intended to read raw packets (currently only 802.15.4
# packets prefixed by a length byte) from a serial port and output them
# in pcap format.

import os
import subprocess
import sys
import time
import errno
import serial
import struct
import select
import binascii
import datetime
import argparse

version = "2.1"
# This script reads packets from a serial port and writes them to a pcap file or fifo.
# It can be used to capture packets from devices that communicate over serial, such as
# 802.15.4 devices, modbus devices, etc.
# The script can also print the packets in a human-readable format to stdout.

WIRESHARK_FIFO = "/tmp/wireshark"

def start_wireshark(file_path):
    try:
        subprocess.Popen(
            ["wireshark", "-k", "-i", file_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print(f"Started Wireshark on fifo {file_path}")
    except FileNotFoundError:
        print("Error: wireshark not found in PATH")
    except Exception as e:
        print(f"Failed to start Wireshark: {e}")

class Formatter:
    def __init__(self, out):
        self.out = out

    def fileno(self):
        return self.out.fileno()

    def close(self):
        self.out.close()

class PcapFormatter(Formatter):
    def write_header(self):
        self.out.write(struct.pack("=IHHiIII",
            0xa1b2c3d4,   # magic number
            2,            # major version number
            4,            # minor version number
            0,            # GMT to local correction
            0,            # accuracy of timestamps
            1024,         # max length of captured packets, in octets
            # https://www.tcpdump.org/linktypes.html
            # https://www.geeksforgeeks.org/user-dlts-protocol-table-in-wireshark/
            147,   # data link type (DLT) user specific
        ))
        self.out.flush()

    def write_packet(self, data):
        now = datetime.datetime.now()
        timestamp = int(time.mktime(now.timetuple()))

        # pcap packet record
        self.out.write(struct.pack("=IIII",
            timestamp,        # timestamp seconds
            now.microsecond,  # timestamp microseconds
            len(data),     # number of bytes of packet
            len(data),     # actual length of packet
        ))

        # write payload
        #sl=slice(len(data))
        # print("write: {}".format(binascii.hexlify(data).decode()))
        self.out.write(data)
        self.out.flush()

# prints data in human readable format on console
class HumanFormatter(Formatter):
    # print no header
    def write_header(self):
        pass

    def write_packet(self, data):
        self.out.write(binascii.hexlify(data).decode())
        self.out.write("\n")
        self.out.flush()

def open_fifo(options, name):
    try:
        os.mkfifo(name)
    except FileExistsError:
        pass
    except:
        raise

    if not options.quiet:
        print("Waiting for fifo to be opened...")
    # This blocks until the other side of the fifo is opened
    ret = open(name, 'wb')
    print("Fifo connected")
    return ret

def setup_output(options):
    if options.fifo:
        print("Write to fifo: {}".format(options.fifo))
        return PcapFormatter(open_fifo(options, options.fifo))
    elif options.write_file:
        print("Write to file: {}".format(options.write_file))
        return PcapFormatter(open(options.write_file, 'wb'))
    else:
        print("Write to stdout")
        return HumanFormatter(sys.stdout)

def main():
    parser = argparse.ArgumentParser(description='converts packets read from a serial port into pcap format')
    parser.add_argument('port',
                        help='The serial port to read from')
    parser.add_argument('-b', '--baudrate', default=19200, type=int,
                        help='The baudrate to use for the serial port (defaults to %(default)s)')

    parser.add_argument(
        '--bytesize',
        choices=[5, 6, 7, 8],
        default=8,
        type=int,
        help='Data bits (default: %(default)s)'
    )

    parser.add_argument(
        '--parity',
        choices=['N', 'E', 'O', 'M', 'S'],
        default='E',
        help='Parity: N,E,O,M,S (default: %(default)s)'
    )

    parser.add_argument(
        '--stopbits',
        choices=[1, 1.5, 2],
        default=1,
        type=float,
        help='Stop bits (default: %(default)s)'
    )

    parser.add_argument(
        '-t', '--timeout',
        default=0.01,
        type=float,
        help='Read timeout in seconds (default: %(default)s)'
    )

    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Do not output any informational messages')
    parser.add_argument(
        '-ws', '--wireshark',
        action='store_true',
        help='Auto-start Wireshark using argument from --fifo or default "/tmp/wireshark"'
    )
    output = parser.add_mutually_exclusive_group()
    output.add_argument('-F', '--fifo',
                        help='Write output to a fifo instead of stdout. The fifo is created if needed and capturing does not start until the other side of the fifo is opened.')
    output.add_argument('-w', '--write-file',
                        help='Write output to a file instead of stdout')

    options = parser.parse_args();

    try:
        if not options.quiet:
            print("serial-pcap.py version {}".format(version))
            print("Reading from serial port {} at {} baud".format(options.port, options.baudrate))
            print("Output will be written to {}".format(options.fifo if options.fifo else options.write_file if options.write_file else "stdout"))

        timeout=0.01
        try:
            ser = serial.Serial(options.port, options.baudrate, options.bytesize,
                                options.parity, options.stopbits, options.timeout)
        except serial.SerialException as e:
            print(f"Error opening serial port {options.port}: {e}")
            sys.exit(1)

        # TTY-Flags anpassen: PARMRK ausschalten, Break/Parity ignorieren
        try:
            import termios
            fd = ser.fileno()
            attrs = termios.tcgetattr(fd)
            iflags = attrs[0]
            # Clear PARMRK so the driver does not insert 0xFF 0x00 sequences
            iflags &= ~termios.PARMRK
            # Ignore parity errors and break (prevent NULs)
            iflags |= (termios.IGNPAR | termios.IGNBRK)
            attrs[0] = iflags
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
            # Diagnose: lese die Flags zurück und zeige relevante Bits
            attrs2 = termios.tcgetattr(fd)
            iflags2 = attrs2[0]
            def flag_set(v, f): return bool(v & f)
            print("Adjusted TTY input flags: PARMRK cleared, IGNPAR/IGNBRK set")
            print(f"iflags after set: 0x{iflags2:04x}  IGNPAR={flag_set(iflags2, termios.IGNPAR)} IGNB RK={flag_set(iflags2, termios.IGNBRK)} PARMRK_set={flag_set(iflags2, termios.PARMRK)}")
        except Exception as e:
            print(f"Warning: unable to adjust termios flags: {e}")

        # Debug: zeige aktuelle serielle Einstellungen
        print(f"Serial settings: baud={ser.baudrate} bytesize={ser.bytesize} parity={ser.parity} stopbits={ser.stopbits}")
        print("Opened {} at {}".format(options.port, options.baudrate))
        
        if options.wireshark:
            if not options.fifo:
                options.fifo = WIRESHARK_FIFO
            start_wireshark(options.fifo)  
        
        out = setup_output(options)

        print("Write pcap header to pipe")
        out.write_header()

        while True:
            do_sniff_once(options,out,ser)

        ser.close()
        out.close()
    except KeyboardInterrupt:
        pass


def modbus_packet_info(pkt):
    if len(pkt) < 4:
        return "unvollständig"
    unit_id = pkt[0]
    func = pkt[1]
    # Default-Werte
    reg = count = val = byte_count = None
    crc = ""
    payload = ""
    typ = ""
    # Exception Response
    if func & 0x80 and len(pkt) == 5:
        typ = "Exception"
        crc = pkt[-2:].hex()
    # Read Request (1,2,3,4)
    elif func in (1,2,3,4) and len(pkt) == 8:
        typ = "Request"
        reg = pkt[2]<<8 | pkt[3]
        count = pkt[4]<<8 | pkt[5]
        crc = pkt[6:8].hex()
    # Read Response (1,2,3,4)
    elif func in (1,2,3,4) and len(pkt) >= 5:
        typ = "Response"
        byte_count = pkt[2]
        payload = pkt[3:3+byte_count].hex()
        crc = pkt[3+byte_count:3+byte_count+2].hex()
    # Write Single Coil/Register (5,6)
    elif func in (5,6) and len(pkt) == 8:
        typ = "Write"
        reg = pkt[2]<<8 | pkt[3]
        val = pkt[4]<<8 | pkt[5]
        crc = pkt[6:8].hex()
    # Write Multiple (15,16)
    elif func in (15,16):
        if len(pkt) >= 8 and len(pkt) != 8:
            typ = "WriteMultiReq"
            reg = pkt[2]<<8 | pkt[3]
            count = pkt[4]<<8 | pkt[5]
            byte_count = pkt[6]
            payload = pkt[7:7+byte_count].hex()
            crc = pkt[7+byte_count:7+byte_count+2].hex()
        elif len(pkt) == 8:
            typ = "WriteMultiResp"
            reg = pkt[2]<<8 | pkt[3]
            count = pkt[4]<<8 | pkt[5]
            crc = pkt[6:8].hex()
    else:
        typ = "Unknown"
        crc = pkt[-2:].hex()
        payload = pkt[2:-2].hex() if len(pkt) > 4 else ""

    # Spaltenweise Ausgabe, feste Breite
    return (
        f"UnitID: {unit_id:3d}  "
        f"Func: {func:02X}  "
        f"{typ:<12} "
        f"Count: {count if count is not None else byte_count if byte_count is not None else '':<6} "
        f"Reg: {reg if reg is not None else '':<6} "
        f"CRC: {crc:<4}  "
        f"Payload: {payload}"
    )

def is_possible_modbus_start(buffer):
    """
    Prüft, ob der aktuelle Buffer-Start ein plausibler Modbus-Frame ist.
    Jetzt prüfen wir sowohl Unit-ID (Byte 0) als auch Funktionscode (Byte 1),
    damit Reihen mit führenden 0x00 nicht fälschlich als Start erkannt werden.
    """
    if len(buffer) < 2:
        return False
    unit = buffer[0]
    func_code = buffer[1]
    # Unit 0 ist Broadcast (keine Antwort) - Antworten kommen normalerweise von 1..247
    if unit == 0 or unit > 247:
        return False
    # Gültige Funktionscodes laut Modbus-Spezifikation (inkl. Exception-Bit 0x80)
    valid_func_codes = set(range(1, 7)) | set(range(15, 17)) | set(f | 0x80 for f in range(1, 17))
    return func_code in valid_func_codes

def calculate_crc(data):
    """
    Berechnet die Modbus-CRC für die gegebenen Daten.
    """
    crc = 0xFFFF
    for pos in data:
        crc ^= pos
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF

def do_sniff_once(options, out, ser):
    """
    Lese Daten vom seriellen Port, finde Modbus-Frames, bestimme
    Request vs Response und tracke offene Requests (pending).
    Suche im Buffer nach dem frühesten CRC-validen Frame, statt
    aggressiv Bytes vor einem Kandidaten zu verwerfen.
    """
    if not hasattr(do_sniff_once, "buffer"):
        do_sniff_once.buffer = bytearray()
    if not hasattr(do_sniff_once, "pending"):
        do_sniff_once.pending = {}
    buffer = do_sniff_once.buffer
    pending = do_sniff_once.pending

    # read only available bytes
    avail = getattr(ser, 'in_waiting', None)
    fd = ser.fileno()
    if avail is None:
        try:
            data = ser.read_all()
        except AttributeError:
            try:
                data = os.read(fd, 1024)
            except Exception:
                data = ser.read(1)
    else:
        if avail == 0:
            return
        try:
            data = os.read(fd, avail)
        except Exception:
            data = ser.read(avail)

    if data:
        print(f"Received data: {data.hex()}")
        # log big all-zero blocks but keep them (do not aggressively drop)
        if all(b == 0x00 for b in data) and len(data) > 64:
            print(f"Warning: large all-0x00 block length {len(data)} - possible line noise")
        buffer += data

    def consume(n):
        del buffer[:n]

    # minimal bytes to check headers+crc
    if len(buffer) < 5:
        return

    valid_funcs = set(range(1, 7)) | set(range(15, 17)) | set(f | 0x80 for f in range(1, 17))
    now = time.time()
    # cleanup pending older than 5s
    for k in list(pending.keys()):
        lst = pending[k]
        pending[k] = [e for e in lst if now - e['ts'] < 5.0]
        if not pending[k]:
            del pending[k]

    # Search loop: find earliest CRC-valid packet anywhere in buffer
    while True:
        if len(buffer) < 5:
            break

        found = False
        found_i = None
        found_len = None
        found_pkt = None

        max_search = min(len(buffer), 4096)
        # Modbus RTU max payload typically <= 250; cap length to reasonable max
        MAX_FRAME_LEN = 1 + 1 + 1 + 250 + 2

        for i in range(0, max_search - 4):
            unit = buffer[i]
            func = buffer[i + 1]
            if not (1 <= unit <= 247 and func in valid_funcs):
                continue

            # build candidate lengths depending on func
            candidates = set()

            # exception responses
            if func & 0x80:
                candidates.add(1 + 1 + 1 + 2)  # 5

            if func in (5, 6):
                candidates.add(8)

            if func in (15, 16):
                # if byte_count available parse request length
                if i + 7 < len(buffer):
                    byte_count = buffer[i + 6]
                    if 0 <= byte_count <= 250:
                        candidates.add(1 + 1 + 2 + 2 + 1 + byte_count + 2)
                # response fixed
                candidates.add(8)

            if func in (1, 2, 3, 4):
                # response candidate if byte_count present
                if i + 2 < len(buffer):
                    byte_count = buffer[i + 2]
                    if 0 <= byte_count <= 250:
                        candidates.add(1 + 1 + 1 + byte_count + 2)
                # request fixed
                candidates.add(8)

            # try candidates (smallest first -> earliest full frames)
            for L in sorted(candidates):
                if L < 5 or L > MAX_FRAME_LEN:
                    continue
                if i + L > len(buffer):
                    continue
                pkt = buffer[i:i+L]
                exp = calculate_crc(pkt[:-2])
                rec = int.from_bytes(pkt[-2:], byteorder='little')
                if exp == rec:
                    found = True
                    found_i = i
                    found_len = L
                    found_pkt = bytes(pkt)
                    break
            if found:
                break

        if not found:
            # no CRC-valid frame found yet
            # if buffer grows too large, trim the prefix but keep a window
            if len(buffer) > 8192:
                print("Buffer too large without finding any valid frame, trimming prefix")
                del buffer[:len(buffer)-4096]
            break

        # if there are bytes before the found candidate, remove them (noise)
        if found_i > 0:
            # be explicit about what is thrown away
            print(f"Discarding {found_i} bytes of noise before valid frame at index {found_i} (eventually no response from device)")
            del buffer[:found_i]

        # now found frame starts at buffer[0]
        pkt = bytes(buffer[:found_len])
        unit = pkt[0]
        func = pkt[1]

        # Determine direction: Request or Response
        direction = None
        matched = False

        # Decide by structural shape first:
        if func & 0x80 or (func in (1,2,3,4) and found_len >= 5 and found_len != 8 and (found_len == 1+1+1+pkt[2]+2)):
            direction = "Response"
        elif func in (5,6) and found_len == 8:
            # ambiguous – prefer Response if pending exists
            direction = "Response" if (unit, func) in pending else "Request"
        elif func in (15,16):
            # 15/16: if found_len > 8 and matches request shape -> Request
            if found_len > 8:
                direction = "Request"
            else:
                direction = "Response" if (unit, func) in pending else "Request"
        elif func in (1,2,3,4):
            # 1-4: if found_len == 8 -> Request; if variable length -> Response
            if found_len == 8:
                direction = "Request" if (unit, func) not in pending else "Request"
            else:
                direction = "Response"

        # refine by pending matching: if this frame matches an expected pending response, prefer Response
        if direction != "Response":
            lst = pending.get((unit, func), [])
            for idx, entry in enumerate(list(lst)):
                if entry['exp_len'] == found_len:
                    matched = True
                    direction = "Response"
                    # remove matched pending
                    del lst[idx]
                    if not lst:
                        del pending[(unit, func)]
                    break

        # If it's a request, register expected response in pending
        if direction == "Request":
            if func in (1,2,3,4) and found_len >= 8:
                quantity = (pkt[4] << 8) | pkt[5]
                if func in (3,4):
                    resp_byte_count = quantity * 2
                else:
                    resp_byte_count = (quantity + 7) // 8
                expected_resp_len = 1 + 1 + 1 + resp_byte_count + 2
                pending.setdefault((unit, func), []).append({'exp_len': expected_resp_len, 'ts': now, 'params': {'quantity': quantity}})
            elif func in (5,6):
                pending.setdefault((unit, func), []).append({'exp_len': 8, 'ts': now, 'params': {}})
            elif func in (15,16):
                # response fixed 8
                pending.setdefault((unit, func), []).append({'exp_len': 8, 'ts': now, 'params': {}})

        # Log direction and match status before output
        match_info = "matched" if matched else ""
        print(f"Packet direction: {direction} {match_info}".strip())

        # consume and output
        consume(found_len)
        print(f"Extracted packet: {found_pkt.hex()}")
        if not options.quiet:
            print("Packet info:", modbus_packet_info(found_pkt))

        try:
            out.write_packet(found_pkt)
        except OSError as e:
            if e.errno == errno.ESTRPIPE:
                return
        # continue to look for next frame in buffer
    # end while

if __name__ == '__main__':
    main()
