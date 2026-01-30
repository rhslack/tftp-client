import socket
import struct
import os
from loguru import logger
import pyfiglet
import click

# TFTP Opcodes
OP_RRQ = 1   # Read Request
OP_WRQ = 2   # Write Request
OP_DATA = 3  # Data Packet
OP_ACK = 4   # Acknowledgment
OP_ERROR = 5 # Error Packet
OP_OACK = 6  # Option Acknowledgment

TFTP_PORT = 69
DEFAULT_BLOCK_SIZE = 512

def show_banner():
    banner = pyfiglet.figlet_format("TFTP Client", font="slant")
    click.echo(click.style(banner, fg="cyan", bold=True))
    click.echo(click.style("A powerful and stylish TFTP client with Loguru", fg="yellow"))
    click.echo("-" * 60)

def send_rrq(sock, server_addr, filename, mode="octet", options=None):
    # RRQ: Opcode (2) + Filename + 0 + Mode + 0 + Options
    format_str = f">H{len(filename)}sb{len(mode)}sb"
    packet = struct.pack(format_str, OP_RRQ, filename.encode(), 0, mode.encode(), 0)
    
    if options:
        for key, value in options.items():
            packet += f"{key}\0{value}\0".encode()
            
    sock.sendto(packet, server_addr)
    logger.debug(f"Sent read request (RRQ) for {filename} with options {options}")

def send_wrq(sock, server_addr, filename, mode="octet", options=None):
    # WRQ: Opcode (2) + Filename + 0 + Mode + 0 + Options
    format_str = f">H{len(filename)}sb{len(mode)}sb"
    packet = struct.pack(format_str, OP_WRQ, filename.encode(), 0, mode.encode(), 0)
    
    if options:
        for key, value in options.items():
            packet += f"{key}\0{value}\0".encode()
            
    sock.sendto(packet, server_addr)
    logger.debug(f"Sent write request (WRQ) for {filename} with options {options}")

def parse_oack(data):
    # OACK: Opcode (2) + Option1 + 0 + Value1 + 0 + ...
    options = {}
    parts = data[2:].split(b'\0')
    for i in range(0, len(parts) - 1, 2):
        if parts[i]:
            options[parts[i].decode()] = parts[i+1].decode()
    return options

def send_ack(sock, server_addr, block_num):
    # ACK: Opcode (2) + Block Number (2)
    packet = struct.pack(">HH", OP_ACK, block_num)
    sock.sendto(packet, server_addr)
    logger.trace(f"Sent ACK for block {block_num}")

@click.group()
def cli():
    """Simple and Powerful TFTP Client."""
    pass

@cli.command()
@click.argument('host')
@click.argument('filename')
@click.option('--port', default=TFTP_PORT, help='TFTP server port')
@click.option('--output', help='Output filename')
@click.option('--mode', default='octet', type=click.Choice(['octet', 'netascii'], case_sensitive=False), help='Transfer mode')
@click.option('--blksize', default=DEFAULT_BLOCK_SIZE, type=int, help='Block size (RFC 2348)')
@click.option('--timeout', default=5, type=int, help='Timeout in seconds (RFC 2349)')
def get(host, filename, port, output, mode, blksize, timeout):
    """Download a file from the TFTP server."""
    show_banner()
    if not output:
        output = filename

    server_addr = (host, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(float(timeout))

    options = {}
    if blksize != DEFAULT_BLOCK_SIZE:
        options['blksize'] = str(blksize)
    if timeout != 5:
        options['timeout'] = str(timeout)

    block_size = DEFAULT_BLOCK_SIZE

    try:
        send_rrq(sock, server_addr, filename, mode=mode.lower(), options=options)
        
        with open(output, 'wb') as f:
            expected_block = 1
            while True:
                try:
                    # We use a large enough buffer for the first packet (OACK or DATA)
                    data, server_new_addr = sock.recvfrom(blksize + 4 if blksize > DEFAULT_BLOCK_SIZE else DEFAULT_BLOCK_SIZE + 4)
                    opcode = struct.unpack(">H", data[:2])[0]

                    if opcode == OP_DATA:
                        block_num = struct.unpack(">H", data[2:4])[0]
                        payload = data[4:]

                        if block_num == expected_block:
                            f.write(payload)
                            logger.info(f"Received block {block_num} ({len(payload)} bytes)")
                            send_ack(sock, server_new_addr, block_num)
                            expected_block += 1
                            
                            if len(payload) < block_size:
                                logger.success(f"Download completed: {output}")
                                break
                        else:
                            logger.warning(f"Received unexpected block: {block_num}, expected: {expected_block}")
                            send_ack(sock, server_new_addr, block_num)

                    elif opcode == OP_OACK:
                        server_options = parse_oack(data)
                        logger.info(f"Received OACK with options: {server_options}")
                        if 'blksize' in server_options:
                            block_size = int(server_options['blksize'])
                            logger.info(f"Block size negotiated: {block_size}")
                        # Acknowledge OACK with ACK 0
                        send_ack(sock, server_new_addr, 0)

                    elif opcode == OP_ERROR:
                        error_code = struct.unpack(">H", data[2:4])[0]
                        error_msg = data[4:-1].decode()
                        logger.error(f"Error from server ({error_code}): {error_msg}")
                        break
                except socket.timeout:
                    logger.error("Timeout during data reception")
                    break
    except Exception as e:
        logger.exception(f"Error during download: {e}")
    finally:
        sock.close()

@cli.command()
@click.argument('host')
@click.argument('filename')
@click.option('--port', default=TFTP_PORT, help='TFTP server port')
@click.option('--mode', default='octet', type=click.Choice(['octet', 'netascii'], case_sensitive=False), help='Transfer mode')
@click.option('--blksize', default=DEFAULT_BLOCK_SIZE, type=int, help='Block size (RFC 2348)')
@click.option('--timeout', default=5, type=int, help='Timeout in seconds (RFC 2349)')
def put(host, filename, port, mode, blksize, timeout):
    """Send a file to the TFTP server."""
    show_banner()
    if not os.path.exists(filename):
        logger.error(f"File not found: {filename}")
        return

    server_addr = (host, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(float(timeout))

    options = {}
    if blksize != DEFAULT_BLOCK_SIZE:
        options['blksize'] = str(blksize)
    if timeout != 5:
        options['timeout'] = str(timeout)

    block_size = DEFAULT_BLOCK_SIZE

    try:
        send_wrq(sock, server_addr, filename, mode=mode.lower(), options=options)

        with open(filename, 'rb') as f:
            block_num = 0
            # Wait for ACK for WRQ (block 0) or OACK
            data, server_new_addr = sock.recvfrom(blksize + 4 if blksize > DEFAULT_BLOCK_SIZE else DEFAULT_BLOCK_SIZE + 4)
            opcode = struct.unpack(">H", data[:2])[0]
            
            if opcode == OP_ACK or opcode == OP_OACK:
                if opcode == OP_OACK:
                    server_options = parse_oack(data)
                    logger.info(f"Received OACK with options: {server_options}")
                    if 'blksize' in server_options:
                        block_size = int(server_options['blksize'])
                        logger.info(f"Block size negotiated: {block_size}")
                
                logger.info("Starting upload...")
                block_num = 1
                while True:
                    payload = f.read(block_size)
                    
                    # DATA packet
                    data_packet = struct.pack(">HH", OP_DATA, block_num) + payload
                    sock.sendto(data_packet, server_new_addr)
                    logger.info(f"Sent block {block_num} ({len(payload)} bytes)")

                    # Wait for ACK
                    try:
                        ack_data, _ = sock.recvfrom(block_size + 4)
                        ack_op, ack_num = struct.unpack(">HH", ack_data[:4])
                        if ack_op == OP_ACK and ack_num == block_num:
                            if len(payload) < block_size:
                                logger.success(f"Upload completed: {filename}")
                                break
                            block_num += 1
                        elif ack_op == OP_ERROR:
                            err_code = struct.unpack(">H", ack_data[2:4])[0]
                            err_msg = ack_data[4:-1].decode()
                            logger.error(f"Error from server: {err_msg}")
                            break
                    except socket.timeout:
                        logger.error("Timeout while waiting for ACK")
                        break
            elif opcode == OP_ERROR:
                error_msg = data[4:-1].decode()
                logger.error(f"Error from server during WRQ phase: {error_msg}")

    except Exception as e:
        logger.exception(f"Error during upload: {e}")
    finally:
        sock.close()

if __name__ == '__main__':
    cli()
