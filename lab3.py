#!/usr/bin/python3

import socket
import select
import sys
import threading
import signal
import datetime
from struct import pack, unpack
from time import sleep

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


endpoints_dict = {}
ip_to_name = {}
is_active = True
PACKET_LEN = 6

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverUPD = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serverUPD.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
serverUPD.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

def on_exit(a, b):
    global is_active
    is_active = False
    server.close()
    print("exit...")

signal.signal(signal.SIGINT, on_exit)

def output(conn, text: str):
    if not conn:
        user = "you"
    else:
        info = endpoints_dict[conn]
        name = ip_to_name.get(info, "Martha")
        user = f"{info[0]}:{info[1]}({name})"

    date = datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    print(f"[{date} <{user}>]:{text}")


def init_connection(ip: str, port: int) -> int: 
    comutator = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        endpoints_dict[comutator] = (ip, port)
        comutator.connect((ip, port)) 
    except:
        print(f"Can't connect to {ip}:{port}")
        endpoints_dict.pop(comutator)
        return -1
    else:
        init_pack = b"\x01"+socket.inet_aton(serverIP[0])+pack("!H", serverIP[1])+pack("!B", len(Username))+Username.encode("utf-8")
        comutator.send(init_pack + pack_endpoints())
        output(None, f"{ip}:{port} - {bcolors.HEADER}connected{bcolors.ENDC}")
        return 0

def send_upd() -> int:
    init_pack = b"\x00"+socket.inet_aton(serverIP[0])+pack("!H", serverIP[1])+Username.encode("utf-8")
    serverUPD.sendto(init_pack, ("<broadcast>", 5005))
    output(None, f"{bcolors.HEADER}search for clients...{bcolors.ENDC}")
    return 0


def work_with_pack(conn: socket.socket, package: bytes):
    if len(package)<1:
        output(conn, f"{bcolors.BOLD}{bcolors.WARNING}disconnected{bcolors.ENDC}")
        endpoints_dict.pop(conn)
        return

    type = package[0]
    if(type == 0 and conn == serverUPD):
        ip_tuple = (socket.inet_ntoa(package[1:5]), int.from_bytes(package[5:7],"big"))
        ip_to_name[ip_tuple] = package[7:].decode('utf-8')
        if(ip_tuple not in endpoints_dict.values() and ip_tuple != serverIP):
            init_connection(*ip_tuple)
    elif(type == 1):
        ip_tuple = (socket.inet_ntoa(package[1:5]), int.from_bytes(package[5:7],"big"))
        length = package[7]
        ip_to_name[ip_tuple] = package[8:8+length].decode('utf-8')
        endpoints_dict[conn] = ip_tuple
        
        count = package[8+length]
        for i in range(count):
            target_ip = socket.inet_ntoa(package[9+length+i*PACKET_LEN:13+length+i*PACKET_LEN])
            target_port = int.from_bytes(package[13+length+i*PACKET_LEN:15+length+i*PACKET_LEN],"big")
            if (target_ip, target_port) not in endpoints_dict.values() and (target_ip, target_port) != serverIP:
                init_connection(target_ip, target_port)
    elif(type == 255):
        output(conn, package[1:].decode('utf-8'))
    else:
        print(package)

def broadcast(message: str):
    for conn in endpoints_dict.keys():
        try:
            conn.send(b"\xff"+message.encode('utf-8'))
        except:
            endpoints_dict.pop(conn)


def pack_endpoints():
    endpt_bytes = pack("!B", len(endpoints_dict.values())+1)
    for endpoint in endpoints_dict.values():
        endpt_bytes += socket.inet_aton(endpoint[0])
        endpt_bytes += pack("!H", endpoint[1])
    endpt_bytes += socket.inet_aton(serverIP[0])
    endpt_bytes += pack("!H", serverIP[1])
    return endpt_bytes

def background_listen():
    while is_active:
        inputs = list(endpoints_dict.keys())
        inputs.append(sys.stdin)
        inputs.append(serverUPD)

        read_sockets, write_socket, error_socket = select.select(inputs, [], [], 0.05)

        for input_itm in read_sockets:
            if(input_itm == sys.stdin):
                message = sys.stdin.readline()[:-1]
                broadcast(message)
                output(None, message)
            else:
                message = input_itm.recv(2048)
                work_with_pack(input_itm, message)


IP_address, Port = sys.argv[1].split(":")
Port = int(Port)
serverIP = (IP_address, Port)
Username = sys.argv[2]
ip_to_name[serverIP] = Username

try:
    server.bind(serverIP)
    server.listen(10)
except:
    print("port is busy")
    exit(-1)#вот тут

listener = threading.Thread(target=background_listen)
listener.start()
serverUPD.bind(("", 5005))

status = send_upd()
if(status):
    on_exit(None, None)

while is_active:
    try:
        conn, addr = server.accept()
        endpoints_dict[conn] = addr
    except OSError:
        break

listener.join()
