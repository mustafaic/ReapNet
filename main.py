import os
import pandas
import scapy.all as scapy
import mmap
import socket
import subprocess

from numpy.f2py.crackfortran import verbose
from tabulate import tabulate

def get_local_network():

    result = subprocess.check_output("ipconfig" if os.name == "nt" else "ifconfig", shell=True).decode()
    lines = result.strip("\n")

    for line in lines:
        if "IPv4 Address" in line or "inet" in line:
            ip = line.strip(":")[-1].strip() if os.name == "nt" else line.strip()[1]
            if ip.startswith("192.") or ip.startswith("10.") or ip.startswith("172."):
                return ".".join(ip.split(".")[:-1]) + ".0/24"

    return None


def scan_network(network):
    arp_request = scapy.ARP(pdst=network)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = broadcast / arp_request
    answered = scapy.srp(arp_packet, timeout=2, verbose=False)[0]

    devices = []

    for sent, received in answered:
        devices.append({"IP": received.psrc, "MAC": received.hwsrc})

    return devices


def scan_ports(ip):
    open_ports = []
    for port in [22,80,443,445,3389]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        if sock.connect_ex((ip,port)) == 0:
            open_ports.append(port)

        sock.close()

    return open_ports


def main():
    network = get_local_network()
    if not network:
        print("Ağ bulunamadı!")
        return

    print(f"Taranan Ağ: {network}")
    devices = scan_network(network)

    for device in devices:
        device["Open Ports"] = scan_ports(device["IP"])

    print("\nAğdaki Cihazlar:")
    print(tabulate(devices, headers="keys", tablefmt="grid"))


if __name__ == "__main__":
    main()



