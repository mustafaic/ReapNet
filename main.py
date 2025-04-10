import os
import re
import pandas as pd
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
import socket
import subprocess
from tabulate import tabulate


def get_local_network():
    try:
        # Windows ve Unix sistemleri için komut seçimi
        command = "ipconfig" if os.name == "nt" else "ifconfig"
        encoding = "cp850" if os.name == "nt" else "utf-8"

        result = subprocess.check_output(command, shell=True).decode(encoding, errors="ignore")

        # IP adreslerini yakalamak için regex
        if os.name == "nt":
            ip_pattern = re.compile(r"IPv4 Address.*?: (\d+\.\d+\.\d+\.\d+)")
        else:
            ip_pattern = re.compile(r"inet (\d+\.\d+\.\d+\.\d+)")

        matches = ip_pattern.findall(result)

        for ip in matches:
            if ip.startswith(("192.", "10.", "172.")):
                network = f"{'.'.join(ip.split('.')[:3])}.0/24"
                return network

    except Exception as e:
        print(f"Hata oluştu: {e}")

    return None


def scan_network(network):
    try:
        # ARP taraması
        arp_request = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_packet = broadcast / arp_request

        print("Ağ taranıyor, lütfen bekleyin...")
        answered, _ = srp(arp_packet, timeout=3, verbose=False)

        devices = []
        for sent, received in answered:
            devices.append({
                "IP": received.psrc,
                "MAC": received.hwsrc
            })

        return devices

    except Exception as e:
        print(f"Tarama sırasında hata oluştu: {e}")
        return []


def scan_ports(ip):
    open_ports = []
    common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389]

    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass

    return ", ".join(map(str, open_ports)) if open_ports else "Yok"


def main():
    # Yerel ağ tespiti
    network = get_local_network()
    if not network:
        print("Ağ tespit edilemedi!")
        return

    print(f"Taranan Ağ: {network}")

    # Ağdaki cihazları tara
    devices = scan_network(network)
    if not devices:
        print("Hiçbir cihaz bulunamadı!")
        return

    # Her cihaz için port taraması yap
    for device in devices:
        device["Açık Portlar"] = scan_ports(device["IP"])

    print("\nAğdaki Cihazlar:")
    print(tabulate(devices, headers="keys", tablefmt="grid"))


if __name__ == "__main__":
    main()
