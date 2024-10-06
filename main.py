from scapy.all import sniff, IP, TCP, UDP
import psutil
from datetime import datetime
import os
os.system('clear' if os.name == 'posix' else 'cls')

known_ports = {
    0: "Reserved",
    1: "TCP Port Service Multiplexer (TCPMUX)",
    5: "Remote Job Entry",
    7: "Echo",
    9: "Discard",
    11: "Active Users",
    13: "Daytime",
    17: "Quote of the Day",
    19: "Character Generator",
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    77: "Privileged Copy",
    79: "Finger",
    87: "TTYlink",
    95: "Supdup",
    37: "Time",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    113: "Ident",
    123: "NTP",
    135: "MS RPC",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    194: "IRC",
    443: "HTTPS",
    465: "SMTP over SSL",
    487: "X.400",
    514: "Syslog",
    522: "XMPP",
    523: "IBM Tivoli",
    540: "UUCP",
    543: "Klogin",
    544: "KShell",
    554: "RTSP",
    563: "NNTPS",
    587: "SMTP (Submission)",
    631: "IPP",
    636: "LDAPS",
    5000: "UPnP / Flask",
    993: "IMAP over SSL",
    995: "POP3 over SSL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6000: "X11",
    29: "Message Send Protocol",
    37: "Time",
    42: "Name Server",
    49: "TACACS",
    53: "DNS",
    77: "Privileged Copy",
    79: "Finger",
    87: "TTYlink",
    95: "Supdup",
    123: "NTP",
    135: "MS RPC",
    139: "NetBIOS Session Service",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    177: "X Display Manager Control Protocol (XDMCP)",
    514: "Syslog",
    515: "Printer",
    543: "Klogin",
    544: "KShell",
    631: "IPP (Internet Printing Protocol)",
    646: "LDP (Label Distribution Protocol)",
    666: "Doom",
    710: "CPLS (Call Processing Language Service)",
    749: "Kerberos (Admin)",
    767: "VTP (VLAN Trunking Protocol)",
    820: "L2F (Layer 2 Forwarding Protocol)",
    873: "RSYNC",
    888: "AJP13 (Apache JServ Protocol)",
    989: "FTPS (Data)",
    990: "FTPS (Control)",
    995: "POP3 over SSL",
    10001: "UDP Port for the DNS Service",
    10002: "UDP Port for the BIND DNS Service",
    12345: "NetBus",
    1433: "SQL Server",
    1434: "SQL Server (UDP)",
    3307: "MySQL (Cluster)",
    3388: "MS WBT Server",
    5431: "Oracle XDB",
    5901: "VNC Display 1",
    5902: "VNC Display 2",
    5985: "WSMan (HTTP)",
    5986: "WSMan (HTTPS)",
    6000: "X11 (Display 0)",
    6008: "X11 (Display 1)",
    8085: "HTTP Alternate",
    8086: "InfluxDB",
    8880: "HTTP Alternate",
    8881: "HTTP Alternate",
    9001: "Tor Hidden Service",
    9200: "Elasticsearch",
    9300: "Elasticsearch (Transport)",
    27020: "MongoDB (Shard)",
    49152: "Dynamic/Private Ports",
    49153: "Dynamic/Private Ports",
    49154: "Dynamic/Private Ports",
    49155: "Dynamic/Private Ports",
    6666: "HTTP Alternate",
    6667: "IRC",
    8080: "HTTP Alternate",
    8081: "HTTP Alternate",
    8443: "HTTPS Alternate",
    27017: "MongoDB",
    5001: "UPnP",
    5002: "UPnP",
    5003: "UPnP",
    6001: "X11:1",
    6002: "X11:2",
    6003: "X11:3",
    6004: "X11:4",
    6005: "X11:5",
    6006: "X11:6",
    6007: "X11:7",
    6379: "Redis",
    8082: "HTTP Alternate",
    8083: "HTTP Alternate",
    8084: "HTTP Alternate",
    27018: "MongoDB",
    27019: "MongoDB",
    5005: "RMI Registry",
    6009: "RMI Tunneling",
    7000: "Torrents",
    8888: "HTTP Alternate",
    9000: "Various",
    9090: "HTTP Alternate",
    10000: "Webmin",
    32768: "Dynamic/Private Ports",
}

def get_application_name(port):
    return known_ports.get(port, "Application Not Found")

def get_process_info(ip, port):
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr and conn.raddr.ip == ip and conn.raddr.port == port:
            try:
                process = psutil.Process(conn.pid)
                return process.name(), conn.pid
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return "Access Denied", conn.pid
    return "Application Not Found", None

def packet_handler(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if packet.haslayer(TCP):
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport
            app_src, pid_src = get_process_info(ip_src, port_src)
            app_dst, pid_dst = get_process_info(ip_dst, port_dst)
            print(f"[{timestamp}] Source: {ip_src} ({app_src}:{port_src}, PID: {pid_src}) -> Aim: {ip_dst} ({app_dst}:{port_dst}, PID: {pid_dst}) | Dimension: {len(packet)} bytes | Protocol: TCP | TCP Flags: {packet[TCP].flags} | Window Size: {packet[TCP].window}")

        elif packet.haslayer(UDP):
            port_src = packet[UDP].sport
            port_dst = packet[UDP].dport
            app_src, pid_src = get_process_info(ip_src, port_src)
            app_dst, pid_dst = get_process_info(ip_dst, port_dst)
            print(f"[{timestamp}] Source: {ip_src} ({app_src}:{port_src}, PID: {pid_src}) -> Aim: {ip_dst} ({app_dst}:{port_dst}, PID: {pid_dst}) | Dimension: {len(packet)} bytes | Protocol: UDP | Window Size: {packet[UDP].len}")

# Ana fonksiyon
if __name__ == "__main__":
    print("""

 ______             _                      
(_____ \           | |            _        
 _____) _____  ____| |  _ _____ _| |_      
|  ____(____ |/ ___| |_/ | ___ (_   _)     
| |    / ___ ( (___|  _ (| ____| | |_      
|_|    \_____|\____|_| \_|_____)  \__)     
                                           
  ______       _    ___    ___             
 / _____)     (_)  / __)  / __)            
( (____  ____  _ _| |__ _| |__ _____  ____ 
 \____ \|  _ \| (_   __(_   __| ___ |/ ___)
 _____) | | | | | | |    | |  | ____| |    
(______/|_| |_|_| |_|    |_|  |_____|_|                                              
                                                            
          """)
    input("[<>] Press 'Enter' to start capturing packets...")
    try:
        print("[<>] Packet capture has started. To stop, press Ctrl+C.")
        sniff(prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\n[<>] Packet capture stopped.")
