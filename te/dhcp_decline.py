# coding = 'utf-8'
"""
@File:          dhcp_decline.py
@Time:          2022/10/24 10:31
@Author:        mf.liang
@Email:         mf.liang@yamu.com
@Desc:
"""
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import srp1
from scapy.utils import mac2str
from scapy.volatile import RandMAC

ether = Ether()
udp = UDP(sport=68, dport=67)
bootp = BOOTP(chaddr=mac2str(RandMAC()))
ip = IP(dst='192.168.31.134')
ether_ip_udp_bootp = ether / ip / udp / bootp

dhcp_discover = DHCP(options=[("message-type", "discover"), "end"])
dhcp_request = DHCP(options=[("message-type", "request"), "end"])
dhcp_inform = DHCP(options=[("message-type", "inform"), "end"])
dhcp_decline = DHCP(options=[("message-type", "decline"), "end"])

for i in range(10):

    offer = srp1(ether_ip_udp_bootp / dhcp_discover)
    yiaddr = offer[BOOTP].yiaddr
    dhcp_request.options.insert(-1, ("requested_addr", yiaddr))
    ack = srp1(ether_ip_udp_bootp / dhcp_request)
    ack.show()

    dhcp_decline.options.insert(-1, ("requested_addr", yiaddr))
    decline = srp1(ether_ip_udp_bootp / dhcp_decline, timeout=1)
