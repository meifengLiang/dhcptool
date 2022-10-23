# -*- coding: utf-8 -*-
# @Time    : 2022/10/23 19:00
# @Author  : mf.liang
# @File    : dhcp_pkt.py
# @Software: PyCharm
# @desc    :
import logging

from scapy.layers.dhcp6 import DHCP6_Solicit, DHCP6_Release, DHCP6OptClientId, DHCP6OptIA_NA, DHCP6OptIA_PD, \
    DHCP6_Request, DHCP6OptServerId, DHCP6_RelayForward, DUID_LLT
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.utils import mac2str

from env_args import xid, random_mac
from tools import Tools


class Pkt:

    def __init__(self):
        self.ether = Ether()
        self.udp = UDP()

    def send_pkt(self):
        pass


class Dhcp6Pkt(Pkt):

    def __init__(self):
        super(Dhcp6Pkt, self).__init__()

        self.ether_ipv6_udp = self.ether / IPv6(src=Tools.get_local_ipv6(), dst='ff02::1:2') / self.udp
        self.duid = DUID_LLT(lladdr=mac2str(random_mac), timeval=xid)
        self.solicit = DHCP6_Solicit(trid=xid)
        self.release = DHCP6_Release(trid=xid)
        self.opt_client_id = DHCP6OptClientId(duid=self.duid)
        self.opt_ia_na = DHCP6OptIA_NA(iaid=xid)
        self.opt_ia_pd = DHCP6OptIA_PD(iaid=xid)
        self.request = DHCP6_Request(trid=xid)
        self.request = DHCP6_Request(trid=xid)
        self.opt_server_id = DHCP6OptServerId()
        self.relay_forward = DHCP6_RelayForward(linkaddr=filter)

    def dhcp6_solicit(self):
        logging.debug('生产solicit包')

    def dhcp6_advertise(self):
        pass

    def dhcp6_request(self):
        pass

    def dhcp6_reply(self):
        pass


class Dhcp4Pkt(Pkt):

    def __init__(self):
        super(Dhcp4Pkt, self).__init__()

    def dhcp4_discover(self):
        pass

    def dhcp4_offer(self):
        pass

    def dhcp4_request(self):
        pass

    def dhcp4_ack(self):
        pass
