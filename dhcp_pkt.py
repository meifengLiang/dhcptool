# -*- coding: utf-8 -*-
# @Time    : 2022/10/23 19:00
# @Author  : mf.liang
# @File    : dhcp_pkt.py
# @Software: PyCharm
# @desc    :

from time import sleep

from loguru import logger
from scapy.layers.dhcp6 import DHCP6_Solicit, DHCP6_Release, DHCP6OptClientId, DHCP6OptIA_NA, DHCP6OptIA_PD, \
    DHCP6_Request, DHCP6OptServerId, DHCP6_RelayForward, DUID_LLT
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, srp1, AsyncSniffer
from scapy.utils import mac2str

from env_args import xid, random_mac, pkt_result
from tools import Tools


class Pkt:

    def __init__(self):
        self.ether = Ether()
        self.udp = UDP()
        self.DHCPv6 = None

    def send_dhcp6_pkt(self, pkt, filter: str = None):
        pkt.summary()
        t = AsyncSniffer(iface="eth0", filter=f'port 547 and host {filter}')
        t.start()
        sleep(50 / 1000)
        sendp(pkt, verbose=0)
        t.stop()
        return t.results

    def send_dhcp4_pkt(self, pkt):
        res = srp1(pkt)


class Dhcp6Pkt(Pkt):

    def __init__(self, args):
        super(Dhcp6Pkt, self).__init__()
        self.args = args
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
        logger.debug('生产solicit包')
        solicit_pkt = self.ether_ipv6_udp / self.solicit / self.opt_client_id / self.opt_ia_na

        Tools.print_formart(solicit_pkt, self.args.get('debug'))
        return solicit_pkt

    def dhcp6_advertise(self):
        pass

    def dhcp6_request(self):
        logger.debug('生产request包')
        advertise_pkt = pkt_result.get('dhcp6_advertise').get()
        opt_client_id = advertise_pkt[DHCP6OptClientId]
        request_pkt = self.ether_ipv6_udp / self.request / opt_client_id
        request_pkt.summary()
        return request_pkt

    def dhcp6_reply(self):
        pass

    def dhcp6_relay_forward(self):
        logger.debug('生产relay forward包')
        pass


class Dhcp4Pkt(Pkt):

    def __init__(self, args):
        super(Dhcp4Pkt, self).__init__()
        self.args = args

    def dhcp4_discover(self):
        pass

    def dhcp4_offer(self):
        pass

    def dhcp4_request(self):
        pass

    def dhcp4_ack(self):
        pass
