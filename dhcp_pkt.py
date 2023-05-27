# -*- coding: utf-8 -*-
# @Time    : 2022/10/23 19:00
# @Author  : mf.liang
# @File    : dhcp_pkt.py
# @Software: PyCharm
# @desc    :
import random
from argparse import Namespace
from ipaddress import ip_address
from time import sleep
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dhcp6 import DHCP6_Solicit, DHCP6_Release, DHCP6OptClientId, DHCP6OptIA_NA, DHCP6OptIA_PD, \
    DHCP6_Request, DHCP6OptServerId, DHCP6_RelayForward, DUID_LLT, DHCP6_Renew, DHCP6_Decline, DHCP6OptRelayMsg
from scapy.layers.inet import UDP, IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.utils import mac2str, str2mac
from scapy.sendrecv import sendp, srp1, AsyncSniffer
from env_args import xid, pkt_result, logs
from options import Dhcp4Options, Dhcp6Options
from tools import Tools


class Pkt:

    def __init__(self, args):
        self.args = args
        self.ether = Ether()
        self.udp = UDP()
        self.DHCPv6 = None
        self.timeout = 200 / 1000
        self.mac = Tools.get_mac(self.args)
        self.xid = Tools.get_xid_by_mac(self.mac)

    def send_dhcp6_pkt(self, pkt, args: Namespace = None):
        """
        发送并接收 dhcp6 数据包
        :param pkt:
        :param args:
        :return:
        """
        if args.filter and ip_address(args.filter).version == 6:
            filter = args.filter
        elif args.dhcp_server and ip_address(args.dhcp_server).version == 6:
            filter = args.dhcp_server
        else:
            logs.info("v6发包需要指定IPv6服务器")
            filter = 'ff02::1:2'
        debug = args.debug
        Tools.print_formart(pkt, debug)
        t = AsyncSniffer(iface=args.iface, filter=f'port 547 and src host {filter}', count=1,
                         timeout=self.timeout)
        t.start()
        sleep(10 / 1000)
        sendp(pkt, verbose=0)
        t.join()
        return t.results

    def send_dhcp4_pkt(self, pkt, args: Namespace = None):
        """
        发送并接收 dhcp4 数据包
        :param pkt:
        :param args:
        :return:
        """
        if args.filter and ip_address(args.filter).version == 4:
            filter = args.filter
            debug = args.debug
            Tools.print_formart(pkt, debug)
            t = AsyncSniffer(iface=args.iface, filter=f'port 67 and src host {filter}', count=1,
                             timeout=self.timeout)
            t.start()
            sleep(10 / 1000)
            sendp(pkt, verbose=0, iface=args.iface)
            t.join()
            return t.results
        elif args.dhcp_server and ip_address(args.dhcp_server).version == 4:
            debug = args.debug
            Tools.print_formart(pkt, debug)
            res = srp1(pkt, verbose=0, timeout=self.timeout, iface=args.iface)
            try:
                assert res
            except Exception as ex:
                logs.error('没有接收到返回包！')
            return res
        else:
            logs.info("v4发包需要指定IPv4服务器")


class Dhcp6Pkt(Pkt):

    def __init__(self, args):
        super(Dhcp6Pkt, self).__init__(args)
        if args.filter:
            self.ether_ipv6_udp = self.ether / IPv6(src=Tools.get_local_ipv6(), dst='ff02::1:2') / self.udp
        else:
            self.ether_ipv6_udp = self.ether / IPv6(src=Tools.get_local_ipv6(),
                                                    dst=self.args.dhcp_server) / self.udp
        self.duid = DUID_LLT(lladdr=self.mac, timeval=self.xid)
        self.solicit = DHCP6_Solicit(trid=xid)
        self.release = DHCP6_Release(trid=xid)
        self.decline = DHCP6_Decline(trid=xid)
        self.renew = DHCP6_Renew(trid=xid)
        self.opt_client_id = DHCP6OptClientId(duid=self.duid)
        self.opt_ia_na = DHCP6OptIA_NA(iaid=self.xid)
        self.opt_ia_pd = DHCP6OptIA_PD(iaid=self.xid)
        self.request = DHCP6_Request(trid=xid)
        self.opt_server_id = DHCP6OptServerId()
        self.relay_forward = DHCP6_RelayForward(linkaddr=self.args.relay_forward)
        self.make_options = Dhcp6Options(self.args)
        self.options_list = self.make_options.make_options_list()

    def dhcp6_solicit(self):
        """
        制作solicit包
        :return:
        """

        if self.args.na and self.args.pd:
            solicit_pkt = self.ether_ipv6_udp / self.solicit / self.opt_client_id / self.opt_ia_na / self.opt_ia_pd / self.options_list
        elif self.args.pd:
            solicit_pkt = self.ether_ipv6_udp / self.solicit / self.opt_client_id / self.opt_ia_pd / self.options_list
        else:
            solicit_pkt = self.ether_ipv6_udp / self.solicit / self.opt_client_id / self.opt_ia_na / self.options_list

        if self.args.dhcp_server:
            solicit_pkt = self.dhcp6_relay_for_ward(solicit_pkt[DHCP6_Solicit])
            return solicit_pkt

        return solicit_pkt

    def dhcp6_advertise(self):
        pass

    def dhcp6_request(self):
        """
        制作request包
        :return:
        """
        advertise_pkt = pkt_result.get('dhcp6_advertise').get(timeout=self.timeout)
        opt_client_id = advertise_pkt[DHCP6OptClientId]
        request_pkt = self.ether_ipv6_udp / self.request / opt_client_id / self.options_list

        if self.args.dhcp_server:
            request_pkt = self.dhcp6_relay_for_ward(request_pkt[DHCP6_Request])
            return request_pkt
        return request_pkt

    def dhcp6_reply(self):
        pass

    def dhcp6_relay_forward(self):
        pass

    def dhcp6_renew(self):
        """
        制作renew包
        :return:
        """
        reply_pkt = pkt_result.get('dhcp6_reply').get(timeout=self.timeout)
        opt_client_id = reply_pkt[DHCP6OptClientId]
        renew_pkt = self.ether_ipv6_udp / self.renew / opt_client_id / self.options_list
        if self.args.dhcp_server:
            renew_pkt = self.dhcp6_relay_for_ward(renew_pkt[DHCP6_Renew])
            return renew_pkt
        return renew_pkt

    def dhcp6_release(self):
        """
        制作release包
        :return:
        """
        reply_pkt = pkt_result.get('dhcp6_reply').get(timeout=self.timeout)
        opt_client_id = reply_pkt[DHCP6OptClientId]
        release_pkt = self.ether_ipv6_udp / self.release / opt_client_id / self.options_list
        if self.args.dhcp_server:
            release_pkt = self.dhcp6_relay_for_ward(release_pkt[DHCP6_Release])
            return release_pkt
        return release_pkt

    def dhcp6_decline(self):
        """
        制作decline包
        :return:
        """
        reply_pkt = pkt_result.get('dhcp6_reply').get(timeout=self.timeout)
        opt_client_id = reply_pkt[DHCP6OptClientId]
        decline_pkt = self.ether_ipv6_udp / self.decline / opt_client_id / self.options_list
        if self.args.dhcp_server:
            decline_pkt = self.dhcp6_relay_for_ward(decline_pkt[DHCP6_Decline])
            return decline_pkt
        return decline_pkt

    def dhcp6_relay_for_ward(self, pkt=None):
        """
        制作中继包
        :return:
        """
        relay_forward_pkt = self.ether_ipv6_udp / self.relay_forward / DHCP6OptRelayMsg(message=pkt)
        return relay_forward_pkt


class Dhcp4Pkt(Pkt):

    def __init__(self, args: Namespace):
        super(Dhcp4Pkt, self).__init__(args)
        self.make_options = Dhcp4Options(self.args)
        if args.filter:
            self.bootp = BOOTP(chaddr=self.mac, giaddr='0.0.0.0', xid=random.randint(1, 900000000), flags=1)
            self.ether_ip_udp_bootp = Ether(src=str2mac(self.mac), dst='ff:ff:ff:ff:ff:ff') / IP(src='0.0.0.0',
                                                                                                 dst='255.255.255.255') / UDP(
                sport=67, dport=67) / self.bootp
        else:
            self.bootp = BOOTP(chaddr=self.mac, giaddr=self.args.relay_forward, xid=random.randint(1, 900000000),
                               flags=0)
            self.ether_ip_udp_bootp = Ether() / IP(dst=self.args.dhcp_server) / UDP(sport=67, dport=67) / self.bootp

        self.options_list = self.make_options.make_options_list()

    def make_pkts(self, pkt, message_type):
        """
        组装  discover/request/decline/inform报文，
        :param pkt: 接收到的报文
        :param message_type: 请求类型
        :return:
        """
        options = [("message-type", message_type)]
        if message_type == 'discover':
            pass
        else:
            yiaddr = pkt[BOOTP].yiaddr
            options.append(("requested_addr", yiaddr))

        if dict(options).get('requested_addr') and 'requested_addr' in str(self.options_list):
            requested_addr_index = [i for i, d in enumerate(self.options_list) if d[0] == 'requested_addr'][0]
            self.options_list.pop(requested_addr_index)
        for i in self.options_list: options.append(i)
        make_pkt = self.ether_ip_udp_bootp / DHCP(options=options)
        return make_pkt

    def dhcp4_discover(self):
        """
        制作 discover包
        :return:
        """
        discover_pkt = self.make_pkts(None, "discover")
        return discover_pkt

    def dhcp4_offer(self):
        pass

    def dhcp4_request(self):
        """
        制作 request包
        :return:
        """
        if self.args.single:
            options = [('message-type', 'request')]
            for i in self.options_list: options.append(i)
            if dict(options[:-1]).get('requested_addr'):
                request_pkt = self.ether_ip_udp_bootp / DHCP(options=options)
                return request_pkt
            else:
                logs.info("单独request报文不能没有requested_addr，请指定 -o 50=ipv4")
        else:
            offer_pkt = pkt_result.get('dhcp4_offer').get(timeout=self.timeout)
            request_pkt = self.make_pkts(offer_pkt, "request")
            return request_pkt

    def dhcp4_exception_request(self):
        options = [('message-type', 'request'), ('requested_addr', '192.0.0.1'), 'end']
        for i in self.options_list: options.append(i)
        request_pkt = self.ether_ip_udp_bootp / DHCP(options=options)
        return request_pkt

    def dhcp4_ack(self):
        pass

    def dhcp4_decline(self):
        """
        制作 decline包
        :return:
        """
        if self.args.single:
            options = [('message-type', 'decline')]
            for i in self.options_list: options.append(i)
            if dict(options[:-1]).get('requested_addr'):
                decline_pkt = self.ether_ip_udp_bootp / DHCP(options=options)
                return decline_pkt
            else:
                logs.info("单独发送decline报文不能没有requested_addr，请指定 -o 50=ipv4")
        else:
            ack_pkt = pkt_result.get('dhcp4_ack').get(timeout=self.timeout)
            decline_pkt = self.make_pkts(ack_pkt, "decline")
            return decline_pkt

    def dhcp4_release(self):
        """
        制作 release包
        :return:
        """
        ack_pkt = pkt_result.get('dhcp4_ack').get(timeout=self.timeout)
        release_pkt = self.make_pkts(ack_pkt, "release")
        return release_pkt

    def dhcp4_inform(self):
        """
        制作 inform包
        :return:
        """
        if self.args.single:
            options = [('message-type', 'inform')]
            for i in self.options_list: options.append(i)
            if dict(options[:-1]).get('requested_addr'):
                inform_pkt = self.ether_ip_udp_bootp / DHCP(options=options)
                return inform_pkt
            else:
                logs.info("单独发送inform报文不能没有requested_addr，请指定 -o 50=ipv4")
        else:
            ack_pkt = pkt_result.get('dhcp4_ack').get(timeout=self.timeout)
            inform_pkt = self.make_pkts(ack_pkt, "inform")
            return inform_pkt
