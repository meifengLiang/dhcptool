# -*- coding: utf-8 -*-
# @Time    : 2022/10/23 18:56
# @Author  : mf.liang
# @File    : tools.py
# @Software: PyCharm
# @desc    :
import collections
import hashlib
import json
import re
import socket
import subprocess
from inspect import getmodule, stack
from scapy.layers.dhcp import DHCPTypes, DHCP, BOOTP
from scapy.layers.dhcp6 import dhcp6types, DHCP6OptIAAddress, DHCP6OptRelayMsg, DHCP6OptIAPrefix
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.utils import mac2str, str2mac
from scapy.volatile import RandMAC
from env_args import pkt_result, logs, summary_result, global_var
import time


class Tools:

    @staticmethod
    def mac_self_incrementing(mac, num, offset=1):
        """
        mac自增
        :param mac:
        :param num:
        :param offset:
        :return:
        """
        mac = ''.join(mac.split(':'))

        #  使用format格式化字符串，int函数，按照16进制算法，将输入的mac地址转换成十进制，然后加上偏移量
        # {:012X}将十进制数字，按照16进制输出。其中12表示只取12位，0表示不足的位数在左侧补0
        mac_address = "{:012X}".format(int(mac, 16) + offset * num)
        mac_address = ':'.join(re.findall('.{2}', mac_address)).lower()
        return mac_address

    @staticmethod
    def get_mac(args: dict = None):
        """
        获取mac信息
        :return:

        """
        if args.get('mac') is not None:
            mac = Tools.mac_self_incrementing(args.get('mac'), global_var.get('tag'))
        else:
            mac = mac2str(RandMAC())
        global_var.update({"generate_mac": mac})
        return mac

    @staticmethod
    def get_xid_by_mac(mac):
        """
        根据mac生成hash
        :return:
        """
        mac = str2mac(mac).encode('utf-8')
        m = hashlib.md5()
        m.update(mac)
        mac_xid = int(str(int(m.hexdigest(), 16))[0:9])
        return mac_xid

    @staticmethod
    def convert_code(data):
        """
        字节/16进制相互转换
        :param data:
        :return:
        """
        if isinstance(data, bytes):  # 转 16进制
            data = data.hex()
        else:  # 字符串转化成字节码
            data = bytes.fromhex(data)
        return data

    @staticmethod
    def get_local_ipv4():
        # 获取本机IP
        local_ipv4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        local_ipv4.connect(('8.8.8.8', 80))
        local_ipv4 = local_ipv4.getsockname()[0]
        logs.info(f"获取本机IP:\t{local_ipv4}")
        return local_ipv4

    @staticmethod
    def get_local_ipv6():
        # 获取本机ipv6
        local_ipv6 = subprocess.Popen("ip -6 address show | grep inet6 | awk '{print $2}' | cut -d'/' -f1",
                                      shell=True, stdout=subprocess.PIPE)
        local_ipv6 = str(local_ipv6.stdout.readlines()[1], encoding='utf-8').strip('\n')
        return local_ipv6

    @staticmethod
    def analysis_results(pkts_list, DHCPv6=None, args: dict = None, call_name=None):
        """
        解析结果并存入队列
        :param args:
        :param pkts_list:
        :param DHCPv6:
        :param filter:
        :return:
        """
        if args.get('dhcp_server') == 'ff02::1:2':
            filter = args.get('filter')
        else:
            filter = args.get('dhcp_server')

        # filter = args.get('dhcp_server')
        debug = args.get('debug')
        call_func_name = getmodule(stack()[1][0])
        call_mod = call_func_name.__name__
        for i in pkts_list:
            if 'dhcp4' in call_mod:
                if i[IP].src == filter:
                    if i[DHCP].options[0][1] == 2:
                        pkt_result.get('dhcp4_offer').put(i)
                        Tools.print_formart(i, debug)
                    elif i[DHCP].options[0][1] == 5:
                        pkt_result.get('dhcp4_ack').put(i)
                        Tools.print_formart(i, debug)

                else:
                    logs.info('没有监听到 server 返回 结果！,请检查是否有多个DHCP server影响监听结果')
            else:
                if i[IPv6].src == filter:
                    if i[DHCPv6].msgtype == 2:
                        try:
                            assert i[DHCP6OptIAAddress].addr
                            pkt_result.get('dhcp6_advertise').put(i)
                            if call_name is None:
                                Tools.print_formart(i, debug)
                        except Exception as ex:
                            try:
                                assert i[DHCP6OptIAPrefix].prefix
                                pkt_result.get('dhcp6_advertise').put(i)
                                if call_name is None:
                                    Tools.print_formart(i, debug)
                            except Exception as ex:
                                logs.error('返回包中没有携带分配ip！')
                                assert False

                    elif i[DHCPv6].msgtype == 7:
                        pkt_result.get('dhcp6_reply').put(i)
                        if call_name is None:
                            Tools.print_formart(i, debug)

                    elif i[DHCPv6].msgtype == 13:
                        ether_ipv6_udp = Ether() / IPv6(src=i[IPv6].src) / UDP()
                        relay_pkt = ether_ipv6_udp / i[DHCP6OptRelayMsg].message
                        Tools.analysis_results(pkts_list=relay_pkt, args=args, call_name=1)
                        Tools.print_formart(i, debug)

                else:
                    logs.info('没有监听到 server 返回 结果！,请检查是否有多个DHCP server影响监听结果')

    @staticmethod
    def print_formart(pkt, level='off'):
        """
        格式化打印
        :param pkt:
        :param level:
        :return:
        """
        response_dict = {}
        if level == 'off':
            replx = '(\/)|(:dhcpv6_server)|(:bootps)|(DHCP6OptClientId)|(:dhcpv6_client)|(DHCP6OptServerId)|' \
                    '(DHCP6OptIA_NA)|(DHCP6OptIA_PD)|(DHCP6OptStatusCode)|(DHCP6OptRelayMsg)'
            txt, n = re.subn(replx, '', pkt.summary())
            detail_info = ' '.join(list(filter(None, txt.split(' ')))[3:])
            response_dict.update({"info": detail_info})
            if pkt.payload.name == 'IPv6':
                try:
                    addr = pkt[DHCP6OptIAAddress].addr
                    response_dict.update({"addr": addr})
                    prefix = pkt[DHCP6OptIAPrefix].prefix
                    response_dict.update({"prefix": prefix})
                except Exception as ex:
                    if 'DHCP6OptIAAddress' in str(ex):
                        try:
                            prefix = pkt[DHCP6OptIAPrefix].prefix
                            response_dict.update({"prefix": prefix})
                        except:
                            pass
            else:
                yiaddr = pkt[BOOTP].yiaddr
                response_dict.update({"yiaddr": yiaddr})
            mac = str2mac(global_var.get('generate_mac')) or ''
            if response_dict.get('yiaddr'):
                content_format = "{:<} | yiaddr: {:<15} | {:<}".format(
                    mac, response_dict.get('yiaddr') or '', response_dict.get('info') or '')
            else:
                content_format = "{:<} | addr: {:<15} | prefix: {:<} | {:<}".format(
                    mac, response_dict.get('addr') or '', response_dict.get('prefix') or '',
                         response_dict.get('info') or '')
            logs.info(content_format)
        else:
            logs.info(str(pkt.show()))
        Tools.record_pkt_num(pkt)

    @staticmethod
    def record_pkt_num(pkt, DHCPv6=None):
        try:
            for i in dhcp6types:
                # TODO: 需要断言返回的包中是否带有分配的ip
                if pkt[DHCPv6].msgtype == i:
                    summary_result[dhcp6types.get(i)] += 1
                    if pkt[DHCPv6].msgtype in (12, 13):
                        Tools.record_pkt_num(pkt[DHCP6OptRelayMsg].message)
        except:
            for v in DHCPTypes.values():
                pkt_type = pkt[DHCP].options[0][1]
                if isinstance(pkt_type, int):
                    pkt_type = DHCPTypes.get(pkt_type)
                if pkt_type == v:
                    summary_result[v] += 1

    @staticmethod
    def rate_print(text_tips, sleep_time):
        """
        倒计时打印
        :param text_tips:
        :param sleep_time:
        :return:
        """
        if sleep_time != 0:
            for i in range(sleep_time, 0, -1):
                print("\r", text_tips, '倒计时', "{}".format(i), '', end="", flush=True)
                time.sleep(1)
