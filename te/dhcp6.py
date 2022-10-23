# -*- coding: utf-8 -*-
# @Time    : 2022/10/23 19:45
# @Author  : mf.liang
# @File    : dhcp6.py
# @Software: PyCharm
# @desc    :
# coding = 'utf-8'
"""
@File:          dhcp6_tools.py
@Time:          2022/8/15 11:28
@Author:        mf.liang
@Email:         mf.liang@yamu.com
@Desc:          请注明模块要实现的功能

"""
import argparse
import random
import re
import subprocess
import threading

import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import sleep

from scapy.layers.dhcp6 import DUID_LLT, DHCP6_Solicit, DHCP6OptClientId, DHCP6OptIA_NA, VENDOR_CLASS_DATA, DHCP6_Reply, \
    dhcp6_cls_by_type, dhcp6types, DHCP6OptIA_PD, DHCP6_Request, DHCP6OptServerId, DHCP6_Release, DHCP6OptElapsedTime, \
    DHCP6_Renew, DHCP6OptVendorClass, DHCP6_RelayForward, DHCP6OptRelayMsg, DHCP6OptIfaceId, DHCP6_RelayReply, \
    DHCP6OptStatusCode
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.all import *

# 默认变量-------------------------------------------------------------------------------------------
# 获取本机ipv6
ipv6_src = subprocess.Popen("ip -6 address show | grep inet6 | awk '{print $2}' | cut -d'/' -f1",
                            shell=True, stdout=subprocess.PIPE)
ipv6_src = str(ipv6_src.stdout.readlines()[1], encoding='utf-8').strip('\n')
# 客户端mac地址  (重用曾经分配的IP地址，更改这个选项)（更新租约,更改这个选项为当前mac）
random_mac = RandMAC()
# 事务id(可选)
xid = random.randint(1, 900000000)
# duid
myduid = DUID_LLT(lladdr=mac2str(random_mac), timeval=xid)
# udp
Ether_IPv6_UDP = Ether() / IPv6(src=ipv6_src, dst='ff02::1:2') / UDP()
# 线程锁
tn = threading.Lock()
# 接收抓包数据
thead_data_list = []


def parse_cmd_args():
    """
    创建命令行解析器句柄，并自定义描述信息
    :return:
    """
    parser = argparse.ArgumentParser(description="DHCP IPV6发包")
    parser.add_argument("--num", "-n", help="发包数量", default=1)
    parser.add_argument("--options", "-o", help="""-o '{"option1":{"id":"${id}"},"option2":{"id":1234}}'""",
                        default=None)
    parser.add_argument("--ipv6_src", "-src", help='指定ipv6源ip,例如: -src "1000::31:350:9640:be36:46f6"',
                        default=ipv6_src)
    parser.add_argument("--message_type", "-mt", help='发送指定类型报文如：solicit,request,renew', default='default')
    parser.add_argument("--na_pd", "-np", help='0:前缀模式, 1:后缀模式, 2:前+后缀模式', default=0)
    parser.add_argument("--show", "-show", help='查看详细请求过程,默认为 0/False, 1/True', default=0)
    parser.add_argument("--file_path", "-fp", help='指定pcap文件,目前与rennew搭配使用', default=None)
    parser.add_argument("--data", "-d", help='自定义入参', default=None)
    parser.add_argument("--mac", "-mac", help='指定mac地址进行发流', default=random_mac)
    parser.add_argument("--filter", "-f", required=True, default=None,
                        help='tcpdump过滤条件，用于接收返回值过滤，必须指定发送方得mac地址,如:  -f "1000:0:0:30::1" ')

    args = parser.parse_args()
    return vars(args)


params = parse_cmd_args()
# 接收变量---------------------------------------------------------------------------------------------------------------

# 发包数量
send_num = int(params.get('num'))
# 探析抓包过滤
filter = params.get('filter')
# 发送指定报文
message_type = params.get('message_type')
# 前缀/后缀模式
np = int(params.get('na_pd'))
# 自定义option
options = params.get('options')
# 指定mac地址
cmac = params.get('mac')
# 自定义入参
data = params.get('data')

# 传入的文件
file_path = params.get('file_path')
# 汇总测试结果
res = {}


class Option:

    @staticmethod
    def option16():
        """

        suxx@suxx:     1f31014d65822107fcfd520000000062f5c046673a94562464a0b5172b521560f4614ad018626532955a6dd9ea9db4a23ca2be
        :return:
        """
        user_pwd = data[4:]
        try:
            # myduid = DUID_LLT(lladdr=mac2str(cmac), timeval=xid)
            vendor_class_data = VENDOR_CLASS_DATA(data=bytes.fromhex(user_pwd))
            # option16_pkt = DHCP6OptClientId(duid=myduid) / DHCP6OptIA_NA(iaid=xid) / DHCP6OptVendorClass(
            #     vcdata=vendor_class_data)
            option16_pkt = DHCP6OptVendorClass(vcdata=vendor_class_data)

        except Exception as ex:
            print(ex)
            return
        return option16_pkt

    @staticmethod
    def option18():
        """
        suxx@suxx:      eth 2/1/4:80.90 ZTEOLT001/1/1/5/0/1/
        :return:
        """
        face_id = data
        option18_pkt = DHCP6OptIfaceId(ifaceid=face_id)
        return option18_pkt


class Tool:

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
    def parse_pcap(file_path, filter_type):
        """
        解析pcap文件
        :param file_path:
        :param filter_type:
        :return:
        """
        if file_path:
            pkts = sniff(offline=file_path)
            pkts_list = []
            for i in pkts:
                req_type = eval(i.summary().split('/')[3].strip())
                if i[IPv6].src == filter or i[IPv6].dst == filter:
                    if i[req_type].msgtype == filter_type[0]:
                        pkts_list.append(i)
                    if i[req_type].msgtype == filter_type[1]:
                        try:
                            if i[DHCP6_Reply]:
                                pkts_list.append(i)
                        except:
                            pass
            return pkts_list

    @staticmethod
    def verify_sniff_data(pkts_data, pkt_type):
        """
        自定义过滤条件
        :param pkts_data:
        :return:
        """

        pkts_list = []
        for i in pkts_data:
            req_type = eval(i.summary().split('/')[3].strip())
            if i[IPv6].src == filter:
                if i[req_type].msgtype == pkt_type:
                    pkts_list.append(i)
        return pkts_list

    @staticmethod
    def get_sniff(pkt_type):
        """
        执行探嗅任务，返回抓包结果分析
        :return:
        """

        filter_cmd = f'port 547 and host {filter}'
        pkts = sniff(filter=filter_cmd, count=send_num * 2, timeout=3)
        pkts = Tool.verify_sniff_data(pkts, pkt_type)
        if pkts:
            Tool.get_result(pkts[-1])
        for i in pkts:
            thead_data_list.append(i)
        return pkts

    @staticmethod
    def get_result(pkt):
        """
        计算最终结果,及打印请求信息
        :param pkt:
        :param status:
        :return:
        """
        for i in pkt:
            req_type = i.summary().split('/')[3].strip()
            req_type = req_type.split('_')[1].upper()
            for cls_dhcp6, dhcp6_type in zip(dhcp6_cls_by_type.values(), dhcp6types.values()):
                dhcp6_types = ''.join(re.findall(r'[A-Za-z]', dhcp6_type))
                if dhcp6_types in req_type:
                    res[dhcp6_type] += 1
            if params.get('show'):
                i.show()
            else:
                print(i.summary(), '\n', i.mysummary(), '请求类型:', req_type)

    @staticmethod
    def make_options(options):
        option16 = Option.option16()
        option18 = Option.option18()
        option_pkt = eval(options)
        return option_pkt


class Pkt:

    def __init__(self):
        self.ether_ipv6_udp = Ether() / IPv6(src=ipv6_src, dst='ff02::1:2') / UDP()
        self.solicit = DHCP6_Solicit(trid=random.randint(1, 900000000))
        self.release = DHCP6_Release(trid=random.randint(1, 900000000))
        self.opt_client_id = DHCP6OptClientId(duid=DUID_LLT(lladdr=mac2str(cmac), timeval=xid))
        self.opt_ia_na = DHCP6OptIA_NA(iaid=random.randint(1, 900000000))
        self.opt_ia_pd = DHCP6OptIA_PD(iaid=random.randint(1, 900000000))
        self.request = DHCP6_Request(trid=random.randint(1, 900000000))
        self.request = DHCP6_Request(trid=random.randint(1, 900000000))
        self.opt_server_id = DHCP6OptServerId()
        self.relay_forward = DHCP6_RelayForward(linkaddr=filter)

    def dhcp6_relay_forward(self, pkts, pkt_type):
        Tool.get_result(pkts)
        if pkt_type == 'solicit':
            pkt = pkts[DHCP6_Solicit]
        elif pkt_type == 'request':
            pkt = pkts[DHCP6_Request]
        else:
            print('未知的类型!!!')

        relay_msg = DHCP6OptRelayMsg(message=pkt)

        if options:
            relay_forward_pkt = self.ether_ipv6_udp / self.relay_forward / options_pkt / relay_msg
        else:
            relay_forward_pkt = self.ether_ipv6_udp / self.relay_forward / relay_msg
        return relay_forward_pkt

    def dhcp6_release(self, pkt):
        """
        生成dhcp6 release包
        :param server_id_pkt:
        :return:
        """
        opt_client_id = pkt[DHCP6OptClientId]
        release_pkt = self.ether_ipv6_udp / self.release / opt_client_id
        return release_pkt

    def dhcp6_solicit(self):
        """
        生成dhcp6 solicit包
        :param ms_type:
        :return:
        """
        self.__init__()

        def options_pkt_func():
            if options and 'relay' not in message_type:
                return options_pkt
            else:
                return DHCP6OptStatusCode()

        if np == 1:  # PD模式
            solicit_pkt = self.ether_ipv6_udp / self.solicit / self.opt_client_id / self.opt_ia_pd / options_pkt_func()
        elif np == 2:  # NA+PD模式
            solicit_pkt = self.ether_ipv6_udp / self.solicit / self.opt_client_id / self.opt_ia_na / self.opt_ia_pd / options_pkt_func()
        else:  # NA模式
            solicit_pkt = self.ether_ipv6_udp / self.solicit / self.opt_client_id / self.opt_ia_na / options_pkt_func()
        return solicit_pkt

    def dhcp6_request(self, pkt):
        """
        生成dhcp6 request包
        :param pkt:
        :return:
        """
        opt_client_id = pkt[DHCP6OptClientId]
        opt_server_id = pkt[DHCP6OptServerId]
        if options and 'relay' not in message_type:
            request_pkt = self.ether_ipv6_udp / self.request / opt_server_id / opt_client_id / options_pkt
        else:
            request_pkt = self.ether_ipv6_udp / self.request / opt_client_id
        return request_pkt

    def dhcp6_renew(self, pkt):
        """
        生成dhcp6 renew包
        :param pkt:
        :return:
        """
        opt_client_id = pkt[DHCP6OptClientId]
        renew_pkt = Ether_IPv6_UDP / DHCP6_Renew(trid=xid) / opt_client_id
        return renew_pkt


class Send_Pkt:
    def __init__(self):
        self.dhcp6_pkts = Pkt()
        self.dhcp6types = {v: k for k, v in dhcp6types.items()}
        self.relay_pkts = Tool.parse_pcap(file_path, [self.dhcp6types.get('REPLY'), self.dhcp6types.get('RELAY-REPL')])

    def send_pkt(self, pkt, send_type, pkt_type=None):
        if send_type == 'solicit':
            pkt = self.dhcp6_pkts.dhcp6_solicit()
        elif send_type == 'request':
            pkt = self.dhcp6_pkts.dhcp6_request(pkt)
        elif send_type == 'renew':
            pkt = self.dhcp6_pkts.dhcp6_renew(pkt)
        elif send_type == 'release':
            pkt = self.dhcp6_pkts.dhcp6_release(pkt)
        elif send_type in 'relay_forward':
            if pkt_type == 'solicit':
                pkt = self.dhcp6_pkts.dhcp6_solicit()
            if pkt_type == 'request':
                pkt = pkt[DHCP6_RelayReply]
                pkt = self.dhcp6_pkts.dhcp6_request(pkt)

            pkt = self.dhcp6_pkts.dhcp6_relay_forward(pkt, pkt_type)
        # 记录并打印
        Tool.get_result(pkt)
        # 发送包
        sendp(pkt)

    def dhcp6_relay_forward(self, send_type):
        with ThreadPoolExecutor(max_workers=1) as e:
            # 创建抓包线程监听抓包
            sniff_res = e.submit(Tool.get_sniff, self.dhcp6types.get('RELAY-REPL'))
            sleep(10 / 1000)
            with ThreadPoolExecutor(max_workers=send_num) as e:
                """创建发送solicit消息的线程池"""
                if send_type == 'solicit':
                    thead_res = [e.submit(self.send_pkt, i, 'relay_forward', send_type) for i in range(send_num)]
                elif send_type == 'request':
                    thead_res = [e.submit(self.send_pkt, i, 'relay_forward', send_type) for i in thead_data_list]
                for i in as_completed(thead_res):
                    i.result()

    def dhcp6_release(self):
        filter_type = [self.dhcp6types.get('REPLY'), self.dhcp6types.get('RELAY-REPL')]
        relay_pkts = Tool.parse_pcap(file_path, filter_type)
        with ThreadPoolExecutor(max_workers=1) as e:
            # 创建抓包线程监听抓包
            sniff_res = e.submit(Tool.get_sniff, self.dhcp6types.get('REPLY'))
            sleep(10 / 1000)
            with ThreadPoolExecutor(max_workers=send_num) as e:
                """创建发送solicit消息的线程池"""
                thead_res = [e.submit(self.send_pkt, i, 'release') for i in relay_pkts]
                for i in as_completed(thead_res):
                    i.result()

            res.update({'REPLY': len(sniff_res.result())})

    def dhcp6_solicit(self):
        with ThreadPoolExecutor(max_workers=1) as e:
            # 创建抓包线程监听抓包
            sniff_res = e.submit(Tool.get_sniff, self.dhcp6types.get('ADVERTISE'))
            sleep(10 / 1000)
            with ThreadPoolExecutor(max_workers=send_num) as e:
                """创建发送solicit消息的线程池"""
                thead_res = [e.submit(self.send_pkt, i, 'solicit') for i in range(send_num)]
                for i in as_completed(thead_res):
                    i.result()
            res.update({'REPLY': len(sniff_res.result())})

    def dhcp6_request(self):
        with ThreadPoolExecutor(max_workers=1) as e:
            # 创建抓包线程监听抓包
            sniff_res = e.submit(Tool.get_sniff, self.dhcp6types.get('REPLY'))
            sleep(10 / 1000)
            with ThreadPoolExecutor(max_workers=send_num) as e:
                """创建发送solicit消息的线程池"""
                thead_res = [e.submit(self.send_pkt, i, 'request') for i in thead_data_list]
                for i in as_completed(thead_res):
                    i.result()

            res.update({'REPLY': len(sniff_res.result())})

    def dhcp6_renew(self):
        filter_type = [self.dhcp6types.get('REPLY'), self.dhcp6types.get('RELAY-REPL')]
        relay_pkts = Tool.parse_pcap(file_path, filter_type)
        with ThreadPoolExecutor(max_workers=1) as e:
            # 创建抓包线程监听抓包
            sniff_res = e.submit(Tool.get_sniff, self.dhcp6types.get('REPLY'))
            sleep(5 / 1000)
            with ThreadPoolExecutor(max_workers=send_num) as e:
                """创建发送solicit消息的线程池"""
                thead_res = [e.submit(self.send_pkt, i, 'renew') for i in relay_pkts]
                for i in as_completed(thead_res):
                    i.result()

            res.update({'REPLY': len(sniff_res.result())})


def run():
    # 初始化汇总信息
    for i in dhcp6types.values(): res[i] = 0

    # 初始化发送 对象
    send = Send_Pkt()
    # for i in range(send_num):
    if message_type in 'default':
        send.dhcp6_solicit()
        send.dhcp6_request()
    if message_type in 'solicit':
        send.dhcp6_solicit()
    if message_type in 'renew':
        send.dhcp6_renew()
    if message_type in 'release':
        send.dhcp6_release()
    if 'relay' in message_type:
        send.dhcp6_relay_forward('solicit')
        send.dhcp6_relay_forward('request')
    print('\n', res)


if __name__ == '__main__':
    # 动态制作option
    if options: options_pkt = Tool.make_options(options)
    run()
