# -*- coding: utf-8 -*-
# @Time    : 2022/10/23 19:48
# @Author  : mf.liang
# @File    : dhcp4.py
# @Software: PyCharm
# @desc    :
import argparse
import random
import socket
import uuid

from scapy.layers.dhcp import DHCP, BOOTP, dhcp_request, DHCPTypes
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import ls
from scapy.sendrecv import srp1
from scapy.utils import mac2str
from scapy.volatile import RandMAC

# 获取本机IP
local_ip = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
local_ip.connect(('8.8.8.8', 80))
local_ip = local_ip.getsockname()[0]


def parse_cmd_args():
    # 创建命令行解析器句柄，并自定义描述信息
    parser = argparse.ArgumentParser(description="DHCP IPV4发包")
    parser.add_argument("--num", "-n", help="发包数量")
    parser.add_argument("--dhcp_server", "-s", help="指定DHCP服务器")
    parser.add_argument("--chaddr", "-c", help="指定Client的MAC地址.更新租约使用上次分配过的地址")
    parser.add_argument("--giaddr", "-g", help="指定中继服务器")
    parser.add_argument("--flags", "-f", help="单播:0/广播:1")
    parser.add_argument("--options", "-o", help='添加option,格式：hostname=yamu&option_name=value')
    parser.add_argument("--message_type", "-mt", help='发送指定类型报文如：discover,request')
    # 返回一个命名空间
    args = parser.parse_args()
    return vars(args)


params = parse_cmd_args()

# 发包数量
send_num = int(params.get('num') if params.get('num') else 1)
# dhcp服务器
dhcp_server_ipv4 = params.get('dhcp_server') if params.get('dhcp_server') else '255.255.255.255'
# 本机mac
address = ':'.join(hex(uuid.getnode())[2:][i:i + 2] for i in range(0, len(hex(uuid.getnode())[2:]), 2))
# 事务id(可选)
xid = random.randint(1, 900000000)
# 主机名（可选）
hostname = '192.168.31.135'
# 客户端mac地址  (重用曾经分配的IP地址，更改这个选项)（更新租约,更改这个选项为当前mac）
random_mac = params.get('chaddr') if params.get('chaddr') else RandMAC()
# 中继服务器
giaddr = params.get('giaddr') if params.get('giaddr') else local_ip
# 单播:0/广播:1
flags = int(params.get('flags') if params.get('flags') else 0)
# 指定options
options = params.get('options') if params.get('options') else 'hostname=yamu'
if options: options = [tuple(i.split('=')) for i in options.split('&')]
# 发送指定报文
message_type = params.get('message_type') if params.get('message_type') else 'default'


def send_discover():
    """
    发送discover请求，并获取offer里的分配地址
    :return:
    """
    myoptions = [
        ("message-type", "discover"),
        "end"
    ]
    myoptions = myoptions + options
    discover = DHCP(options=myoptions)

    dhcp_attack_packet_discover = Ether_IP_UDP_BOOTP / discover
    get_result(dhcp_attack_packet_discover, dhcp_attack_packet_discover[DHCP].options[0][1])

    offer = srp1(dhcp_attack_packet_discover)

    get_result(offer, DHCPTypes.get(offer[DHCP].options[0][1]))
    yiaddr = offer[BOOTP].yiaddr
    print(f"申请ip-------------------->{yiaddr}")
    return yiaddr


def send_request(yiaddr):
    """
    发起request请求,获取ack信息
    :return:
    """
    request_option = [
        ("message-type", 'request'),
        ("requested_addr", yiaddr),
        "end"
    ]
    request = DHCP(options=request_option)
    dhcp_attack_packet_request = Ether_IP_UDP_BOOTP / request
    get_result(dhcp_attack_packet_request, dhcp_attack_packet_request[DHCP].options[0][1])
    ack = srp1(dhcp_attack_packet_request)
    status = ack[DHCP].options[0][1]
    get_result(ack, DHCPTypes.get(status))
    return DHCPTypes.get(status)


def get_result(pkt, status):
    """
    计算最终结果,及打印请求信息
    :param pkt:
    :param status:
    :return:
    """
    print(pkt.summary(), pkt.mysummary(), "请求类型:", status.upper())
    for i in res.keys():
        if status == i:
            res[i] += 1


if __name__ == '__main__':
    res = {}
    for i in DHCPTypes.values():
        res[i] = 0
    for i in range(send_num):
        # 定义数据包
        Ether_IP_UDP_BOOTP = (Ether() / IP(dst=dhcp_server_ipv4) / UDP(sport=68, dport=67)
                              / BOOTP(chaddr=mac2str(random_mac), giaddr=giaddr, xid=xid, flags=flags))

        if message_type == DHCPTypes.get(1):
            # 发送discover
            yiaddr = send_discover()
        else:
            # 发送discover ,request
            yiaddr = send_discover()
            status = send_request(yiaddr)
        print('=' * 100)
    print('\n', res)
