# -*- coding: utf-8 -*-
# @Time    : 2022/10/23 18:56
# @Author  : mf.liang
# @File    : tools.py
# @Software: PyCharm
# @desc    :
import logging
import socket
import subprocess
from scapy.layers.inet6 import IPv6
from env_args import pkt_result, logs


class Tools:

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
        logging.debug(f"获取本机IP:\t{local_ipv4}")
        return local_ipv4

    @staticmethod
    def get_local_ipv6():
        # 获取本机ipv6
        local_ipv6 = subprocess.Popen("ip -6 address show | grep inet6 | awk '{print $2}' | cut -d'/' -f1",
                                      shell=True, stdout=subprocess.PIPE)
        local_ipv6 = str(local_ipv6.stdout.readlines()[1], encoding='utf-8').strip('\n')
        return local_ipv6

    @staticmethod
    def analysis_results(pkts_list, DHCPv6=None, filter: str = None):
        """
        解析结果并存入队列
        :param pkts_list:
        :param DHCPv6:
        :param filter:
        :return:
        """
        for i in pkts_list:
            if i[IPv6].src == filter and i[DHCPv6].msgtype == 2:
                # i.show()
                pkt_result.get('dhcp6_advertise').put(i)

            elif i[IPv6].src == filter and i[DHCPv6].msgtype == 7:
                # i.show()
                pkt_result.get('dhcp6_reply').put(i)

            else:
                logging.info('没有监听到 server 返回 结果！,请检查是否有多个DHCP server影响监听结果')
                # self.send_dhcp6_pkt(pkt)

    @staticmethod
    def print_formart(pkt, level='off'):
        """
        格式化打印
        :param pkt:
        :param level:
        :return:
        """
        if level == 'off':
            logs.debug(pkt.summary())
        else:
            logs.debug(str(pkt.show()))