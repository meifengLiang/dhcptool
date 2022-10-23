# -*- coding: utf-8 -*-
# @Time    : 2022/10/23 19:06
# @Author  : mf.liang
# @File    : dhcp6_controller.py
# @Software: PyCharm
# @desc    :
import logging

from scapy.layers.dhcp6 import dhcp6types

from dhcp_pkt import Dhcp6Pkt
from env_args import summary_result


class Dhcp6Controller:

    def __init__(self, args):
        self.args = args
        self.pkt = Dhcp6Pkt()

    def run(self):
        logging.debug('初始化汇总结果')
        for i in dhcp6types.values(): summary_result[i] = 0

        for i in range(int(self.args.get('num'))):
            self.send_solicit_advertise_request_reply()

    def send_solicit_advertise_request_reply(self):
        """
        发送  dhcp6 完整分配流程
        :return:
        """
        self.pkt.dhcp6_solicit()

    def send_release(self):
        pass

    def send_renew(self):
        pass

    def send_decline(self):
        pass
