# -*- coding: utf-8 -*-
# @Time    : 2022/10/23 19:06
# @Author  : mf.liang
# @File    : dhcp4_controller.py
# @Software: PyCharm
# @desc    :
from scapy.layers.dhcp import DHCPTypes

from env_args import summary_result


class Dhcp4Controller:

    def __init__(self, args):
        self.args = args

    def run(self):
        for i in DHCPTypes.values(): summary_result[i] = 0

    def send_discover_offer_request_ack(self):
        """
        发送  dhcp4 完整分配流程
        :return:
        """

    def send_decline(self):
        """

        :return:
        """
        pass

    def send_release(self):
        """

        :return:
        """
        pass