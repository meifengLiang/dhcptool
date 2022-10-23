# -*- coding: utf-8 -*-
# @Time    : 2022/10/23 19:06
# @Author  : mf.liang
# @File    : dhcp6_controller.py
# @Software: PyCharm
# @desc    :
from scapy.layers.dhcp6 import dhcp6types

from env_args import summary_result


class Dhcp6Controller:

    def __init__(self, args):
        self.args = args

    def run(self):
        for i in dhcp6types.values(): summary_result[i] = 0

    def send_solicit_advertise_request_reply(self):
        """
        发送  dhcp6 完整分配流程
        :return:
        """
        pass

    def send_release(self):
        pass

    def send_renew(self):
        pass

    def send_decline(self):
        pass


