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
from tools import Tools


class Dhcp6Controller(Dhcp6Pkt):

    def __init__(self, args):
        super(Dhcp6Controller, self).__init__(args)
        self.args = args


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
        solicit_pkt = self.dhcp6_solicit()
        res = self.send_dhcp6_pkt(solicit_pkt, filter=self.args.get('filter'))
        Tools.analysis_results(pkts_list=res, filter=self.args.get('filter'))

        request_pkt = self.dhcp6_request()
        res = self.send_dhcp6_pkt(request_pkt, filter=self.args.get('filter'))
        Tools.analysis_results(pkts_list=res, filter=self.args.get('filter'))

    def send_release(self):
        pass

    def send_renew(self):
        pass

    def send_decline(self):
        pass
