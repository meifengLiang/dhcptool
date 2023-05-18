# -*- coding: utf-8 -*-
# @Time    : 2022/10/23 19:06
# @Author  : mf.liang
# @File    : dhcp4_controller.py
# @Software: PyCharm
# @desc    :
import json
from scapy.layers.dhcp import DHCPTypes
from dhcp_pkt import Dhcp4Pkt
from env_args import summary_result, logs, pkt_result, global_var
from tools import Tools


class Dhcp4Controller(Dhcp4Pkt):

    def __init__(self, args):
        super(Dhcp4Controller, self).__init__(args)
        self.args = args

    def run(self):
        """
        执行 发包测试入口
        :return:
        """
        message_type = self.args.get('message_type')

        for i in DHCPTypes.values():
            summary_result[i] = 0

        for i in range(int(self.args.get('num'))):
            global_var['tag'] = i
            try:
                if message_type == 'default':
                    self.send_discover_offer_request_ack()
                elif message_type == 'renew':
                    self.send_discover_offer_request_ack_renew()
                elif message_type == 'release':
                    self.send_discover_offer_request_ack_release()
                elif message_type == 'inform':
                    if self.args.get('single'):
                        self.send_inform()
                    else:
                        self.send_discover_offer_request_ack_inform()
                elif message_type == 'request':
                    self.send_request()
                elif message_type == 'nak':
                    self.send_discover_offer_request_nak()
                else:
                    self.send_discover_offer_request_ack_decline()
            except:
                pass

            print('-' * 100)
            pkt_result.get('dhcp4_ack').queue.clear()
        logs.info(json.dumps(summary_result, indent=4))

    def send_discover_offer_request_ack(self):
        """
        发送  dhcp4 完整分配流程
        :return:
        """
        self.__init__(self.args)
        discover_pkt = self.dhcp4_discover()
        res = self.send_dhcp4_pkt(discover_pkt, args=self.args)
        Tools.analysis_results(pkts_list=res, args=self.args)

        request_pkt = self.dhcp4_request()
        ack_pkt = self.send_dhcp4_pkt(request_pkt, args=self.args)
        Tools.analysis_results(pkts_list=ack_pkt, args=self.args)

    def send_discover_offer_request_nak(self):
        """
        发送  dhcp4 完整分配流程
        :return:
        """
        self.__init__(self.args)
        discover_pkt = self.dhcp4_discover()
        res = self.send_dhcp4_pkt(discover_pkt, args=self.args)
        Tools.analysis_results(pkts_list=res, args=self.args)

        request_pkt = self.dhcp4_exception_request()
        ack_pkt = self.send_dhcp4_pkt(request_pkt, args=self.args)
        Tools.analysis_results(pkts_list=ack_pkt, args=self.args)

    def send_discover_offer_request_ack_renew(self):
        """
        发起 更新租约 请求
        :return:
        """
        self.__init__(self.args)
        discover_pkt = self.dhcp4_discover()
        res = self.send_dhcp4_pkt(discover_pkt, args=self.args)
        Tools.analysis_results(pkts_list=res, args=self.args)
        request_pkt = self.dhcp4_request()
        ack_pkt = self.send_dhcp4_pkt(request_pkt, args=self.args)
        Tools.analysis_results(pkts_list=ack_pkt, args=self.args)
        Tools.rate_print('租约更新', self.args.get('sleep_time'))
        ack_pkt = self.send_dhcp4_pkt(request_pkt, args=self.args)
        Tools.analysis_results(pkts_list=ack_pkt, args=self.args)

    def send_discover_offer_request_ack_decline(self):
        """
        发起 冲突租约 请求
        :return:
        """
        self.send_discover_offer_request_ack()
        decline_pkt = self.dhcp4_decline()
        Tools.rate_print('模拟冲突', self.args.get('sleep_time'))
        self.send_dhcp4_pkt(decline_pkt, args=self.args)

    def send_discover_offer_request_ack_release(self):
        """
        发起 释放租约 请求
        :return:
        """
        self.send_discover_offer_request_ack()
        release_pkt = self.dhcp4_release()
        Tools.rate_print('租约释放', self.args.get('sleep_time'))
        self.send_dhcp4_pkt(release_pkt, args=self.args)

    def send_discover_offer_request_ack_inform(self):
        """
        发起 inform 请求
        :return:
        """
        self.send_discover_offer_request_ack()
        inform_pkt = self.dhcp4_inform()
        ack_pkt = self.send_dhcp4_pkt(inform_pkt, args=self.args)
        Tools.analysis_results(pkts_list=ack_pkt, args=self.args)

    def send_inform(self):
        inform_pkt = self.dhcp4_custom_inform()
        res = self.send_dhcp4_pkt(inform_pkt, args=self.args)
        Tools.analysis_results(pkts_list=res, args=self.args)

    def send_request(self):
        request_pkt = self.dhcp4_request()
        res = self.send_dhcp4_pkt(request_pkt, args=self.args)
        Tools.analysis_results(pkts_list=res, args=self.args)
