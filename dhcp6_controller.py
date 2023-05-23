# -*- coding: utf-8 -*-
# @Time    : 2022/10/23 19:06
# @Author  : mf.liang
# @File    : dhcp6_controller.py
# @Software: PyCharm
# @desc    :
import json
from queue import Empty
from scapy.layers.dhcp6 import dhcp6types
from dhcp_pkt import Dhcp6Pkt
from env_args import summary_result, logs, pkt_result, global_var
from tools import Tools


class Dhcp6Controller(Dhcp6Pkt):

    def __init__(self, args):
        super(Dhcp6Controller, self).__init__(args)
        self.args = args

    def run(self):
        """
        执行 发包测试入口
        :return:
        """
        for i in dhcp6types.values():
            summary_result[i] = 0

        for i in range(int(self.args.num)):
            global_var['tag'] = i
            try:
                send_pkts = {
                    self.args.renew: self.send_solicit_advertise_request_reply_renew,
                    self.args.release: self.send_solicit_advertise_request_reply_release,
                    self.args.decline: self.send_solicit_advertise_request_reply_decline,
                }

                send_pkts.get(True, self.send_solicit_advertise_request_reply)()
            except Empty as ex:
                logs.info('没有接收到返回包！')
            except AssertionError as ex:
                logs.info('返回包未包含分配ip！')

            print('-' * 60)
            pkt_result.get('dhcp6_reply').queue.clear()
        logs.info(json.dumps(summary_result, indent=4))

    def send_solicit_advertise_request_reply(self):
        """
        发送  dhcp6 完整分配流程
        :return:
        """
        self.__init__(self.args)
        solicit_pkt = self.dhcp6_solicit()
        res = self.send_dhcp6_pkt(solicit_pkt, args=self.args)
        Tools.analysis_results(pkts_list=res, args=self.args)

        request_pkt = self.dhcp6_request()
        res = self.send_dhcp6_pkt(request_pkt, args=self.args)
        Tools.analysis_results(pkts_list=res, args=self.args)

    def send_solicit_advertise_request_reply_renew(self):
        """
        分配完地址后进行 更新租约
        :return:
        """
        self.send_solicit_advertise_request_reply()
        renew_pkt = self.dhcp6_renew()
        Tools.rate_print('租约更新', self.args.sleep_time)
        res = self.send_dhcp6_pkt(renew_pkt, args=self.args)
        Tools.analysis_results(pkts_list=res, args=self.args)

    def send_solicit_advertise_request_reply_release(self):
        """
        分配完地址后进行 释放地址
        :return:
        """
        self.send_solicit_advertise_request_reply()
        release_pkt = self.dhcp6_release()
        Tools.rate_print('租约释放', self.args.sleep_time)
        res = self.send_dhcp6_pkt(release_pkt, args=self.args)
        Tools.analysis_results(pkts_list=res, args=self.args)

    def send_solicit_advertise_request_reply_decline(self):
        """
        分配完地址后进行 释放地址
        :return:
        """
        self.send_solicit_advertise_request_reply()
        decline_pkt = self.dhcp6_decline()
        Tools.rate_print('模拟冲突', self.args.sleep_time)
        res = self.send_dhcp6_pkt(decline_pkt, args=self.args)
        Tools.analysis_results(pkts_list=res, args=self.args)
