# -*- coding: utf-8 -*-
# @Time    : 2022/10/23 19:00
# @Author  : mf.liang
# @File    : dhcp_pkt.py
# @Software: PyCharm
# @desc    :

class Pkt:

    def __init__(self):
        pass

    def send_pkt(self):
        pass


class Dhcp6Pkt(Pkt):

    def __init__(self):
        super(Dhcp6Pkt, self).__init__()

    def dhcp6_solicit(self):
        pass


class Dhcp4Pkt(Pkt):

    def __init__(self):
        super(Dhcp4Pkt, self).__init__()

    def dhcp4_discover(self):
        pass
