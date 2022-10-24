# -*- coding: utf-8 -*-
# @Time    : 2022/10/23 18:59
# @Author  : mf.liang
# @File    : env_args.py
# @Software: PyCharm
# @desc    :
import queue
import random
import subprocess
import uuid
from scapy.volatile import RandMAC

# 本机mac
address = ':'.join(hex(uuid.getnode())[2:][i:i + 2] for i in range(0, len(hex(uuid.getnode())[2:]), 2))

# 事务id(可选)
xid = random.randint(1, 900000000)

# 客户端mac地址  (重用曾经分配的IP地址，更改这个选项)（更新租约,更改这个选项为当前mac）
random_mac = RandMAC()

# 获取本机ipv6
ipv6_src = subprocess.Popen("ip -6 address show | grep inet6 | awk '{print $2}' | cut -d'/' -f1",
                            shell=True, stdout=subprocess.PIPE)

summary_result = {}

pkt_result = {
    "dhcp6_advertise": queue.Queue(),
    "dhcp6_reply": queue.Queue()
}

