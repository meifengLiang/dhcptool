# -*- coding: utf-8 -*-
# @Time    : 2022/10/23 18:59
# @Author  : mf.liang
# @File    : env_args.py
# @Software: PyCharm
# @desc    :

import os
import platform
import queue
import random
import subprocess
import uuid
from Logings import Logings

# 本机mac
address = ':'.join(hex(uuid.getnode())[2:][i:i + 2] for i in range(0, len(hex(uuid.getnode())[2:]), 2))

# 事务id(可选)
xid = random.randint(1, 900000000)

# 获取本机ipv6
sys = platform.system()
if sys is 'Windows':
    output = (os.popen('wmic nicConfig where "IPEnabled=True" get IPAddress')
        .read().strip(' ').replace(' ', '').split('\n\n')[1])
    ipv6_src = list(eval(output))[0]
else:
    ipv6_src = subprocess.Popen("ip -6 address show | grep inet6 | awk '{print $2}' | cut -d'/' -f1",
                                shell=True, stdout=subprocess.PIPE)

summary_result = {}

global_var = {"tag": 0}

pkt_result = {
    "dhcp6_advertise": queue.Queue(),
    "dhcp6_reply": queue.Queue(),
    # "dhcp6_relay_repl": {
    #     "dhcp6_advertise": queue.Queue(),
    #     "dhcp6_rely": queue.Queue()
    #     },
    "dhcp4_offer": queue.Queue(),
    "dhcp4_ack": queue.Queue(),
}

logs = Logings()
