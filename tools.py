# -*- coding: utf-8 -*-
# @Time    : 2022/10/23 18:56
# @Author  : mf.liang
# @File    : tools.py
# @Software: PyCharm
# @desc    :
import logging
import socket
import subprocess
from functools import wraps


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