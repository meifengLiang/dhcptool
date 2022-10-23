# -*- coding: utf-8 -*-
# @Time    : 2022/10/23 16:33
# @Author  : mf.liang
# @File    : main.py
# @Software: PyCharm
# @desc    : dhcp 命令行接受，本工具为循环发包，未考虑实现并发
import argparse
import logging
logging.basicConfig(level=logging.DEBUG)
from dhcp4_controller import Dhcp4Controller
from dhcp6_controller import Dhcp6Controller

parser = argparse.ArgumentParser(description="DHCP发包,同时支持ipv4,ipv6", conflict_handler='resolve')
subparsers = parser.add_subparsers(help='help帮助信息')
subparsers_4 = subparsers.add_parser('v4', help='DHCP4 发包帮助信息')
subparsers_6 = subparsers.add_parser('v6', help='DHCP6 发包帮助信息')


def parse_cmd_args_dhcp4():
    """
    解析dhcp4参数
    :return:
    """
    subparsers_4.add_argument("--num", "-n", help="发包数量", default=1)
    subparsers_4.add_argument("--dhcp_server", "-s", help="指定DHCP服务器", required=True)
    subparsers_4.add_argument("--chaddr", "-c", help="指定Client的MAC地址.更新租约使用上次分配过的地址",
                              default='8e:d0:0d:86:c9:9a')
    subparsers_4.add_argument("--giaddr", "-g", help="指定中继服务器", default='192.168.31.135')
    subparsers_4.add_argument("--options", "-o", help='添加option,格式：hostname=yamu&option_name=value')
    subparsers_4.add_argument("--message_type", "-mt", help='发送指定类型报文如：discover,request')


def parse_cmd_args_dhcp6():
    """
    解析dhcp6参数
    :return:
    """
    subparsers_6.add_argument("--num", "-n", help="发包数量", default=1)
    subparsers_6.add_argument("--options", "-o", help="""-o '{"option1":{"id":"${id}"},"option2":{"id":1234}}'""",
                              default=None)
    subparsers_6.add_argument("--ipv6_src", "-src", help='指定ipv6源ip,例如: -src "1000::31:350:9640:be36:46f6"',
                              default="1000:0:0:31::135")
    subparsers_6.add_argument("--message_type", "-mt", help='发送指定类型报文如：solicit,request,renew',
                              default='default')
    subparsers_6.add_argument("--na_pd", "-np", help='0:前缀模式, 1:后缀模式, 2:前+后缀模式', default=0)
    subparsers_6.add_argument("--show", "-show", help='查看详细请求过程,默认为 0/False, 1/True', default=0)
    subparsers_6.add_argument("--file_path", "-fp", help='指定pcap文件,目前与rennew搭配使用', default=None)
    subparsers_6.add_argument("--data", "-d", help='自定义入参', default=None)
    subparsers_6.add_argument("--mac", "-mac", help='指定mac地址进行发流', default="8e:d0:0d:86:c9:9a")
    subparsers_6.add_argument("--filter", "-f", required=True, default=None,
                              help='tcpdump过滤条件，用于接收返回值过滤，必须指定发送方得mac地址,如:  -f "1000:0:0:30::1" ')


def dhcp_main():
    """
    dhcp执行函数入口
    :return:
    """
    parse_cmd_args_dhcp4()
    parse_cmd_args_dhcp6()
    args = vars(parser.parse_args())
    logging.debug(f"解析命令行:\t{args}")
    dhcp_server = args.get('dhcp_server')
    if dhcp_server is None:
        dhcp6_controldler = Dhcp6Controller(args)
        dhcp6_controldler.run()
    else:
        dhcp4_controller = Dhcp4Controller(args)
        dhcp4_controller.run()


if __name__ == '__main__':
    dhcp_main()
