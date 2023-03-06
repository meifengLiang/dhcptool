# -*- coding: utf-8 -*-
# @Time    : 2022/10/23 16:33
# @Author  : mf.liang
# @File    : main.py
# @Software: PyCharm
# @desc    : dhcp 命令行接受，本工具为循环发包，未考虑实现并发
import argparse
from env_args import logs, global_var
from dhcp4_controller import Dhcp4Controller
from dhcp6_controller import Dhcp6Controller
from tools import Tools

parser = argparse.ArgumentParser(description="DHCP发包,同时支持ipv4,ipv6", conflict_handler='resolve')
parser.add_argument("--version", "-v", help="查看dhcptool版本信息", action='version', version=Tools.get_version())
subparsers = parser.add_subparsers(help='help帮助信息')
subparsers_4 = subparsers.add_parser('v4', help='DHCP4 发包帮助信息')
subparsers_6 = subparsers.add_parser('v6', help='DHCP6 发包帮助信息')


def parse_cmd_args_dhcp4():
    """
    # 解析dhcp4参数
    :return:
    """
    subparsers_4.add_argument("--num", "-n", help="发包数量", default=1)
    subparsers_4.add_argument("--dhcp_server", "-s", help="指定DHCP服务器")
    subparsers_4.add_argument("--filter", "-f", help='tcpdump过滤条件，用于接收返回值过滤，必须指定发送方得mac地址,如:  -f "192.168.31.1"',
                              default=None)
    subparsers_4.add_argument("--relay_forward", "-rf", help="指定中继服务器", default=Tools.get_local_ipv4())
    subparsers_4.add_argument("--options", "-o", help='添加option,格式：hostname=yamu&option_name=value')
    subparsers_4.add_argument("--message_type", "-mt", help='发送指定类型报文如：discover,request,renew,release,decline,inform',
                              default='default')
    subparsers_4.add_argument("--iface", "-i", help='指定网卡', default='eth0')
    subparsers_4.add_argument("--debug", "-debug", help='查看详细请求过程,默认为 off, on', type=str, default='off')
    subparsers_4.add_argument("--mac", "-mac", help='指定mac地址进行发流', default=None)
    subparsers_4.add_argument("--multiprocessing", "-mp", default='master/slave,192.168.31.134,192.168.31.134,8080',
                              help='分布式测试配置')
    subparsers_4.add_argument("--sleep_time", "-st", type=int,
                              help='在特定阶段 等待一段时间,支持完成ack后等待指定时间后执行下面的动作', default=0)


def parse_cmd_args_dhcp6():
    """
    解析dhcp6参数
    :return:
    """
    subparsers_6.add_argument("--num", "-n", help="发包数量", default=1)
    subparsers_6.add_argument("--options", "-o", help="自定义options",
                              default=None)
    subparsers_6.add_argument("--ipv6_src", "-src", help='指定ipv6源ip,例如: -src "1000::31:350:9640:be36:46f6"')
    subparsers_6.add_argument("--message_type", "-mt", help='发送指定类型报文如：solicit,request,renew,release,decline',
                              default='default')
    subparsers_6.add_argument("--na_pd", "-np", help='输入项： na, pd,na/pd', default='na')
    subparsers_6.add_argument("--debug", "-debug", help='查看详细请求过程,默认为 off, on', type=str, default='off')
    subparsers_6.add_argument("--mac", "-mac", help='指定mac地址进行发流', default=None)
    subparsers_6.add_argument("--multiprocessing", "-mp", default='master,192.168.31.134,8080', help='分布式测试配置')
    subparsers_6.add_argument("--dhcp_server", "-s", help='tcpdump过滤条件，用于接收返回值过滤，必须指定发送方得mac地址,如:  -f "1000:0:0:30::1"')
    subparsers_6.add_argument("--filter", "-f", help='tcpdump过滤条件，用于接收返回值过滤，必须指定发送方得mac地址,如:  -f "1000:0:0:30::1"',
                              default=None)
    subparsers_6.add_argument("--relay_forward", "-rf", type=str, help='配置中继地址, 默认为 None', default=None)
    subparsers_6.add_argument("--sleep_time", "-st", type=int,
                              help='在特定阶段 等待一段时间,支持完成ack后等待指定时间后执行下面的动作', default=0)


def dhcp_main():
    """
    dhcp执行函数入口
    :return:  v6 -s 1000:0:0:31::11 -n 5
    """
    parse_cmd_args_dhcp4()
    parse_cmd_args_dhcp6()
    args = vars(parser.parse_args())
    global_var.update(args)
    logs.info(f"解析命令行:\t{args}")
    napd = args.get('na_pd')
    dhcp_server, filter = args.get('dhcp_server'), args.get('filter')

    if napd:
        dhcp6_controldler = Dhcp6Controller(args)
        dhcp6_controldler.run()
    elif napd is None:
        dhcp4_controller = Dhcp4Controller(args)
        dhcp4_controller.run()
    else:
        logs.error('参数错误, 请检查入参!')


if __name__ == '__main__':
    dhcp_main()
