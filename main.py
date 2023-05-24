# -*- coding: utf-8 -*-
# @Time    : 2022/10/23 16:33
# @Author  : mf.liang
# @File    : main.py
# @Software: PyCharm
# @desc    : dhcp 命令行接受，本工具为循环发包，未考虑实现并发
import argparse
from ipaddress import ip_address

from dhcp4_controller import Dhcp4Controller
from env_args import logs, global_var
from dhcp6_controller import Dhcp6Controller
from tools import Tools


def parse_cmd_args_common(subparsers):
    """
    DHCPv4和DHCPv6公共解析参数
    :param subparsers: 
    :return: 
    """
    subparsers.add_argument("--dhcp_server", "-s", help="dhcptool [v4|v6] -s [ipv4|ipv6]")
    subparsers.add_argument("--relay_forward", "-rf", type=str,
                            default=Tools.get_local_ipv4() if "v4" in subparsers.prog else Tools.get_local_ipv6(),
                            help='dhcptool [v4|v6] -f [ipv4|ipv6] -rf [ipv4|ipv6]')
    subparsers.add_argument("--iface", "-i", default='eth0', help='dhcptool [v4|v6] -s [ipv4|ipv6] -i eth1')
    subparsers.add_argument("--single", "-single", action='store_true',
                            help='dhcptool [v4|v6] -s [ipv4|ipv6] -mt inform -single -o 50=[ipv4]')
    subparsers.add_argument("--renew", "-renew", action='store_true', help='dhcptool [v4|v6] -f [ipv4|ipv6] -renew')
    subparsers.add_argument("--discover", "-discover", action='store_true', help='发起discover请求')
    subparsers.add_argument("--request", "-request", action='store_true', help='发起request请求')
    subparsers.add_argument("--release", "-release", action='store_true', help='发起release请求')
    subparsers.add_argument("--decline", "-decline", action='store_true', help='发起decline请求')
    subparsers.add_argument("--inform", "-inform", action='store_true', help='发起inform请求')
    subparsers.add_argument("--nak", "-nak", action='store_true', help='模拟异常报文以返回nak响应报文')
    subparsers.add_argument("--filter", "-f", default=None, help='使用广播发包,用来过滤监听的返回结果')
    subparsers.add_argument("--mac", "-mac", default=None, help='指定用户mac')
    subparsers.add_argument("--debug", "-debug", action='store_true', help='debug模式，能查看更详细的报文内容')
    subparsers.add_argument("--num", "-n", type=int, default=1, help="发送报文数量")
    subparsers.add_argument("--fixe", "-fixe", action='store_true', help="固定mac值进行发包")
    subparsers.add_argument("--sleep_time", "-st", type=int, default=0, help='发包过程中等待时间')
    subparsers.add_argument("--options", "-o", default=None,
                            help='dhcptool [v4|v6] -f [ipv4|ipv6] -o [code]=[value]&[code]=[value] [dhcptool v4 -s 192.168.31.134 -o [16=1f3……&14=''][18="eth 2/1/4:114.14 ZTEOLT001/1/1/5/0/1/000000000000001111111154 XE"][60=60:000023493534453……][6=12,7][50=192.168.31.199]')


def parse_cmd_args_dhcp4():
    """
    # 解析dhcp4参数
    :return:
    """
    parse_cmd_args_common(subparsers_4)


def parse_cmd_args_dhcp6():
    """
    解析dhcp6参数
    :return:
    """
    parse_cmd_args_common(subparsers_6)
    subparsers_6.add_argument("--ipv6_src", "-src", default=Tools.get_local_ipv6(),
                              help='指定ipv6源ip 例: dhcptool v6 -f ipv6 -src ipv6')
    subparsers_6.add_argument("--na", "-na", action='store_true', help='dhcptool v6 -f ipv6 -na')
    subparsers_6.add_argument("--pd", "-pd", action='store_true', help='dhcptool v6 -f ipv6 -pd')


def exec_dhcp4(args):
    """
    DHCPv4发包
    :param args:
    :return:
    """
    dhcp4_controller = Dhcp4Controller(args)
    dhcp4_controller.run()


def exec_dhcp6(args):
    """
    DHCPv6发包
    :param args:
    :return:
    """
    dhcp6_controller = Dhcp6Controller(args)
    dhcp6_controller.run()


parser = argparse.ArgumentParser(description="DHCP发包,同时支持ipv4,ipv6", conflict_handler='resolve')
parser.add_argument("--version", "-v", help="查看dhcptool版本信息", action='version', version=Tools.get_version())
subparsers = parser.add_subparsers(
    help='[s|f] [debug] [single] [renew|release|decline|inform|nak] [mac] [o] [n] [st] [np]')
subparsers_4 = subparsers.add_parser('v4', help='DHCPv4 发包帮助信息')
subparsers_4.set_defaults(func=exec_dhcp4)
subparsers_6 = subparsers.add_parser('v6', help='DHCPv6 发包帮助信息')
subparsers_6.set_defaults(func=exec_dhcp6)
parse_cmd_args_dhcp4()
parse_cmd_args_dhcp6()


def dhcp_main():
    """
    dhcp执行函数入口
    :return:  v6 -s 1000:0:0:31::11 -n 5
    """
    args = parser.parse_args()
    args_dict = vars(args)
    str_args_dict = str(args_dict).replace('{', '').replace('}', '').replace("'", '')
    logs.info(f"args: {str_args_dict}")
    global_var.update(args_dict)
    # 开启执行
    args.func(args)


if __name__ == '__main__':
    dhcp_main()
