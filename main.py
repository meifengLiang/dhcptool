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
    subparsers_4.add_argument("--num", "-n", help="数量  例: dhcptool v4 -s 192.168.31.134 -n 10", default=1)
    subparsers_4.add_argument("--dhcp_server", "-s", help="DHCP服务器(单播)  例: dhcptool v4 -s 192.168.31.134")
    subparsers_4.add_argument("--filter", "-f", help='DHCP服务器(广播)   例: dhcptool v4 -f 192.168.31.134', default=None)
    subparsers_4.add_argument("--relay_forward", "-rf", default=Tools.get_local_ipv4(),
                              help="填充giaddr  例: dhcptool v4 -s 192.168.31.134 -rf 192.168.31.1")

    subparsers_4.add_argument("--options", "-o",
                              help='填充options    例: 格式:dhcptool v4 -s 192.168.31.134 -o [code]=[value]&[code]=[value] [dhcptool v4 -s 192.168.31.134 -o [12=yamu&7=1.1.1.1][82="eth 2/1/4:114.14 ZTEOLT001/1/1/5/0/1/000000000000001111111154 XE"][60=60:000023493534453……][55=12,7][50=192.168.31.199]')
    subparsers_4.add_argument("--message_type", "-mt", default='default',
                              help='发送指定类型报文如  例: dhcptool v4 -s 192.168.31.134 -mt renew/release/decline/inform/nak')

    subparsers_4.add_argument("--iface", "-i", help='指定网卡   例: dhcptool v4 -s 192.168.31.134 -i eth1', default='eth0')
    subparsers_4.add_argument("--debug", "-debug", help='调试日志   例: dhcptool v4 -s 192.168.31.134 -debug on/off', type=str, default='off')
    subparsers_4.add_argument("--mac", "-mac", help='指定mac  例: dhcptool v4 -f 192.168.11.181 -mac 9a:cf:66:12:99:d1', default=None)
    subparsers_4.add_argument("--sleep_time", "-st", type=int, default=0,
                              help='分配完成后的阶段设置等待进入下一阶段  例: dhcptool v4 -f 192.168.11.181 -st 1 -mt renew/release/decline/inform')


def parse_cmd_args_dhcp6():
    """
    解析dhcp6参数
    :return:
    """
    subparsers_6.add_argument("--num", "-n", help="数量  例: dhcptool v6 -f 1000:0:0:31::135 -n 10", default=1)
    subparsers_6.add_argument("--options", "-o", help='填充options    例: 格式:dhcptool v6 -f 1000:0:0:31::135 -o [code]=[value]&[code]=[value] [dhcptool v4 -s 192.168.31.134 -o [16=1f3……&14=''][18="eth 2/1/4:114.14 ZTEOLT001/1/1/5/0/1/000000000000001111111154 XE"][60=60:000023493534453……][6=12,7][50=192.168.31.199]', default=None)
    subparsers_6.add_argument("--ipv6_src", "-src", help='指定ipv6源ip 例: dhcptool v6 -f 1000:0:0:31::135 -src 1000::31:350:9640:be36:46f6')
    subparsers_6.add_argument("--message_type", "-mt", default='default',
                              help='发送指定类型报文如  例: dhcptool v6 -f 1000:0:0:31::135 -mt renew/release/decline')
    subparsers_6.add_argument("--na_pd", "-np", help='分配类型  例: dhcptool v6 -f 1000:0:0:31::135 -np na / pd / na/pd', default='na')
    subparsers_6.add_argument("--debug", "-debug", help='调试日志   例: dhcptool v4 -f 1000:0:0:31::135 -debug on/off', type=str, default='off')
    subparsers_6.add_argument("--mac", "-mac", help='指定mac  例: dhcptool v4 -f 1000:0:0:31::135 -mac 9a:cf:66:12:99:d1', default=None)

    subparsers_6.add_argument("--dhcp_server", "-s", help='中继单播发包   例: dhcptool v4 -s 1000:0:0:31::135 -rf 1000:0:0:31::1')
    subparsers_6.add_argument("--filter", "-f", help='DHCP服务器(广播)   例: dhcptool v4 -f 1000:0:0:31::135', default=None)
    subparsers_6.add_argument("--relay_forward", "-rf", type=str, help='中继地址    例: dhcptool v4 -f 1000:0:0:31::135 -rf 1000:0:0:31::1', default=None)
    subparsers_6.add_argument("--sleep_time", "-st", type=int, default=0,
                              help='分配完成后的阶段设置等待进入下一阶段  例: dhcptool v4 -f 1000:0:0:31::135 -st 1 -mt renew/release/decline')


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
