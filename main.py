# -*- coding: gbk -*-
# @Time    : 2022/10/23 16:33
# @Author  : mf.liang
# @File    : main.py
# @Software: PyCharm
# @desc    : dhcp �����н��ܣ�������Ϊѭ��������δ����ʵ�ֲ���
import argparse
from env_args import logs, global_var
from dhcp4_controller import Dhcp4Controller
from dhcp6_controller import Dhcp6Controller
from tools import Tools

parser = argparse.ArgumentParser(description="DHCP����,ͬʱ֧��ipv4,ipv6", conflict_handler='resolve')
subparsers = parser.add_subparsers(help='help������Ϣ')
subparsers_4 = subparsers.add_parser('v4', help='DHCP4 ����������Ϣ')
subparsers_6 = subparsers.add_parser('v6', help='DHCP6 ����������Ϣ')


def parse_cmd_args_dhcp4():
    """
    # ����dhcp4����
    :return:
    """
    subparsers_4.add_argument("--num", "-n", help="��������", default=1)
    subparsers_4.add_argument("--dhcp_server", "-s", help="ָ��DHCP������", required=True)
    subparsers_4.add_argument("--relay_forward", "-rf", help="ָ���м̷�����", default=Tools.get_local_ipv4())
    subparsers_4.add_argument("--options", "-o", help='���option,��ʽ��hostname=yamu&option_name=value')
    subparsers_4.add_argument("--message_type", "-mt", help='����ָ�����ͱ����磺discover,request,renew,release,decline,inform',
                              default='default')
    subparsers_4.add_argument("--debug", "-debug", help='�鿴��ϸ�������,Ĭ��Ϊ off, on', type=str, default='off')
    subparsers_4.add_argument("--mac", "-mac", help='ָ��mac��ַ���з���', default=None)
    subparsers_4.add_argument("--sleep_time", "-st", type=int,
                              help='���ض��׶� �ȴ�һ��ʱ��,֧�����ack��ȴ�ָ��ʱ���ִ������Ķ���', default=0)


def parse_cmd_args_dhcp6():
    """
    ����dhcp6����
    :return:
    """
    subparsers_6.add_argument("--num", "-n", help="��������", default=1)
    subparsers_6.add_argument("--options", "-o", help="�Զ���options",
                              default=None)
    subparsers_6.add_argument("--ipv6_src", "-src", help='ָ��ipv6Դip,����: -src "1000::31:350:9640:be36:46f6"')
    subparsers_6.add_argument("--message_type", "-mt", help='����ָ�����ͱ����磺solicit,request,renew,release,decline',
                              default='default')
    subparsers_6.add_argument("--na_pd", "-np", help='����� na, pd,na/pd', default='na')
    subparsers_6.add_argument("--debug", "-debug", help='�鿴��ϸ�������,Ĭ��Ϊ off, on', type=str, default='off')
    subparsers_6.add_argument("--mac", "-mac", help='ָ��mac��ַ���з���', default=None)
    subparsers_6.add_argument("--dhcp_server", "-s", required=True,
                              help='tcpdump�������������ڽ��շ���ֵ���ˣ�����ָ�����ͷ���mac��ַ,��:  -f "1000:0:0:30::1"')
    subparsers_6.add_argument("--relay_forward", "-rf", type=str, help='�����м̵�ַ, Ĭ��Ϊ None', default=None)
    subparsers_6.add_argument("--sleep_time", "-st", type=int,
                              help='���ض��׶� �ȴ�һ��ʱ��,֧�����ack��ȴ�ָ��ʱ���ִ������Ķ���', default=0)


def dhcp_main():
    """
    dhcpִ�к������
    :return:  v6 -s 1000:0:0:31::11 -n 5
    """
    parse_cmd_args_dhcp4()
    parse_cmd_args_dhcp6()
    args = vars(parser.parse_args())
    global_var.update(args)
    logs.info(f"����������:\t{args}")
    napd = args.get('na_pd')
    dhcp_server = args.get('dhcp_server')

    if napd and ':' in dhcp_server:

        dhcp6_controldler = Dhcp6Controller(args)
        dhcp6_controldler.run()
    elif napd is None and ':' not in dhcp_server:
        dhcp4_controller = Dhcp4Controller(args)
        dhcp4_controller.run()
    else:
        logs.error('��������, �������!')


if __name__ == '__main__':
    dhcp_main()
