# -*- coding: utf-8 -*-
# @Time    : 2022/10/23 19:33
# @Author  : mf.liang
# @File    : options.py
# @Software: PyCharm
# @desc    :
import binascii
from scapy.layers.dhcp6 import DHCP6OptVendorClass, VENDOR_CLASS_DATA, DHCP6OptIfaceId, DHCP6OptStatusCode, \
    DHCP6OptRapidCommit, DHCP6OptOptReq
from env_args import logs


class Options:

    def __init__(self, args):
        self.args = args

    def parse_dhcp4_options(self):
        options_list = self.args.options
        if options_list == None:
            return None
        else:
            options_list = [i.split('=') for i in options_list.split('&')]
            return options_list

    def parse_dhcp6_options(self):
        options_list = self.args.options
        if options_list == None:
            return None
        else:
            options_list = [i.split('=') for i in options_list.split('&')]
            return options_list


class Dhcp4Options(Options):

    def __init__(self, args):
        self.args = args
        super(Dhcp4Options, self).__init__(args=self.args)

    def make_options_list(self) -> object:
        """
        制作 options
        :return:
        """
        options = []
        options_list = self.parse_dhcp4_options()
        if options_list is not None:
            for index, i in enumerate(options_list):
                if int(i[0]) == 12:
                    options.append(self.option_12(i[1]))
                if int(i[0]) == 7:
                    options.append(self.option_7(i[1]))
                if int(i[0]) == 60:
                    options.append(self.option_60(i[1]))
                if int(i[0]) == 82:
                    options.append(self.option_82(i[1], str(index + 1).rjust(2, '0')))
                if int(i[0]) == 55:
                    options.append(self.option_55(i[1]))
                if int(i[0]) == 50:
                    options.append(self.option_50(i[1]))
        options.append('end')
        return options

    def option_12(self, value=''):
        return 'hostname', value

    def option_7(self, value='0.0.0.0'):
        return 'log_server', value

    def option_60(self, value=''):
        """

        :param value:
        :return:
        ./dhcptool v4 -s 192.168.31.134 -o 60=$(radtools passwd mf@liang admin123)
        TODO: 除了上面的方式,还需要兼容字符串格式的option60
        """
        hex = value.encode("utf-8")
        value = binascii.unhexlify(hex)
        return 'vendor_class_id', value

    def option_82(self, value='', suboption_index='01'):
        try:
            hex_value = value.encode("utf-8")
            value = binascii.unhexlify(hex_value)
        except:
            value_len = hex(len(value))[2:]
            hex_value = value.encode("utf-8").hex()
            value = str(suboption_index) + str(value_len) + hex_value
            hex_value = value.encode("utf-8")
            value = binascii.unhexlify(hex_value)
        return 'relay_agent_information', value

    def option_55(self, value=''):
        value_list = [int(i) for i in value.split(',')]
        return 'param_req_list', value_list

    def option_50(self, value='192.168.0.1'):
        return 'requested_addr', value


class Dhcp6Options(Options):

    def __init__(self, args):
        self.args = args
        super(Dhcp6Options, self).__init__(args=self.args)

    def make_options_list(self):
        """
        制作 options
        :return:
        """
        options = DHCP6OptStatusCode()
        options_list = self.parse_dhcp6_options()
        if options_list is not None:
            for i in options_list:
                if int(i[0]) == 16:
                    options = self.option_16(i[1]) / options
                if int(i[0]) == 18:
                    options = self.option_18(i[1]) / options
                if int(i[0]) == 6:
                    options = self.option_6(i[1]) / options
                if int(i[0]) == 14:
                    options = self.option_14() / options
        return options

    def option_16(self, account_pwd_hex: str):
        """
        python3 main.py v6 -s 1000::31:332b:d5ab:4457:fb60 -debug on -o "16=1f31014d65822107fcfd52000000006358c1cc2f31c57f7dd8b43d27edc570aba8e999ed46b5176fb38bb7a407d97010eeebba"
        :return:
        """
        try:
            if "0000" in account_pwd_hex[:5]:
                account_pwd_hex = account_pwd_hex[4:]
            vendor_class_data = VENDOR_CLASS_DATA(data=bytes.fromhex(account_pwd_hex))
            option16_pkt = DHCP6OptVendorClass(vcdata=vendor_class_data)
        except Exception as ex:
            logs.error(ex)
            return None
        return option16_pkt

    def option_18(self, ipoe_value: str):
        """
        suxx@suxx:      eth 2/1/4:80.90 ZTEOLT001/1/1/5/0/1/
        python3 main.py v6 -s 1000::31:332b:d5ab:4457:fb60 -o "16=1f31014d65822107fcfd52000000006358c1cc2f31c57f7dd8b43d27edc570aba8e999ed46b5176fb38bb7a407d97010eeebba&18=eth 2/1/4:80.90 ZTEOLT001/1/1/5/0/1"
        :return:
        """
        option18_pkt = DHCP6OptIfaceId(ifaceid=ipoe_value)
        return option18_pkt

    def option_6(self, value):
        """
        Option Request
        :return:
        """
        if value:
            value_list = [int(i) for i in value.split(',')]
            option6_pkt = DHCP6OptOptReq(reqopts=value_list)
        else:
            option6_pkt = DHCP6OptOptReq()
        return option6_pkt

    def option_14(self):
        """
        Rapid Commit
        :return:
        """
        option14_pkt = DHCP6OptRapidCommit()
        return option14_pkt
