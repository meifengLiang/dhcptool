# -*- coding: utf-8 -*-
# @Time    : 2022/10/23 20:15
# @Author  : mf.liang
# @File    : fdss.py
# @Software: PyCharm
# @desc    :
import logging

logging.basicConfig(level=logging.DEBUG)

# logging.debug("This is  DEBUG !!")
# logging.info("This is  INFO !!")
# logging.warning("This is  WARNING !!")
# logging.error("This is  ERROR !!")
# logging.critical("This is  CRITICAL !!")


import queue

get_result = {
    "dhcp6_advertise": queue.Queue(),
    "dhcp6_reply": queue.Queue()
}

q = get_result.get('dhcp6_advertise')  # 如果不设置长度,默认为无限长
# print(q.maxsize)  # 注意没有括号
q.put(123)
q.put(456)
q.put(789)
q.put(100)
q.put(111)

print(q.get())
print(q.get())
print(q.get())
print(q.get())
print(q.get())
print(q.get())
print(q.get())
