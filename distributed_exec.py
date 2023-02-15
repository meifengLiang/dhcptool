# coding = 'utf-8'
"""
@File:          QueueManager.py
@Time:          2023/2/15 17:37
@Author:        mf.liang
@Email:         mf.liang@yamu.com
@Desc:          请注明模块要实现的功能

"""
from multiprocessing.managers import BaseManager


class QueueManager(BaseManager):

    def get_slave(self):
        pass
