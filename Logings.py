# -*- coding: utf-8 -*-
# @Time    : 2022/10/25 0:13
# @Author  : mf.liang
# @File    : Logings.py
# @Software: PyCharm
# @desc    :
import sys
from loguru import logger
logger.remove()


class Logings:
    __instance = None

    logger.add('dhcp_{time}.log',
               retention=3,
               encoding='utf-8',
               backtrace=True,  # 回溯
               diagnose=True,  # 诊断
               )
    logger.add(sys.stdout,  # 指定文件
               format="<green>{time:YYYYMMDD HH:mm:ss}</green> | "  # 颜色>时间
                      "<level>{message}</level>",  # 日志内容
               level="DEBUG"
               )

    def __new__(cls, *args, **kwargs):
        if not cls.__instance:
            cls.__instance = super(Logings, cls).__new__(cls, *args, **kwargs)
        return cls.__instance

    def info(self, msg, *args, **kwargs):
        return logger.info(msg, *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        return logger.debug(msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        return logger.warning(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        return logger.error(msg, *args, **kwargs)

    def success(self, msg, *args, **kwargs):
        return logger.success(msg, *args, **kwargs)

    def stop(self, msg, *args, **kwargs):
        return logger.stop(msg, *args, **kwargs)

    def start(self, msg, *args, **kwargs):
        return logger.start(msg, *args, **kwargs)

    def exception(self, msg, *args, exc_info=True, **kwargs):
        return logger.exception(msg, *args, exc_info=True, **kwargs)


if __name__ == '__main__':
    l = Logings()
    l.debug('------------')
