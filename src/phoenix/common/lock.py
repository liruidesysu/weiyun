# -*- coding:utf-8 -*-
# Copyright (c) 2016 Vinzor Co.,Ltd.
#
# lock
# 
# Created by fengyc at 16/5/18
# 16/5/18 fengyc: Create lock

import os
import time
import errno

from ..exception import BaseException


class LockException(BaseException):
    """Generic lock exception"""
    pass


class FileLockException(LockException):
    """File lock exception"""
    pass


class FileLock(object):
    """跨平台文件锁

    跨平台文件锁，通过上下文管理协议和文件独占写机制实现。不依赖于 posix 的 fnctl 和 windows 的 msvcrt 。

    使用方法 ::

        with FileLock(file_path) as f:
            do_something()

    或 ::

        l = FileLock(file_path)
        with l:
            do_something()

    在锁定失败时，抛出 FileLockException
    """

    def __init__(self, file_name, timeout=10, delay=.05):
        """ Prepare the file locker. Specify the file to lock and optionally
            the maximum timeout and the delay between each attempt to lock.
        """
        self.is_locked = False
        self.lockfile = os.path.abspath(file_name)
        self.file_name = file_name
        self.timeout = timeout
        self.delay = delay
        self.fd = None

    def acquire(self):
        """ Acquire the lock, if possible. If the lock is in use, it check again
            every `wait` seconds. It does this until it either gets the lock or
            exceeds `timeout` number of seconds, in which case it throws
            an exception.
        """
        start_time = time.time()
        while True:
            # 当前文件锁对象未有加锁，执行加锁
            if self.fd is None:
                try:
                    # 独占式打开文件
                    lock_dir = os.path.dirname(self.lockfile)
                    if not os.path.isdir(lock_dir):
                        os.makedirs(lock_dir, exist_ok=True)
                    self.fd = os.open(self.lockfile, os.O_CREAT | os.O_EXCL | os.O_RDWR)
                    break
                except OSError as e:
                    if e.errno != errno.EEXIST:
                        raise
                    # 超时
                    if (time.time() - start_time) >= self.timeout:
                        raise FileLockException("Timeout occured.")
            # 本次加锁失败，需要等待
            time.sleep(self.delay)
        self.is_locked = True

    def release(self):
        """ Get rid of the lock by deleting the lockfile.
            When working in a `with` statement, this gets automatically
            called at the end.
        """
        #关闭文件，删除文件
        if self.fd is not None:
            os.close(self.fd)
            os.unlink(self.lockfile)
            self.is_locked = False
            self.fd = None

    def __enter__(self):
        """ Activated when used in the with statement.
            Should automatically acquire a lock to be used in the with block.
        """
        self.acquire()
        return self

    def __exit__(self, type, value, traceback):
        """ Activated at the end of the with statement.
            It automatically releases the lock if it isn't locked.
        """
        self.release()

    def __del__(self):
        """ Make sure that the FileLock instance doesn't leave a lockfile
            lying around.
        """
        self.release()
