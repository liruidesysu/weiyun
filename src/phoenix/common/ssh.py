# -*- encoding: utf-8 -*-
# Copyright 2016 Vinzor Co.,Ltd.
#
# ssh utils
#
# 2018/10/24 wuhaibin: init
import paramiko


def ssh_cmd(mode=None, ip=None, port=22, username="root", password=None, cmd=None):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if mode == 'key' or mode == None:
            key = paramiko.RSAKey.from_private_key("../../web/static/hostkey")
            ssh.connect(ip, port, username, pkey=key)
        else:
            ssh.connect(ip, port, username, password)

        if cmd:
            ssh.exec_command(cmd)
        return True
    except Exception as ex:
        return False
