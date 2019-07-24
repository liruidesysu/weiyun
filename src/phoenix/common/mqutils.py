# -*- encoding: utf-8 -*-
# Copyright 2016 Vinzor Co.,Ltd.
#
# comment
#
# 7/21/17 bitson : Init

from kombu.entity import Exchange, Queue
from kombu.connection import Connection

import phoenix.config as cfg

# from oslo_config import cfg as oslo_cfg

os_options = [
    cfg.StrOpt('amqp_url', default='amqp://guest:guest@localhost:5672//',
               help='amqp_url'),
]
cfg.CONF.register_opts(os_options, group='rpc')

connection = Connection(cfg.CONF.rpc.amqp_url)
channel = connection.channel()


def delete_queue(name):
    exchange = Exchange('agent', type='topic')
    queue = Queue(name, exchange=exchange, routing_key='news')
    q = queue(channel)
    q.delete(nowait=True)
