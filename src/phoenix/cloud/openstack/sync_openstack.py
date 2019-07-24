# -*- encoding: utf-8 -*-
# Copyright 2016 Vinzor Co.,Ltd.
#
# comment
#
# 4/19/16 bitson : Init

import os
import sys
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..')))


import threading
import time
import logging

from phoenix.cloud.openstack.client import ClientManager
from phoenix.common.proxy import SimpleProxy
from phoenix.common.singleton import SingletonMixin

from phoenix import db
from phoenix.db.models import FloatingIp

LOG = logging.getLogger(__name__)

# check if neutron is supported
NEUTRON_CLI = None
KEYSTONE_CLI = SimpleProxy(lambda: ClientManager().keystone_client)

if KEYSTONE_CLI.services.list(type='network'):
    NEUTRON_CLI = SimpleProxy(lambda: ClientManager().neutron_client)

NOVA_CLI = SimpleProxy(lambda: ClientManager().nova_client)


class LocalFloatingIpManager(SingletonMixin):
    """Local floating ip manager."""

    def delete_floating_ip_address(self, ip_address):
        """从本地缓存删除特定的 IP 地址"""
        return db.delete_floating_ip_address(ip_address)

    def allocate_ip(self, external_net_id):
        """分配并占用 Floating IP"""
        if NEUTRON_CLI:
            ip = db.allocate_floating_ip(external_net_id)
            if not ip:
                body = {
                    'floatingip': {'floating_network_id': external_net_id}
                }
                result = NEUTRON_CLI.create_floatingip(body)
                new_floating_ip = result['floatingip']
                floating_ip_id = new_floating_ip['id']
                floating_ip_address = new_floating_ip['floating_ip_address']

                # add to floating ip table
                new_ip = FloatingIp()
                new_ip.ip_address = new_floating_ip['floating_ip_address']
                new_ip.external_network_id = new_floating_ip['floating_network_id']
                new_ip.ref_id = new_floating_ip['id']
                new_ip.status = FloatingIp.IP_STATUS.ACTIVE
                db.create_floating_ip(new_ip)
            else:
                floating_ip_id = ip.ref_id
                floating_ip_address = ip.ip_address
            return {'address': floating_ip_address,
                    'id': floating_ip_id}
        else:
            ip = db.allocate_floating_ip(external_net_id)
            if not ip:
                new_floating_ip = NOVA_CLI.floating_ips.create()
                new_ip = FloatingIp()
                new_ip.ip_address = new_floating_ip.ip
                new_ip.external_network_id = new_floating_ip.pool
                new_ip.ref_id = new_floating_ip.id
                new_ip.status = FloatingIp.IP_STATUS.ACTIVE
                db.create_floating_ip(new_ip)

                floating_ip_id = new_floating_ip.id
                floating_ip_address = new_floating_ip.ip
            else:
                floating_ip_id = ip.ref_id
                floating_ip_address = ip.ip_address
            return {'address': floating_ip_address,
                    'id': floating_ip_id}

    def reclaim_ip(self, ip):
        """释放本地数据库 Floating IP 占用记录"""
        db.reclaim_floating_ip(ip)

    def refresh(self):
        """同步本地数据库与 openstack 的 Floating IP 数据"""
        if NEUTRON_CLI:
            db.delete_all_floating_ip()
            server_ips = NEUTRON_CLI.list_floatingips()
            # get current tenant's id
            keystone_client = ClientManager().keystone_client
            tenant_id = keystone_client.session.auth.auth_ref.project_id
            for ip in server_ips['floatingips']:
                if ip['tenant_id'] == tenant_id:
                    new_ip = FloatingIp()
                    new_ip.ip_address = ip['floating_ip_address']
                    new_ip.external_network_id = ip['floating_network_id']
                    new_ip.ref_id = ip['id']
                    new_ip.status = ip['status'].lower()
                    db.create_floating_ip(new_ip)
        else:
            db.delete_all_floating_ip()
            server_ips = NOVA_CLI.floating_ips.findall()
            for ip in server_ips:
                new_ip = FloatingIp()
                new_ip.ip_address = ip.ip
                new_ip.external_network_id = ip.pool
                new_ip.ref_id = ip.id
                new_ip.status = 'active' if ip.fixed_ip else 'down'
                db.create_floating_ip(new_ip)


    def clean(self):
        """删除所有本地数据库的 Floating IP 缓存记录"""
        db.delete_all_floating_ip()

floating_ip_manager = LocalFloatingIpManager()

# if __name__ == '__main__':
#     floating_ip_manager.clean()
#     floating_ip_manager.start_sync()
