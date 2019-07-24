# -*- encoding: utf-8 -*-
# Copyright 2016 Vinzor Co.,Ltd.
#
# Openstack API implementation
#
# 2018/3/1 chengkang: Init

import sys

from phoenix.cloud.openstack.client import ClientManager, AdminClientManager
from phoenix.cloud.utils import wrap_cloud_retry
from phoenix.common.proxy import SimpleProxy


def get_backend():
    """
    The backend is this module itself.
    """
    return sys.modules[__name__]

KEYSTONE_CLI = SimpleProxy(lambda: ClientManager().keystone_client)


###################


def get_project_id():
    """
    Get current project/tenant id
    """
    return KEYSTONE_CLI.session.get_project_id()


def get_user_id():
    """
    Get current user id
    """
    return KEYSTONE_CLI.session.get_user_id()