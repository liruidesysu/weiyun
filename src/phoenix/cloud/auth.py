# -*- encoding: utf-8 -*-
# Copyright 2016 Vinzor Co.,Ltd.
#
# Compute API
#
# 2018/3/1 chengkang: Init

from phoenix.cloud import utils
from phoenix.cloud import CONF


_BACKEND_MAPPING = {'openstack': 'phoenix.cloud.openstack.auth'}

IMPL = utils.CLOUDAPI.from_config(conf=CONF, backend_mapping=_BACKEND_MAPPING)


def get_project_id():
    """
    Get current project/tenant id
    """
    return IMPL.get_project_id()


def get_user_id():
    """
    Get current user id
    """
    return IMPL.get_user_id()