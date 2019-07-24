# -*- encoding: utf-8 -*-
# Copyright 2016 Vinzor Co.,Ltd.
#
# openstack client
#
# 2016/1/23 lipeizhao : Init

import threading
import functools
import logging
import sys

from novaclient import client as os_nova_client
from neutronclient.v2_0 import client as os_neutron_client
import glanceclient as os_glance_client
import swiftclient as os_swift_client

# for keystone v3
from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client
from keystoneauth1.identity.base import BaseIdentityPlugin

from phoenix.common.singleton import SingletonMixin
from phoenix.common import timeutils
import phoenix.config as cfg

LOG = logging.getLogger(__name__)

keystone_version = '2'

# openstack generic option
os_options = [
    cfg.StrOpt('username', default='admin',
               help='The user name for openstack access'),
    cfg.StrOpt('password', default='admin123',
               help='The password for openstack access'),
    cfg.StrOpt('tenant', default='demo',
               help='The tenant(project ID) of openstack'),
    cfg.StrOpt('domain', default='default',
               help='The domain of openstack'),
    cfg.StrOpt('auth_url', default='http://192.168.199.200/identity/v3',
               help='The authentication url'),
    cfg.StrOpt('admin_username', default='admin',
               help='The user name of openstack administrator'),
    cfg.StrOpt('admin_password', default='admin123',
               help='The password of openstack administrator'),
    cfg.StrOpt('region_name', default='RegionOne',
               help='The region of openstack'),
]
cfg.CONF.register_opts(os_options, group='openstack')


# for keystone v3
def __sync_local_token_time(f):
    def wrapped(*args, **kwargs):
        # result = f(*args, **kwargs)
        auth_plugin = args[0]
        session = args[1]

        with auth_plugin._lock:
            if auth_plugin._needs_reauthenticate():
                auth_plugin.auth_ref = auth_plugin.get_auth_ref(session)

                auth_ref = auth_plugin.auth_ref
                issued = auth_ref.issued
                expires = auth_ref.expires
                local_expires = timeutils.utcnow() + (expires - issued)
                local_issued = timeutils.utcnow()
                auth_ref._data['token']['expires_at'] = local_expires.isoformat()
                auth_ref._data['token']['issued_at'] = local_issued.isoformat()

        return auth_plugin.auth_ref
    return functools.update_wrapper(wrapped, f)

# monkey patch for auth plugin
BaseIdentityPlugin.get_access = __sync_local_token_time(BaseIdentityPlugin.get_access)
BaseIdentityPlugin.MIN_TOKEN_LIFE_SECONDS = 2 * 60 * 60

# cache for endpoints
def endpoint_cache(f):
    """ endpoints cache """
    f._endpoints = {}

    def inner(*args, **kwargs):
        service_type = args[1]
        if f._endpoints.get(service_type, None) is None:
            f._endpoints[service_type] = f(*args, **kwargs)
            LOG.info('keystone service %s endpoints refreshed' % service_type)
        return f._endpoints[service_type]
    return functools.update_wrapper(inner, f)


class ClientManager(SingletonMixin):

    _keystone_client = None
    _nova_client = None
    _glance_client = None
    _neutron_client = None
    _swift_client = None
    
    def __init__(self):
        self._username = cfg.CONF.openstack.username
        self._password = cfg.CONF.openstack.password
        self._tenant = cfg.CONF.openstack.tenant
        self._domain = cfg.CONF.openstack.domain
        self._auth_url = cfg.CONF.openstack.auth_url
        self._region_name = cfg.CONF.openstack.region_name
        
        self._keystone_lock = threading.Lock()
        self._nova_lock = threading.Lock()
        self._glance_lock = threading.Lock()
        self._neutron_lock = threading.Lock()
        self._swift_lock = threading.Lock()

        self._nova_api_version = '2'
        self._glance_api_version = '2'

    @endpoint_cache
    def get_admin_endpoint(self, service_type):
        service = self.keystone_client.services.list(type=service_type)
        service_id = service[0].id
        endpoints = self.keystone_client.endpoints.list(service=service_id, interface='admin')
        return endpoints[0] if endpoints else None

    @property
    def keystone_client(self):
        if not self._keystone_client:
            with self._keystone_lock:
                if not self._keystone_client:
                    auth = v3.Password(auth_url=self._auth_url, username=self._username,
                                       password=self._password, project_name=self._tenant,
                                       user_domain_name=self._domain, project_domain_name=self._domain)
                    sess = session.Session(auth=auth)
                    self._keystone_client = client.Client(session=sess, region_name=self._region_name)
        return self._keystone_client

    def clear_keystone_client(self):
        """clear keystone client for later retrieve"""
        self._keystone_client = None

    @property
    def nova_client(self):
        return os_nova_client.Client(version=self._nova_api_version,
                                     session=self.keystone_client.session,
                                     region_name=self._region_name)

    @property
    def neutron_client(self):
        endpoint = self.get_admin_endpoint('network')
        return os_neutron_client.Client(session=self.keystone_client.session,
                                        region_name=self._region_name)

    @property
    def glance_client(self):
        endpoint = self.get_admin_endpoint('image')
        return os_glance_client.Client(version=self._glance_api_version,
                                       session=self.keystone_client.session,
                                       region_name=self._region_name)


class AdminClientManager(SingletonMixin):

    _keystone_client = None
    _nova_client = None
    _glance_client = None
    _neutron_client = None
    _swift_client = None

    def __init__(self):
        self._username = cfg.CONF.openstack.admin_username
        self._password = cfg.CONF.openstack.admin_password
        self._domain = cfg.CONF.openstack.domain
        self._tenant = cfg.CONF.openstack.tenant
        self._auth_url = cfg.CONF.openstack.auth_url
        self._region_name = cfg.CONF.openstack.region_name

        self._keystone_lock = threading.Lock()
        self._nova_lock = threading.Lock()
        self._glance_lock = threading.Lock()
        self._neutron_lock = threading.Lock()
        self._swift_lock = threading.Lock()

        self._nova_api_version = '2'
        self._glance_api_version = '2'

    @endpoint_cache
    def get_admin_endpoint(self, service_type):
        service = self.keystone_client.services.list(type=service_type)
        service_id = service[0].id
        endpoints = self.keystone_client.endpoints.list(service=service_id, interface='admin')
        return endpoints[0] if endpoints else None

    def clear_keystone_client(self):
        """clear keystone client for later retrieve"""
        self._keystone_client = None

    @property
    def keystone_client(self):
        if not self._keystone_client:
            with self._keystone_lock:
                if not self._keystone_client:
                    auth = v3.Password(auth_url=self._auth_url, username=self._username,
                                       password=self._password, project_name=self._tenant,
                                       user_domain_name=self._domain, project_domain_name=self._domain)
                    sess = session.Session(auth=auth)
                    self._keystone_client = client.Client(session=sess, region_name=self._region_name)
        return self._keystone_client

    @property
    def nova_client(self):
        return os_nova_client.Client(version=self._nova_api_version,
                                     session=self.keystone_client.session,
                                     region_name=self._region_name)

    @property
    def neutron_client(self):
        endpoint = self.get_admin_endpoint('network')
        return os_neutron_client.Client(session=self.keystone_client.session,
                                        region_name=self._region_name)

    @property
    def glance_client(self):
        endpoint = self.get_admin_endpoint('image')
        return os_glance_client.Client(version=self._glance_api_version,
                                       session=self.keystone_client.session,
                                       region_name=self._region_name)
