from phoenix.cloud import compute as OSCompute

from keystoneauth1 import identity
from keystoneauth1 import session
from keystoneauth1.identity import v3

from neutronclient.v2_0 import client as neutronclient

from novaclient.v2 import client as novaclient

username = 'admin'
password = 'admin123'
project_name = 'demo'
project_domain_id = 'default'
user_domain_id = 'default'
auth_url = 'http://192.168.199.200/identity/v3'
region_name = "CentralRegion"

auth = v3.Password(auth_url=auth_url,
                   username=username,
                   password=password,
                   project_name=project_name,
                   project_domain_id=project_domain_id,
                   user_domain_id=user_domain_id)
sess = session.Session(auth=auth)
neutron = neutronclient.Client(session=sess, region_name=region_name)

network = {'name': 'mynetwork', 'admin_state_up': True, 'availability_zone_hint': ["RegionOne"]}
for net in neutron.list_networks()["networks"]:
    print(net)
#neutron.create_network(body={'network': network})

vms = OSCompute.list_servers()
print(vms)
