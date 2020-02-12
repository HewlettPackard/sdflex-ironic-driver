# Copyright 2019 Hewlett Packard Enterprise Development LP
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from ironic.common import states
from ironic.drivers import base as drivers_base
from ironic.objects import node


def get_test_node(**kw):
    properties = {
        "cpu_arch": "x86_64",
        "cpus": "8",
        "local_gb": "10",
        "memory_mb": "4096",
    }
    # NOTE(deva): API unit tests confirm that sensitive fields in instance_info
    #             and driver_info will get scrubbed from the API response
    #             but other fields (eg, 'foo') do not.
    fake_instance_info = {
        "configdrive": "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ=",
        "image_url": "http://example.com/test_image_url",
        "foo": "bar",
    }
    fake_driver_info = {
        "foo": "bar",
        "fake_password": "fakepass",
    }
    fake_internal_info = {
        "private_state": "secret value"
    }
    result = {
        'version': kw.get('version', node.Node.VERSION),
        'id': kw.get('id', 123),
        'name': kw.get('name', None),
        'uuid': kw.get('uuid', '1be26c0b-03f2-4d2e-ae87-c02d7f33c123'),
        'chassis_id': kw.get('chassis_id', None),
        'conductor_affinity': kw.get('conductor_affinity', None),
        'conductor_group': kw.get('conductor_group', ''),
        'power_state': kw.get('power_state', states.NOSTATE),
        'target_power_state': kw.get('target_power_state', states.NOSTATE),
        'provision_state': kw.get('provision_state', states.AVAILABLE),
        'target_provision_state': kw.get('target_provision_state',
                                         states.NOSTATE),
        'provision_updated_at': kw.get('provision_updated_at'),
        'last_error': kw.get('last_error'),
        'instance_uuid': kw.get('instance_uuid'),
        'instance_info': kw.get('instance_info', fake_instance_info),
        'driver': kw.get('driver', 'fake-hardware'),
        'driver_info': kw.get('driver_info', fake_driver_info),
        'driver_internal_info': kw.get('driver_internal_info',
                                       fake_internal_info),
        'clean_step': kw.get('clean_step'),
        'deploy_step': kw.get('deploy_step'),
        'properties': kw.get('properties', properties),
        'reservation': kw.get('reservation'),
        'maintenance': kw.get('maintenance', False),
        'maintenance_reason': kw.get('maintenance_reason'),
        'fault': kw.get('fault'),
        'console_enabled': kw.get('console_enabled', False),
        'extra': kw.get('extra', {}),
        'updated_at': kw.get('updated_at'),
        'created_at': kw.get('created_at'),
        'inspection_finished_at': kw.get('inspection_finished_at'),
        'inspection_started_at': kw.get('inspection_started_at'),
        'raid_config': kw.get('raid_config'),
        'target_raid_config': kw.get('target_raid_config'),
        'tags': kw.get('tags', []),
        'resource_class': kw.get('resource_class'),
        'traits': kw.get('traits', []),
    }

    for iface in drivers_base.ALL_INTERFACES:
        name = '%s_interface' % iface
        result[name] = kw.get(name)

    return result


def get_test_sdflex_info():
    return {
        "sdflex_address": "1.2.3.4",
        "sdflex_username": "admin",
        "sdflex_password": "fake",
    }
