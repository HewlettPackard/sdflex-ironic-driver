# Copyright 2014 Rackspace, Inc.
# Copyright 2015 Red Hat, Inc.
# All Rights Reserved.
#
# Copyright 2020-2022 Hewlett Packard Enterprise Development LP
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
#
# Hewlett Packard Enterprise made changes in this file.
# Some of the methods/code snippets in this file are owned by Rackspace, Inc
# Some of the methods/code snippets in this file are owned by Red Hat, Inc

import mock
from oslo_config import cfg

from ironic.common import boot_devices
from ironic.common import exception
from ironic.common import states
from ironic.conductor import task_manager
from ironic.conductor import utils as manager_utils
from ironic.drivers import base as drivers_base
from ironic.drivers.modules import agent
from ironic.drivers.modules import agent_client
from ironic.drivers.modules import boot_mode_utils
from ironic.drivers.modules import deploy_utils
from ironic.drivers.modules.network import flat as flat_network
from ironic.drivers.modules.network import neutron as neutron_network
from ironic.drivers.modules.storage import noop as noop_storage
from ironic.tests.unit.db import utils as db_utils
from ironic.tests.unit.objects import utils as object_utils

from sdflex_ironic_driver.sdflex_redfish import boot
from sdflex_ironic_driver.sdflex_redfish import deploy
from sdflex_ironic_driver.tests.unit.sdflex_redfish import test_common


CONF = cfg.CONF

INSTANCE_INFO = db_utils.get_test_agent_instance_info()
DRIVER_INFO = db_utils.get_test_agent_driver_info()
DRIVER_INTERNAL_INFO = db_utils.get_test_agent_driver_internal_info()


class AgentDeployMixinBaseTest(test_common.BaseSdflexTest):

    def setUp(self):
        super(AgentDeployMixinBaseTest, self).setUp()
        for iface in drivers_base.ALL_INTERFACES:
            impl = 'sdflex-redfish'
            if iface == 'deploy':
                impl = 'sdflex-redfish'
            if iface == 'boot':
                impl = 'sdflex-redfish'
            if iface == 'rescue':
                impl = 'agent'
            if iface == 'storage':
                impl = 'noop'
            if iface == 'inspect':
                impl = 'no-inspect'
            if iface == 'console':
                impl = 'no-console'
            if iface == 'vendor':
                impl = 'no-vendor'
            if iface == 'raid':
                impl = 'no-raid'
            if iface == 'network':
                continue
            config_kwarg = {'enabled_%s_interfaces' % iface: [impl],
                            'default_%s_interface' % iface: impl}
            self.config(**config_kwarg)
        self.config(enabled_hardware_types=['sdflex-redfish'])
        self.deploy = deploy.SDFlexAgentDeploy()
        n = {
            'driver': 'sdflex-redfish',
            'instance_info': INSTANCE_INFO,
            'driver_info': DRIVER_INFO,
            'driver_internal_info': DRIVER_INTERNAL_INFO,
            'network_interface': 'noop'
        }
        self.node = object_utils.create_test_node(self.context, **n)


class SDflexHeartbeatMixinTestCase(AgentDeployMixinBaseTest):

    def setUp(self):
        super(SDflexHeartbeatMixinTestCase, self).setUp()
        self.deploy = deploy.SDflexHeartbeatMixin()

    @mock.patch.object(deploy_utils, 'remove_http_instance_symlink',
                       autospec=True)
    @mock.patch.object(deploy.SDFlexAgentDeploy, 'prepare_instance_to_boot',
                       autospec=True)
    @mock.patch.object(deploy.SDFlexAgentDeploy, 'tear_down_agent',
                       autospec=True)
    def test_reboot_to_instance_bfpv(self, tear_down_agent_mock,
                                     prepare_instance_mock,
                                     remove_symlink_mock):
        self.config(manage_agent_boot=True, group='agent')
        self.config(image_download_source='http', group='agent')
        self.node.provision_state = states.DEPLOYWAIT
        self.node.target_provision_state = states.ACTIVE
        self.node.save()
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.driver.deploy.reboot_to_instance_bfpv(task)
            prepare_instance_mock.assert_called_once_with(mock.ANY, task,
                                                          None, None, None)
            tear_down_agent_mock.assert_called_once_with(mock.ANY, task)
            self.assertTrue(remove_symlink_mock.called)

    @mock.patch.object(deploy.SDFlexAgentDeploy, 'reboot_to_instance_bfpv')
    def test_heartbeat_bfpv(self, rti_bfpv_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['bfpv'] = True
            task.node.driver_internal_info['bfpv_started'] = False
            task.driver.deploy.heartbeat(task, 'url', '3.2.0')
            rti_bfpv_mock.assert_called_once_with(task)

    def test_heartbeat_bfpv_started(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['bfpv'] = True
            task.node.driver_internal_info['bfpv_started'] = True
            task.driver.deploy.heartbeat(task, 'url', '3.2.0')

    @mock.patch.object(deploy.SDFlexAgentDeploy, 'heartbeat')
    def test_heartbeat_bfpv_false(self, heartbeat_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['bfpv'] = False
            task.node.driver_internal_info['bfpv_started'] = False
            task.driver.deploy.heartbeat(task, 'url', '3.2.0')
            heartbeat_mock.assert_called_once_with(task, 'url', '3.2.0')

    @mock.patch.object(agent_client.AgentClient, 'install_bootloader',
                       autospec=True)
    @mock.patch.object(deploy_utils, 'try_set_boot_device', autospec=True)
    @mock.patch.object(boot_mode_utils, 'get_boot_mode', autospec=True,
                       return_value='whatever')
    def test_configure_local_boot(self, boot_mode_mock,
                                  try_set_boot_device_mock,
                                  install_bootloader_mock):
        install_bootloader_mock.return_value = {
            'command_status': 'SUCCESS', 'command_error': None}
        with task_manager.acquire(self.context, self.node['uuid'],
                                  shared=False) as task:
            task.node.driver_internal_info['is_whole_disk_image'] = False
            self.deploy.configure_local_boot(task, root_uuid='some-root-uuid')
            try_set_boot_device_mock.assert_called_once_with(
                task, boot_devices.DISK, persistent=True)
            boot_mode_mock.assert_called_once_with(task.node)
            install_bootloader_mock.assert_called_once_with(
                mock.ANY, task.node, root_uuid='some-root-uuid',
                efi_system_part_uuid=None, prep_boot_part_uuid=None,
                target_boot_mode='whatever'
            )

    @mock.patch.object(agent_client.AgentClient, 'install_bootloader',
                       autospec=True)
    @mock.patch.object(deploy_utils, 'try_set_boot_device', autospec=True)
    @mock.patch.object(boot_mode_utils, 'get_boot_mode', autospec=True,
                       return_value='whatever')
    def test_configure_local_boot_with_prep(self, boot_mode_mock,
                                            try_set_boot_device_mock,
                                            install_bootloader_mock):
        install_bootloader_mock.return_value = {
            'command_status': 'SUCCESS', 'command_error': None}

        with task_manager.acquire(self.context, self.node['uuid'],
                                  shared=False) as task:
            task.node.driver_internal_info['is_whole_disk_image'] = False
            self.deploy.configure_local_boot(task, root_uuid='some-root-uuid',
                                             prep_boot_part_uuid='fake-prep')
            try_set_boot_device_mock.assert_called_once_with(
                task, boot_devices.DISK, persistent=True)
            boot_mode_mock.assert_called_once_with(task.node)
            install_bootloader_mock.assert_called_once_with(
                mock.ANY, task.node, root_uuid='some-root-uuid',
                efi_system_part_uuid=None, prep_boot_part_uuid='fake-prep',
                target_boot_mode='whatever'
            )

    @mock.patch.object(agent_client.AgentClient, 'install_bootloader',
                       autospec=True)
    @mock.patch.object(deploy_utils, 'try_set_boot_device', autospec=True)
    @mock.patch.object(boot_mode_utils, 'get_boot_mode', autospec=True,
                       return_value='uefi')
    def test_configure_local_boot_uefi(self, boot_mode_mock,
                                       try_set_boot_device_mock,
                                       install_bootloader_mock):
        install_bootloader_mock.return_value = {
            'command_status': 'SUCCESS', 'command_error': None}
        with task_manager.acquire(self.context, self.node['uuid'],
                                  shared=False) as task:
            task.node.driver_internal_info['is_whole_disk_image'] = False
            self.deploy.configure_local_boot(
                task, root_uuid='some-root-uuid',
                efi_system_part_uuid='efi-system-part-uuid')
            try_set_boot_device_mock.assert_called_once_with(
                task, boot_devices.DISK, persistent=True)
            boot_mode_mock.assert_called_once_with(task.node)
            install_bootloader_mock.assert_called_once_with(
                mock.ANY, task.node, root_uuid='some-root-uuid',
                efi_system_part_uuid='efi-system-part-uuid',
                prep_boot_part_uuid=None,
                target_boot_mode='uefi'
            )

    @mock.patch.object(deploy_utils, 'try_set_boot_device', autospec=True)
    @mock.patch.object(agent_client.AgentClient, 'install_bootloader',
                       autospec=True)
    def test_configure_local_boot_whole_disk_image(
            self, install_bootloader_mock, try_set_boot_device_mock):

        with task_manager.acquire(self.context, self.node['uuid'],
                                  shared=False) as task:
            self.deploy.configure_local_boot(task)
            self.assertTrue(install_bootloader_mock.called)
            try_set_boot_device_mock.assert_called_once_with(
                task, boot_devices.DISK, persistent=True)

    @mock.patch.object(deploy_utils, 'try_set_boot_device', autospec=True)
    @mock.patch.object(agent_client.AgentClient, 'install_bootloader',
                       autospec=True)
    def test_configure_local_boot_no_root_uuid(
            self, install_bootloader_mock, try_set_boot_device_mock):
        with task_manager.acquire(self.context, self.node['uuid'],
                                  shared=False) as task:
            task.node.driver_internal_info['is_whole_disk_image'] = False
            self.deploy.configure_local_boot(task)
            self.assertTrue(install_bootloader_mock.called)
            try_set_boot_device_mock.assert_called_once_with(
                task, boot_devices.DISK, persistent=True)

    @mock.patch.object(boot_mode_utils, 'get_boot_mode',
                       autospec=True)
    @mock.patch.object(deploy_utils, 'try_set_boot_device', autospec=True)
    @mock.patch.object(agent_client.AgentClient, 'install_bootloader',
                       autospec=True)
    def test_configure_local_boot_no_root_uuid_whole_disk(
            self, install_bootloader_mock, try_set_boot_device_mock,
            boot_mode_mock):
        with task_manager.acquire(self.context, self.node['uuid'],
                                  shared=False) as task:
            task.node.driver_internal_info['is_whole_disk_image'] = True
            boot_mode_mock.return_value = 'uefi'
            self.deploy.configure_local_boot(
                task, root_uuid=None,
                efi_system_part_uuid='efi-system-part-uuid')
            install_bootloader_mock.assert_called_once_with(
                mock.ANY, task.node, root_uuid=None,
                efi_system_part_uuid='efi-system-part-uuid',
                prep_boot_part_uuid=None, target_boot_mode='uefi')

    @mock.patch.object(deploy_utils, 'try_set_boot_device', autospec=True)
    @mock.patch.object(agent_client.AgentClient, 'install_bootloader',
                       autospec=True)
    def test_configure_local_boot_enforce_persistent_boot_device_default(
            self, install_bootloader_mock, try_set_boot_device_mock):
        with task_manager.acquire(self.context, self.node['uuid'],
                                  shared=False) as task:
            driver_info = task.node.driver_info
            driver_info['force_persistent_boot_device'] = 'Default'
            task.node.driver_info = driver_info
            driver_info['force_persistent_boot_device'] = 'Always'
            task.node.driver_internal_info['is_whole_disk_image'] = False
            self.deploy.configure_local_boot(task)
            self.assertTrue(install_bootloader_mock.called)
            try_set_boot_device_mock.assert_called_once_with(
                task, boot_devices.DISK, persistent=True)

    @mock.patch.object(deploy_utils, 'try_set_boot_device', autospec=True)
    @mock.patch.object(agent_client.AgentClient, 'install_bootloader',
                       autospec=True)
    def test_configure_local_boot_enforce_persistent_boot_device_always(
            self, install_bootloader_mock, try_set_boot_device_mock):
        with task_manager.acquire(self.context, self.node['uuid'],
                                  shared=False) as task:
            driver_info = task.node.driver_info
            driver_info['force_persistent_boot_device'] = 'Always'
            task.node.driver_info = driver_info
            task.node.driver_internal_info['is_whole_disk_image'] = False
            self.deploy.configure_local_boot(task)
            self.assertTrue(install_bootloader_mock.called)
            try_set_boot_device_mock.assert_called_once_with(
                task, boot_devices.DISK, persistent=True)

    @mock.patch.object(deploy_utils, 'try_set_boot_device', autospec=True)
    @mock.patch.object(agent_client.AgentClient, 'install_bootloader',
                       autospec=True)
    def test_configure_local_boot_enforce_persistent_boot_device_never(
            self, install_bootloader_mock, try_set_boot_device_mock):
        with task_manager.acquire(self.context, self.node['uuid'],
                                  shared=False) as task:
            driver_info = task.node.driver_info
            driver_info['force_persistent_boot_device'] = 'Never'
            task.node.driver_info = driver_info
            task.node.driver_internal_info['is_whole_disk_image'] = False
            self.deploy.configure_local_boot(task)
            self.assertTrue(install_bootloader_mock.called)
            try_set_boot_device_mock.assert_called_once_with(
                task, boot_devices.DISK, persistent=False)

    @mock.patch.object(agent_client.AgentClient, 'collect_system_logs',
                       autospec=True)
    @mock.patch.object(agent_client.AgentClient, 'install_bootloader',
                       autospec=True)
    @mock.patch.object(boot_mode_utils, 'get_boot_mode', autospec=True,
                       return_value='whatever')
    def test_configure_local_boot_boot_loader_install_fail(
            self, boot_mode_mock, install_bootloader_mock,
            collect_logs_mock):
        install_bootloader_mock.return_value = {
            'command_status': 'FAILED', 'command_error': 'boom'}
        self.node.provision_state = states.DEPLOYING
        self.node.target_provision_state = states.ACTIVE
        self.node.save()
        with task_manager.acquire(self.context, self.node['uuid'],
                                  shared=False) as task:
            self.assertRaises(exception.InstanceDeployFailure,
                              self.deploy.configure_local_boot,
                              task, root_uuid='some-root-uuid')
            boot_mode_mock.assert_called_once_with(task.node)
            install_bootloader_mock.assert_called_once_with(
                mock.ANY, task.node, root_uuid='some-root-uuid',
                efi_system_part_uuid=None, prep_boot_part_uuid=None,
                target_boot_mode='whatever'
            )
            collect_logs_mock.assert_called_once_with(mock.ANY, task.node)
            self.assertEqual(states.DEPLOYFAIL, task.node.provision_state)
            self.assertEqual(states.ACTIVE, task.node.target_provision_state)


class TestSDFlexAgentDeploy(test_common.BaseSdflexTest):

    @mock.patch.object(agent.AgentDeploy, 'validate')
    def test_validate_valid_input(self, validate_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['bfpv'] = 'true'
            task.driver.deploy.validate(task)

    def test_validate_invalid_input(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['bfpv'] = 'true32424'
            self.assertRaises(exception.InvalidParameterValue,
                              task.driver.deploy.validate, task)

    @mock.patch.object(manager_utils, 'node_power_action', autospec=True)
    @mock.patch.object(noop_storage.NoopStorage, 'attach_volumes',
                       autospec=True)
    @mock.patch.object(deploy_utils, 'populate_storage_driver_internal_info')
    @mock.patch.object(boot.SdflexPXEBoot, 'prepare_ramdisk')
    @mock.patch.object(deploy_utils, 'build_agent_options')
    @mock.patch.object(deploy_utils, 'build_instance_info_for_deploy')
    @mock.patch.object(flat_network.FlatNetwork, 'add_provisioning_network',
                       spec_set=True, autospec=True)
    @mock.patch.object(flat_network.FlatNetwork,
                       'unconfigure_tenant_networks',
                       spec_set=True, autospec=True)
    @mock.patch.object(flat_network.FlatNetwork, 'validate',
                       spec_set=True, autospec=True)
    def test_prepare(
            self, validate_net_mock,
            unconfigure_tenant_net_mock, add_provisioning_net_mock,
            build_instance_info_mock, build_options_mock,
            pxe_prepare_ramdisk_mock, storage_driver_info_mock,
            storage_attach_volumes_mock, node_power_action):
        node = self.node
        node.network_interface = 'flat'
        node.save()
        with task_manager.acquire(
                self.context, self.node['uuid'], shared=False) as task:
            task.node.provision_state = states.DEPLOYING
            build_instance_info_mock.return_value = {'foo': 'bar'}
            build_options_mock.return_value = {'a': 'b'}
            task.driver.deploy.prepare(task)
            storage_driver_info_mock.assert_called_once_with(task)
            validate_net_mock.assert_called_once_with(mock.ANY, task)
            add_provisioning_net_mock.assert_called_once_with(mock.ANY, task)
            unconfigure_tenant_net_mock.assert_called_once_with(mock.ANY, task)
            storage_attach_volumes_mock.assert_called_once_with(
                task.driver.storage, task)
            build_options_mock.assert_called_once_with(task.node)
            pxe_prepare_ramdisk_mock.assert_called_once_with(
                task, {'a': 'b'})
        self.node.refresh()
        self.assertEqual('bar', self.node.instance_info['foo'])

    @mock.patch.object(manager_utils, 'node_power_action', autospec=True)
    @mock.patch.object(noop_storage.NoopStorage, 'attach_volumes',
                       autospec=True)
    @mock.patch.object(deploy_utils, 'populate_storage_driver_internal_info')
    @mock.patch.object(boot.SdflexPXEBoot, 'prepare_ramdisk')
    @mock.patch.object(deploy_utils, 'build_agent_options')
    @mock.patch.object(neutron_network.NeutronNetwork,
                       'add_provisioning_network',
                       spec_set=True, autospec=True)
    @mock.patch.object(neutron_network.NeutronNetwork,
                       'unconfigure_tenant_networks',
                       spec_set=True, autospec=True)
    @mock.patch.object(neutron_network.NeutronNetwork, 'validate',
                       spec_set=True, autospec=True)
    def test_prepare_with_neutron_net(
            self, validate_net_mock,
            unconfigure_tenant_net_mock, add_provisioning_net_mock,
            build_options_mock,
            pxe_prepare_ramdisk_mock, storage_driver_info_mock,
            storage_attach_volumes_mock, node_power_action_mock):
        node = self.node
        node.network_interface = 'neutron'
        node.save()
        with task_manager.acquire(
                self.context, self.node['uuid'], shared=False) as task:
            task.node.provision_state = states.DEPLOYING
            build_options_mock.return_value = {'a': 'b'}
            task.driver.deploy.prepare(task)
            storage_driver_info_mock.assert_called_once_with(task)
            validate_net_mock.assert_called_once_with(mock.ANY, task)
            add_provisioning_net_mock.assert_called_once_with(mock.ANY, task)
            unconfigure_tenant_net_mock.assert_called_once_with(mock.ANY, task)
            storage_attach_volumes_mock.assert_called_once_with(
                task.driver.storage, task)
            build_options_mock.assert_called_once_with(task.node)
            pxe_prepare_ramdisk_mock.assert_called_once_with(
                task, {'a': 'b'})
        self.node.refresh()
        self.assertEqual('bar', self.node.instance_info['foo'])

    @mock.patch.object(manager_utils, 'node_power_action', autospec=True)
    @mock.patch.object(noop_storage.NoopStorage, 'attach_volumes',
                       autospec=True)
    @mock.patch.object(deploy_utils, 'populate_storage_driver_internal_info')
    @mock.patch.object(boot.SdflexPXEBoot, 'prepare_ramdisk')
    @mock.patch.object(deploy_utils, 'build_agent_options')
    @mock.patch.object(neutron_network.NeutronNetwork,
                       'add_provisioning_network',
                       spec_set=True, autospec=True)
    @mock.patch.object(neutron_network.NeutronNetwork,
                       'unconfigure_tenant_networks',
                       spec_set=True, autospec=True)
    @mock.patch.object(neutron_network.NeutronNetwork, 'validate',
                       spec_set=True, autospec=True)
    def test_prepare_with_neutron_net_capabilities_as_string(
            self, validate_net_mock,
            unconfigure_tenant_net_mock, add_provisioning_net_mock,
            build_options_mock, pxe_prepare_ramdisk_mock,
            storage_driver_info_mock, storage_attach_volumes_mock,
            node_power_action_mock):
        node = self.node
        node.network_interface = 'neutron'
        instance_info = node.instance_info
        instance_info['capabilities'] = '{"lion": "roar"}'
        node.instance_info = instance_info
        node.save()
        validate_net_mock.side_effect = [
            exception.InvalidParameterValue('invalid'), None]
        with task_manager.acquire(
                self.context, self.node['uuid'], shared=False) as task:
            task.node.provision_state = states.DEPLOYING
            build_options_mock.return_value = {'a': 'b'}
            task.driver.deploy.prepare(task)
            storage_driver_info_mock.assert_called_once_with(task)
            self.assertEqual(2, validate_net_mock.call_count)
            add_provisioning_net_mock.assert_called_once_with(mock.ANY, task)
            unconfigure_tenant_net_mock.assert_called_once_with(mock.ANY, task)
            storage_attach_volumes_mock.assert_called_once_with(
                task.driver.storage, task)
            build_options_mock.assert_called_once_with(task.node)
            pxe_prepare_ramdisk_mock.assert_called_once_with(
                task, {'a': 'b'})
        self.node.refresh()
        capabilities = self.node.instance_info['capabilities']
        self.assertEqual('local', capabilities['boot_option'])
        self.assertEqual('roar', capabilities['lion'])

    @mock.patch.object(manager_utils, 'node_power_action', autospec=True)
    @mock.patch.object(noop_storage.NoopStorage, 'attach_volumes',
                       autospec=True)
    @mock.patch.object(deploy_utils, 'populate_storage_driver_internal_info')
    @mock.patch.object(boot.SdflexPXEBoot, 'prepare_ramdisk')
    @mock.patch.object(deploy_utils, 'build_agent_options')
    @mock.patch.object(neutron_network.NeutronNetwork,
                       'add_provisioning_network',
                       spec_set=True, autospec=True)
    @mock.patch.object(neutron_network.NeutronNetwork,
                       'unconfigure_tenant_networks',
                       spec_set=True, autospec=True)
    @mock.patch.object(neutron_network.NeutronNetwork, 'validate',
                       spec_set=True, autospec=True)
    def test_prepare_with_neutron_net_exc_no_capabilities(
            self, validate_net_mock, unconfigure_tenant_net_mock,
            add_provisioning_net_mock, build_options_mock,
            pxe_prepare_ramdisk_mock, storage_driver_info_mock,
            storage_attach_volumes_mock, node_power_action_mock):
        node = self.node
        node.network_interface = 'neutron'
        node.save()
        validate_net_mock.side_effect = [
            exception.InvalidParameterValue('invalid'), None]
        with task_manager.acquire(
                self.context, self.node['uuid'], shared=False) as task:
            task.node.provision_state = states.DEPLOYING
            build_options_mock.return_value = {'a': 'b'}
            task.driver.deploy.prepare(task)
            storage_driver_info_mock.assert_called_once_with(task)
            self.assertEqual(2, validate_net_mock.call_count)
            add_provisioning_net_mock.assert_called_once_with(mock.ANY, task)
            unconfigure_tenant_net_mock.assert_called_once_with(mock.ANY, task)
            storage_attach_volumes_mock.assert_called_once_with(
                task.driver.storage, task)
            build_options_mock.assert_called_once_with(task.node)
            pxe_prepare_ramdisk_mock.assert_called_once_with(
                task, {'a': 'b'})
        self.node.refresh()
        capabilities = self.node.instance_info['capabilities']
        self.assertEqual('local', capabilities['boot_option'])

    @mock.patch.object(manager_utils, 'node_power_action', autospec=True)
    @mock.patch.object(noop_storage.NoopStorage, 'attach_volumes',
                       autospec=True)
    @mock.patch.object(deploy_utils, 'populate_storage_driver_internal_info')
    @mock.patch.object(boot.SdflexPXEBoot, 'prepare_ramdisk')
    @mock.patch.object(deploy_utils, 'build_agent_options')
    @mock.patch.object(neutron_network.NeutronNetwork,
                       'add_provisioning_network',
                       spec_set=True, autospec=True)
    @mock.patch.object(neutron_network.NeutronNetwork,
                       'unconfigure_tenant_networks',
                       spec_set=True, autospec=True)
    @mock.patch.object(neutron_network.NeutronNetwork, 'validate',
                       spec_set=True, autospec=True)
    def test_prepare_with_neutron_net_exc_no_capabilities_overwrite(
            self, validate_net_mock, unconfigure_tenant_net_mock,
            add_provisioning_net_mock, build_options_mock,
            pxe_prepare_ramdisk_mock, storage_driver_info_mock,
            storage_attach_volumes_mock, node_power_action_mock):
        node = self.node
        node.network_interface = 'neutron'
        instance_info = node.instance_info
        instance_info['capabilities'] = {"cat": "meow"}
        node.instance_info = instance_info
        node.save()
        validate_net_mock.side_effect = [
            exception.InvalidParameterValue('invalid'), None]
        with task_manager.acquire(
                self.context, self.node['uuid'], shared=False) as task:
            task.node.provision_state = states.DEPLOYING
            build_options_mock.return_value = {'a': 'b'}
            task.driver.deploy.prepare(task)
            storage_driver_info_mock.assert_called_once_with(task)
            self.assertEqual(2, validate_net_mock.call_count)
            add_provisioning_net_mock.assert_called_once_with(mock.ANY, task)
            unconfigure_tenant_net_mock.assert_called_once_with(mock.ANY, task)
            storage_attach_volumes_mock.assert_called_once_with(
                task.driver.storage, task)
            build_options_mock.assert_called_once_with(task.node)
            pxe_prepare_ramdisk_mock.assert_called_once_with(
                task, {'a': 'b'})
        self.node.refresh()
        capabilities = self.node.instance_info['capabilities']
        self.assertEqual('local', capabilities['boot_option'])
        self.assertEqual('meow', capabilities['cat'])

    @mock.patch.object(noop_storage.NoopStorage, 'attach_volumes',
                       autospec=True)
    @mock.patch.object(deploy_utils, 'populate_storage_driver_internal_info')
    @mock.patch.object(boot.SdflexPXEBoot, 'prepare_ramdisk')
    @mock.patch.object(deploy_utils, 'build_agent_options')
    @mock.patch.object(deploy_utils, 'build_instance_info_for_deploy')
    @mock.patch.object(neutron_network.NeutronNetwork,
                       'add_provisioning_network',
                       spec_set=True, autospec=True)
    @mock.patch.object(neutron_network.NeutronNetwork,
                       'unconfigure_tenant_networks',
                       spec_set=True, autospec=True)
    @mock.patch.object(neutron_network.NeutronNetwork, 'validate',
                       spec_set=True, autospec=True)
    def test_prepare_with_neutron_net_exc_reraise(
            self, validate_net_mock,
            unconfigure_tenant_net_mock, add_provisioning_net_mock,
            build_instance_info_mock, build_options_mock,
            pxe_prepare_ramdisk_mock, storage_driver_info_mock,
            storage_attach_volumes_mock):
        node = self.node
        node.network_interface = 'neutron'
        instance_info = node.instance_info
        instance_info['capabilities'] = {"boot_option": "netboot"}
        node.instance_info = instance_info
        node.save()
        validate_net_mock.side_effect = (
            exception.InvalidParameterValue('invalid'))
        with task_manager.acquire(
                self.context, self.node['uuid'], shared=False) as task:
            task.node.provision_state = states.DEPLOYING
            self.assertRaises(exception.InvalidParameterValue,
                              task.driver.deploy.prepare,
                              task)
            storage_driver_info_mock.assert_called_once_with(task)
            validate_net_mock.assert_called_once_with(mock.ANY, task)
            self.assertFalse(add_provisioning_net_mock.called)
            self.assertFalse(unconfigure_tenant_net_mock.called)
            self.assertFalse(storage_attach_volumes_mock.called)
            self.assertFalse(build_instance_info_mock.called)
            self.assertFalse(build_options_mock.called)
            self.assertFalse(pxe_prepare_ramdisk_mock.called)
        self.node.refresh()
        capabilities = self.node.instance_info['capabilities']
        self.assertEqual('netboot', capabilities['boot_option'])

    @mock.patch.object(flat_network.FlatNetwork, 'add_provisioning_network',
                       spec_set=True, autospec=True)
    @mock.patch.object(flat_network.FlatNetwork, 'validate',
                       spec_set=True, autospec=True)
    @mock.patch.object(manager_utils, 'node_power_action', autospec=True)
    @mock.patch.object(boot.SdflexPXEBoot, 'prepare_ramdisk')
    @mock.patch.object(deploy_utils, 'build_agent_options')
    def test_prepare_manage_agent_boot_false(
            self, build_options_mock,
            pxe_prepare_ramdisk_mock, node_power_action_mock,
            validate_net_mock, add_provisioning_net_mock):
        self.config(group='agent', manage_agent_boot=False)
        node = self.node
        node.network_interface = 'flat'
        node.save()
        with task_manager.acquire(
                self.context, self.node['uuid'], shared=False) as task:
            task.node.provision_state = states.DEPLOYING

            task.driver.deploy.prepare(task)

            validate_net_mock.assert_called_once_with(mock.ANY, task)
            add_provisioning_net_mock.assert_called_once_with(mock.ANY, task)
            self.assertFalse(build_options_mock.called)
            self.assertFalse(pxe_prepare_ramdisk_mock.called)

        self.node.refresh()
        self.assertEqual('bar', self.node.instance_info['foo'])

    @mock.patch.object(manager_utils, 'node_power_action', autospec=True)
    @mock.patch.object(boot.SdflexPXEBoot, 'prepare_ramdisk')
    @mock.patch.object(deploy_utils, 'build_agent_options')
    @mock.patch.object(deploy_utils, 'build_instance_info_for_deploy')
    def _test_prepare_rescue_states(
            self, build_instance_info_mock, build_options_mock,
            pxe_prepare_ramdisk_mock, node_power_action_mock, prov_state):
        with task_manager.acquire(
                self.context, self.node['uuid'], shared=False) as task:
            task.node.provision_state = prov_state
            build_options_mock.return_value = {'a': 'b'}
            task.driver.deploy.prepare(task)
            self.assertFalse(build_instance_info_mock.called)
            build_options_mock.assert_called_once_with(task.node)
            pxe_prepare_ramdisk_mock.assert_called_once_with(
                task, {'a': 'b'})

    def test_prepare_rescue_states(self):
        for state in (states.RESCUING, states.RESCUEWAIT,
                      states.RESCUE, states.RESCUEFAIL):
            self._test_prepare_rescue_states(prov_state=state)
