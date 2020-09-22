# Copyright 2014 Rackspace, Inc.
# Copyright 2015 Red Hat, Inc.
# All Rights Reserved.
#
# Copyright 2020 Hewlett Packard Enterprise Development LP
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
#
# Hewlett Packard Enterprise made changes in this file.
# Some of the methods/code snippets in this file are owned by Rackspace, Inc
# Some of the methods/code snippets in this file are owned by Red Hat, Inc

import time
import types

import mock
from oslo_config import cfg

from ironic.common import exception
from ironic.common import states
from ironic.conductor import task_manager
from ironic.conductor import utils as manager_utils
from ironic.drivers import base as drivers_base
from ironic.drivers.modules import agent_client
from ironic.drivers.modules import deploy_utils
from ironic.drivers.modules import fake
from ironic.drivers import utils as driver_utils
from ironic.tests.unit.db import utils as db_utils
from ironic.tests.unit.objects import utils as object_utils

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

    @mock.patch.object(manager_utils, 'power_on_node_if_needed')
    @mock.patch.object(driver_utils, 'collect_ramdisk_logs', autospec=True)
    @mock.patch.object(time, 'sleep', lambda seconds: None)
    @mock.patch.object(manager_utils, 'node_power_action', autospec=True)
    @mock.patch.object(fake.FakePower, 'get_power_state',
                       spec=types.FunctionType)
    @mock.patch.object(agent_client.AgentClient, 'power_off',
                       spec=types.FunctionType)
    def test_reboot_and_finish_deploy(
            self, power_off_mock, get_power_state_mock,
            node_power_action_mock, collect_mock,
            power_on_node_if_needed_mock):
        cfg.CONF.set_override('deploy_logs_collect', 'always', 'agent')
        self.node.provision_state = states.DEPLOYING
        self.node.target_provision_state = states.ACTIVE
        self.node.save()
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            get_power_state_mock.side_effect = [states.POWER_ON,
                                                states.POWER_OFF]
            get_power_state_mock.call_count = 2
            power_on_node_if_needed_mock.return_value = None
            self.deploy.reboot_and_finish_deploy(task)
            power_off_mock.assert_called_once_with(task.node)
            self.assertEqual(2, get_power_state_mock.call_count)
            node_power_action_mock.assert_called_with(
                task, states.POWER_ON)
            self.assertEqual(states.ACTIVE, task.node.provision_state)
            collect_mock.assert_called_once_with(task.node)
#             resume_mock.assert_called_once_with(task)

    @mock.patch.object(manager_utils, 'power_on_node_if_needed',
                       autospec=True)
    @mock.patch.object(driver_utils, 'collect_ramdisk_logs', autospec=True)
    @mock.patch.object(time, 'sleep', lambda seconds: None)
    @mock.patch.object(manager_utils, 'node_power_action', autospec=True)
    @mock.patch.object(fake.FakePower, 'get_power_state',
                       spec=types.FunctionType)
    @mock.patch.object(agent_client.AgentClient, 'power_off',
                       spec=types.FunctionType)
    @mock.patch('ironic.drivers.modules.network.noop.NoopNetwork.'
                'remove_provisioning_network', spec_set=True, autospec=True)
    @mock.patch('ironic.drivers.modules.network.noop.NoopNetwork.'
                'configure_tenant_networks', spec_set=True, autospec=True)
    def test_reboot_and_finish_deploy_soft_poweroff_doesnt_complete(
            self, configure_tenant_net_mock, remove_provisioning_net_mock,
            power_off_mock, get_power_state_mock,
            node_power_action_mock, mock_collect,
            power_on_node_if_needed_mock):
        self.node.provision_state = states.DEPLOYING
        self.node.target_provision_state = states.ACTIVE
        self.node.save()
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            power_on_node_if_needed_mock.return_value = None
            get_power_state_mock.return_value = states.POWER_ON
            get_power_state_mock.call_count = 7
            self.deploy.reboot_and_finish_deploy(task)
            power_off_mock.assert_called_once_with(task.node)
            self.assertEqual(7, get_power_state_mock.call_count)
            node_power_action_mock.assert_has_calls([
                mock.call(task, states.POWER_OFF),
                mock.call(task, states.POWER_ON)])
            remove_provisioning_net_mock.assert_called_once_with(mock.ANY,
                                                                 task)
            configure_tenant_net_mock.assert_called_once_with(mock.ANY, task)
            self.assertEqual(states.ACTIVE, task.node.provision_state)
            self.assertFalse(mock_collect.called)

    @mock.patch.object(manager_utils, 'notify_conductor_resume_deploy',
                       autospec=True)
    @mock.patch.object(driver_utils, 'collect_ramdisk_logs', autospec=True)
    @mock.patch.object(time, 'sleep', lambda seconds: None)
    @mock.patch.object(manager_utils, 'node_power_action', autospec=True)
    @mock.patch.object(fake.FakePower, 'get_power_state',
                       spec=types.FunctionType)
    @mock.patch.object(agent_client.AgentClient, 'power_off',
                       spec=types.FunctionType)
    @mock.patch('ironic.drivers.modules.network.noop.NoopNetwork.'
                'remove_provisioning_network', spec_set=True, autospec=True)
    @mock.patch('ironic.drivers.modules.network.noop.NoopNetwork.'
                'configure_tenant_networks', spec_set=True, autospec=True)
    def test_reboot_and_finish_deploy_soft_poweroff_fails(
            self, configure_tenant_net_mock, remove_provisioning_net_mock,
            power_off_mock, get_power_state_mock, node_power_action_mock,
            mock_collect, resume_mock):
        power_off_mock.side_effect = RuntimeError("boom")
        self.node.provision_state = states.DEPLOYING
        self.node.target_provision_state = states.ACTIVE
        self.node.save()
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            get_power_state_mock.return_value = states.POWER_ON
            self.deploy.reboot_and_finish_deploy(task)
            power_off_mock.assert_called_once_with(task.node)
            node_power_action_mock.assert_has_calls([
                mock.call(task, states.POWER_OFF),
                mock.call(task, states.POWER_ON)])
            remove_provisioning_net_mock.assert_called_once_with(mock.ANY,
                                                                 task)
            configure_tenant_net_mock.assert_called_once_with(mock.ANY, task)
            self.assertEqual(states.ACTIVE, task.node.provision_state)
            self.assertFalse(mock_collect.called)

    @mock.patch.object(manager_utils, 'notify_conductor_resume_deploy',
                       autospec=True)
    @mock.patch.object(driver_utils, 'collect_ramdisk_logs', autospec=True)
    @mock.patch.object(time, 'sleep', lambda seconds: None)
    @mock.patch.object(manager_utils, 'node_power_action', autospec=True)
    @mock.patch.object(fake.FakePower, 'get_power_state',
                       spec=types.FunctionType)
    @mock.patch.object(agent_client.AgentClient, 'power_off',
                       spec=types.FunctionType)
    @mock.patch('ironic.drivers.modules.network.noop.NoopNetwork.'
                'remove_provisioning_network', spec_set=True, autospec=True)
    @mock.patch('ironic.drivers.modules.network.noop.NoopNetwork.'
                'configure_tenant_networks', spec_set=True, autospec=True)
    def test_reboot_and_finish_deploy_soft_poweroff_race(
            self, configure_tenant_net_mock, remove_provisioning_net_mock,
            power_off_mock, get_power_state_mock, node_power_action_mock,
            mock_collect, resume_mock):
        # Test the situation when soft power off works, but ironic doesn't
        # learn about it.
        power_off_mock.side_effect = RuntimeError("boom")
        self.node.provision_state = states.DEPLOYING
        self.node.target_provision_state = states.ACTIVE
        self.node.save()
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            get_power_state_mock.side_effect = [states.POWER_ON,
                                                states.POWER_OFF]
            self.deploy.reboot_and_finish_deploy(task)
            power_off_mock.assert_called_once_with(task.node)
            remove_provisioning_net_mock.assert_called_once_with(mock.ANY,
                                                                 task)
            configure_tenant_net_mock.assert_called_once_with(mock.ANY, task)
            self.assertEqual(states.ACTIVE, task.node.provision_state)
            self.assertFalse(mock_collect.called)

    @mock.patch.object(manager_utils, 'power_on_node_if_needed')
    @mock.patch.object(manager_utils, 'notify_conductor_resume_deploy',
                       autospec=True)
    @mock.patch.object(driver_utils, 'collect_ramdisk_logs', autospec=True)
    @mock.patch.object(time, 'sleep', lambda seconds: None)
    @mock.patch.object(manager_utils, 'node_power_action', autospec=True)
    @mock.patch.object(fake.FakePower, 'get_power_state',
                       spec=types.FunctionType)
    @mock.patch.object(agent_client.AgentClient, 'power_off',
                       spec=types.FunctionType)
    @mock.patch('ironic.drivers.modules.network.noop.NoopNetwork.'
                'remove_provisioning_network', spec_set=True, autospec=True)
    @mock.patch('ironic.drivers.modules.network.noop.NoopNetwork.'
                'configure_tenant_networks', spec_set=True, autospec=True)
    def test_reboot_and_finish_deploy_get_power_state_fails(
            self, configure_tenant_net_mock, remove_provisioning_net_mock,
            power_off_mock, get_power_state_mock, node_power_action_mock,
            mock_collect, resume_mock, power_on_node_if_needed_mock):
        self.node.provision_state = states.DEPLOYING
        self.node.target_provision_state = states.ACTIVE
        self.node.save()
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            get_power_state_mock.side_effect = RuntimeError("boom")
            power_on_node_if_needed_mock.return_value = None
            self.deploy.reboot_and_finish_deploy(task)
            power_off_mock.assert_called_once_with(task.node)
            node_power_action_mock.assert_has_calls([
                mock.call(task, states.POWER_OFF),
                mock.call(task, states.POWER_ON)])
            remove_provisioning_net_mock.assert_called_once_with(mock.ANY,
                                                                 task)
            configure_tenant_net_mock.assert_called_once_with(mock.ANY, task)
            self.assertEqual(states.ACTIVE, task.node.provision_state)
            self.assertFalse(mock_collect.called)

    @mock.patch.object(manager_utils, 'power_on_node_if_needed',
                       autospec=True)
    @mock.patch.object(driver_utils, 'collect_ramdisk_logs', autospec=True)
    @mock.patch.object(time, 'sleep', lambda seconds: None)
    @mock.patch.object(manager_utils, 'node_power_action', autospec=True)
    @mock.patch.object(fake.FakePower, 'get_power_state',
                       spec=types.FunctionType)
    @mock.patch.object(agent_client.AgentClient, 'power_off',
                       spec=types.FunctionType)
    @mock.patch('ironic.drivers.modules.network.neutron.NeutronNetwork.'
                'remove_provisioning_network', spec_set=True, autospec=True)
    @mock.patch('ironic.drivers.modules.network.neutron.NeutronNetwork.'
                'configure_tenant_networks', spec_set=True, autospec=True)
    def test_reboot_and_finish_deploy_configure_tenant_network_exception(
            self, configure_tenant_net_mock, remove_provisioning_net_mock,
            power_off_mock, get_power_state_mock, node_power_action_mock,
            mock_collect, power_on_node_if_needed_mock):
        self.node.network_interface = 'neutron'
        self.node.provision_state = states.DEPLOYING
        self.node.target_provision_state = states.ACTIVE
        self.node.save()
        power_on_node_if_needed_mock.return_value = None
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            configure_tenant_net_mock.side_effect = exception.NetworkError(
                "boom")
            self.assertRaises(exception.InstanceDeployFailure,
                              self.deploy.reboot_and_finish_deploy, task)
            remove_provisioning_net_mock.assert_called_once_with(mock.ANY,
                                                                 task)
            configure_tenant_net_mock.assert_called_once_with(mock.ANY, task)
            self.assertEqual(states.DEPLOYFAIL, task.node.provision_state)
            self.assertEqual(states.ACTIVE, task.node.target_provision_state)
            self.assertFalse(mock_collect.called)

    @mock.patch.object(driver_utils, 'collect_ramdisk_logs', autospec=True)
    @mock.patch.object(time, 'sleep', lambda seconds: None)
    @mock.patch.object(manager_utils, 'node_power_action', autospec=True)
    @mock.patch.object(fake.FakePower, 'get_power_state',
                       spec=types.FunctionType)
    @mock.patch.object(agent_client.AgentClient, 'power_off',
                       spec=types.FunctionType)
    def test_reboot_and_finish_deploy_power_off_fails(
            self, power_off_mock, get_power_state_mock,
            node_power_action_mock, mock_collect):
        self.node.provision_state = states.DEPLOYING
        self.node.target_provision_state = states.ACTIVE
        self.node.save()
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            get_power_state_mock.return_value = states.POWER_ON
            node_power_action_mock.side_effect = RuntimeError("boom")
            self.assertRaises(exception.InstanceDeployFailure,
                              self.deploy.reboot_and_finish_deploy,
                              task)
            power_off_mock.assert_called_once_with(task.node)
            node_power_action_mock.assert_has_calls([
                mock.call(task, states.POWER_OFF)])
            self.assertEqual(states.DEPLOYFAIL, task.node.provision_state)
            self.assertEqual(states.ACTIVE, task.node.target_provision_state)
            mock_collect.assert_called_once_with(task.node)

    @mock.patch.object(manager_utils, 'power_on_node_if_needed',
                       autospec=True)
    @mock.patch.object(driver_utils, 'collect_ramdisk_logs', autospec=True)
    @mock.patch.object(time, 'sleep', lambda seconds: None)
    @mock.patch.object(manager_utils, 'node_power_action', autospec=True)
    @mock.patch.object(fake.FakePower, 'get_power_state',
                       spec=types.FunctionType)
    @mock.patch.object(agent_client.AgentClient, 'power_off',
                       spec=types.FunctionType)
    @mock.patch('ironic.drivers.modules.network.noop.NoopNetwork.'
                'remove_provisioning_network', spec_set=True, autospec=True)
    @mock.patch('ironic.drivers.modules.network.noop.NoopNetwork.'
                'configure_tenant_networks', spec_set=True, autospec=True)
    def test_reboot_and_finish_deploy_power_on_fails(
            self, configure_tenant_net_mock, remove_provisioning_net_mock,
            power_off_mock, get_power_state_mock,
            node_power_action_mock, mock_collect,
            power_on_node_if_needed_mock):
        self.node.provision_state = states.DEPLOYING
        self.node.target_provision_state = states.ACTIVE
        self.node.save()
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            power_on_node_if_needed_mock.return_value = None
            get_power_state_mock.return_value = states.POWER_ON
            node_power_action_mock.side_effect = [None,
                                                  RuntimeError("boom")]
            self.assertRaises(exception.InstanceDeployFailure,
                              self.deploy.reboot_and_finish_deploy,
                              task)
            power_off_mock.assert_called_once_with(task.node)
#             self.assertEqual(7, get_power_state_mock.call_count)
            node_power_action_mock.assert_has_calls([
                mock.call(task, states.POWER_OFF),
                mock.call(task, states.POWER_ON)])
            remove_provisioning_net_mock.assert_called_once_with(mock.ANY,
                                                                 task)
            configure_tenant_net_mock.assert_called_once_with(mock.ANY, task)
            self.assertEqual(states.DEPLOYFAIL, task.node.provision_state)
            self.assertEqual(states.ACTIVE, task.node.target_provision_state)
            self.assertFalse(mock_collect.called)

    @mock.patch.object(driver_utils, 'collect_ramdisk_logs', autospec=True)
    @mock.patch.object(manager_utils, 'node_power_action', autospec=True)
    @mock.patch.object(agent_client.AgentClient, 'sync',
                       spec=types.FunctionType)
    def test_reboot_and_finish_deploy_power_action_oob_power_off(
            self, sync_mock, node_power_action_mock, mock_collect):
        # Enable force power off
        driver_info = self.node.driver_info
        driver_info['deploy_forces_oob_reboot'] = True
        self.node.driver_info = driver_info

        self.node.provision_state = states.DEPLOYING
        self.node.target_provision_state = states.ACTIVE
        self.node.save()
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            self.deploy.reboot_and_finish_deploy(task)

            sync_mock.assert_called_once_with(task.node)
            node_power_action_mock.assert_has_calls([
                mock.call(task, states.POWER_OFF),
                mock.call(task, states.POWER_ON),
            ])
            self.assertEqual(states.ACTIVE, task.node.provision_state)
            self.assertFalse(mock_collect.called)

    @mock.patch.object(manager_utils, 'notify_conductor_resume_deploy',
                       autospec=True)
    @mock.patch.object(driver_utils, 'collect_ramdisk_logs', autospec=True)
    @mock.patch.object(manager_utils, 'node_power_action', autospec=True)
    @mock.patch.object(agent_client.AgentClient, 'sync',
                       spec=types.FunctionType)
    def test_reboot_and_finish_deploy_power_action_oob_power_off_failed(
            self, sync_mock, node_power_action_mock, mock_collect,
            resume_mock):
        # Enable force power off
        driver_info = self.node.driver_info
        driver_info['deploy_forces_oob_reboot'] = True
        self.node.driver_info = driver_info

        self.node.provision_state = states.DEPLOYING
        self.node.target_provision_state = states.ACTIVE
        self.node.save()
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            sync_mock.return_value = {'faultstring': 'Unknown command: blah'}
            self.deploy.reboot_and_finish_deploy(task)

            sync_mock.assert_called_once_with(task.node)
            node_power_action_mock.assert_has_calls([
                mock.call(task, states.POWER_OFF),
                mock.call(task, states.POWER_ON),
            ])
            self.assertEqual(states.ACTIVE, task.node.provision_state)
            self.assertFalse(mock_collect.called)

    @mock.patch.object(deploy_utils, 'remove_http_instance_symlink',
                       autospec=True)
    @mock.patch.object(deploy.SDFlexAgentDeploy, 'prepare_instance_to_boot',
                       autospec=True)
    @mock.patch.object(deploy.SDFlexAgentDeploy, 'reboot_and_finish_deploy',
                       autospec=True)
    def test_reboot_to_instance_bfv(self, reboot_and_finish_deploy_mock,
                                    prepare_instance_mock,
                                    remove_symlink_mock):
        self.config(manage_agent_boot=True, group='agent')
        self.config(image_download_source='http', group='agent')
        self.node.provision_state = states.DEPLOYWAIT
        self.node.target_provision_state = states.ACTIVE
        self.node.save()
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:

            task.driver.deploy.reboot_to_instance_bfv(task)
            prepare_instance_mock.assert_called_once_with(mock.ANY, task,
                                                          None, None, None)
            self.assertEqual(states.DEPLOYING, task.node.provision_state)
            self.assertEqual(states.ACTIVE, task.node.target_provision_state)
            self.assertTrue(remove_symlink_mock.called)

    @mock.patch.object(deploy.SDFlexAgentDeploy, 'reboot_to_instance_bfv')
    def test_heartbeat_bfv(self, rti_bfv_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['bfv'] = True
            task.node.driver_internal_info['bfv_started'] = False
            task.driver.deploy.heartbeat(task, 'url', '3.2.0')
            rti_bfv_mock.assert_called_once_with(task)

    def test_heartbeat_bfv_started(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['bfv'] = True
            task.node.driver_internal_info['bfv_started'] = True
            task.driver.deploy.heartbeat(task, 'url', '3.2.0')

    @mock.patch.object(deploy.SDFlexAgentDeploy, 'heartbeat')
    def test_heartbeat_bfv_false(self, heartbeat_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['bfv'] = False
            task.node.driver_internal_info['bfv_started'] = False
            task.driver.deploy.heartbeat(task, 'url', '3.2.0')
            heartbeat_mock.assert_called_once_with(task, 'url', '3.2.0')
