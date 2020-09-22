# Copyright 2014 Rackspace, Inc.
# Copyright 2015 Red Hat, Inc.
# All Rights Reserved.
#
# Copyright 2020 Hewlett Packard Enterprise Development LP
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

from ironic.common import exception
from ironic.common import states
from ironic.conductor import task_manager
from ironic.drivers import base as drivers_base
from ironic.drivers.modules import agent
from ironic.drivers.modules import deploy_utils
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

    @mock.patch.object(deploy_utils, 'remove_http_instance_symlink',
                       autospec=True)
    @mock.patch.object(deploy.SDFlexAgentDeploy, 'prepare_instance_to_boot',
                       autospec=True)
    @mock.patch.object(agent.AgentDeploy, 'reboot_and_finish_deploy',
                       autospec=True)
    def test_reboot_to_instance_bfpv(self, reboot_and_finish_deploy_mock,
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
            reboot_and_finish_deploy_mock.assert_called_once_with(mock.ANY,
                                                                  task)
            self.assertEqual(states.ACTIVE, task.node.provision_state)
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
