# Copyright 2014-2020 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Test class for Management Interface used by Sdflex modules."""

import mock
from oslo_utils import importutils
from oslo_utils import uuidutils

from ironic.common import boot_devices
from ironic.common import exception
from ironic.common import states
from ironic.conductor import task_manager
from ironic.conductor import utils as manager_utils
from ironic.drivers.modules import agent_base
from ironic.drivers.modules import deploy_utils
from ironic.drivers.modules.ilo import boot as ilo_boot
from ironic.drivers.modules.ilo import common as ilo_common
from ironic.drivers.modules.ilo import management as ilo_management
from ironic.drivers.modules import ipmitool
from ironic.drivers import utils as driver_utils
from ironic.tests.unit.db import base as db_base
from ironic.tests.unit.db import utils as db_utils
from ironic.tests.unit.drivers.modules.ilo import test_common
from ironic.tests.unit.objects import utils as obj_utils




class SDFlexManagementTestCase(test_common.BaseIloTest):

    def setUp(self):
        super(SDFlexManagementTestCase, self).setUp()

    @mock.patch.object(agent_base, 'execute_clean_step', autospec=True)
    def test_update_firmware_sum_mode(self, execute_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            execute_mock.return_value = states.CLEANWAIT
            # | GIVEN |
            firmware_update_args = {
                'url': 'http://any_url',
                'checksum': 'xxxx'}
            clean_step = {'step': 'update_firmware_sum',
                          'interface': 'management',
                          'args': firmware_update_args}
            task.node.clean_step = clean_step
            # | WHEN |
            return_value = task.driver.management.update_firmware_sum(
                task, **firmware_update_args)
            # | THEN |
            self.assertEqual(states.CLEANWAIT, return_value)
            execute_mock.assert_called_once_with(task, clean_step)


    @mock.patch.object(driver_utils, 'store_ramdisk_logs')
    def test__update_firmware_sum_final_with_logs(self, store_mock):
        self.config(deploy_logs_collect='always', group='agent')
        command = {'command_status': 'SUCCEEDED',
                   'command_result': {
                       'clean_result': {'Log Data': 'aaaabbbbcccdddd'}}
                   }
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.driver.management._update_firmware_sum_final(
                task, command)
            store_mock.assert_called_once_with(task.node, 'aaaabbbbcccdddd',
                                               label='update_firmware_sum')

    @mock.patch.object(driver_utils, 'store_ramdisk_logs')
    def test__update_firmware_sum_final_without_logs(self, store_mock):
        self.config(deploy_logs_collect='on_failure', group='agent')
        command = {'command_status': 'SUCCEEDED',
                   'command_result': {
                       'clean_result': {'Log Data': 'aaaabbbbcccdddd'}}
                   }
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.driver.management._update_firmware_sum_final(
                task, command)
        self.assertFalse(store_mock.called)

    @mock.patch.object(sdflex_management, 'LOG', spec_set=True, autospec=True)
    @mock.patch.object(driver_utils, 'store_ramdisk_logs')
    def test__update_firmware_sum_final_environment_error(self, store_mock,
                                                          log_mock):
        self.config(deploy_logs_collect='always', group='agent')
        command = {'command_status': 'SUCCEEDED',
                   'command_result': {
                       'clean_result': {'Log Data': 'aaaabbbbcccdddd'}}
                   }
        store_mock.side_effect = EnvironmentError('Error')

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.driver.management._update_firmware_sum_final(
                task, command)
        self.assertTrue(log_mock.exception.called)

    @mock.patch.object(sdflex_management, 'LOG', spec_set=True, autospec=True)
    @mock.patch.object(driver_utils, 'store_ramdisk_logs')
    def test__update_firmware_sum_final_unknown_exception(self, store_mock,
                                                          log_mock):
        self.config(deploy_logs_collect='always', group='agent')
        command = {'command_status': 'SUCCEEDED',
                   'command_result': {
                       'clean_result': {'Log Data': 'aaaabbbbcccdddd'}}
                   }
        store_mock.side_effect = Exception('Error')

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.driver.management._update_firmware_sum_final(
                task, command)
        self.assertTrue(log_mock.exception.called)
