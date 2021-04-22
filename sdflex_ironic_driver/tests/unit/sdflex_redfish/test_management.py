# Copyright 2014 Hewlett-Packard Development Company, L.P.
# Copyright 2020-2021 Hewlett Packard Enterprise Development LP
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

from ironic.common import states
from ironic.conductor import task_manager
from ironic.drivers.modules import agent_base
from ironic.drivers import utils as driver_utils

from sdflex_ironic_driver.sdflex_redfish import management as sdflex_management
from sdflex_ironic_driver.tests.unit.sdflex_redfish import test_common \
    as sdflex_common


class SDFlexManagementTestCase(sdflex_common.BaseSdflexTest):

    def setUp(self):
        super(SDFlexManagementTestCase, self).setUp()

    @mock.patch.object(agent_base, 'execute_step', autospec=True)
    def _test_do_update_firmware_sum(self, execute_mock, step_type='clean'):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            execute_mock.return_value = states.CLEANWAIT
            # | GIVEN |
            firmware_update_args = {
                'url': 'http://any_url',
                'checksum': 'xxxx'}
            step = {'interface': 'management',
                    'args': firmware_update_args}
            if step_type == 'clean':
                step['step'] = 'update_firmware_sum'
                task.node.provision_state = states.CLEANING
                execute_mock.return_value = states.CLEANWAIT
                task.node.clean_step = step
                func = task.driver.management.update_firmware_sum
                exp_ret_state = states.CLEANWAIT
            else:
                step['step'] = 'flash_firmware_sum'
                task.node.provision_state = states.DEPLOYING
                execute_mock.return_value = states.DEPLOYWAIT
                task.node.deploy_step = step
                func = task.driver.management.flash_firmware_sum
                exp_ret_state = states.DEPLOYWAIT
            # | WHEN |
            return_value = func(task, **firmware_update_args)
            # | THEN |
            self.assertEqual(exp_ret_state, return_value)
            execute_mock.assert_called_once_with(task, step, step_type)

    def test_update_firmware_sum(self):
        self._test_do_update_firmware_sum(step_type='clean')

    def test_flash_firmware_sum(self):
        self._test_do_update_firmware_sum(step_type='deploy')

    @mock.patch.object(driver_utils, 'store_ramdisk_logs')
    def _test__update_firmware_sum_final_with_logs(self, store_mock,
                                                   step_type='clean'):
        self.config(deploy_logs_collect='always', group='agent')
        firmware_update_args = {
            'url': 'any_valid_url',
            'checksum': 'xxxx'}
        step = {'interface': 'management',
                'args': firmware_update_args}
        if step_type == 'clean':
            step['step'] = 'update_firmware_sum'
            node_state = states.CLEANWAIT
            command = {
                'command_status': 'SUCCEEDED',
                'command_result': {
                    'clean_result': {'Log Data': 'aaaabbbbcccdddd'},
                    'clean_step': step,
                }
            }
            exp_label = 'update_firmware_sum'
        else:
            step['step'] = 'flash_firmware_sum'
            node_state = states.DEPLOYWAIT
            command = {
                'command_status': 'SUCCEEDED',
                'command_result': {
                    'deploy_result': {'Log Data': 'aaaabbbbcccdddd'},
                    'deploy_step': step,
                }
            }
            exp_label = 'flash_firmware_sum'
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.provision_state = node_state
            task.driver.management._update_firmware_sum_final(
                task, command)
            store_mock.assert_called_once_with(task.node, 'aaaabbbbcccdddd',
                                               label=exp_label)

    def test__update_firmware_sum_final_with_logs_clean(self):
        self._test__update_firmware_sum_final_with_logs(step_type='clean')

    def test__write_firmware_sum_final_with_logs_deploy(self):
        self._test__update_firmware_sum_final_with_logs(step_type='deploy')

    @mock.patch.object(driver_utils, 'store_ramdisk_logs')
    def _test__update_firmware_sum_final_without_logs(self, store_mock,
                                                      step_type='clean'):
        self.config(deploy_logs_collect='on_failure', group='agent')
        firmware_update_args = {
            'url': 'any_valid_url',
            'checksum': 'xxxx'}
        step = {'interface': 'management',
                'args': firmware_update_args}
        if step_type == 'clean':
            step['step'] = 'update_firmware_sum'
            command = {
                'command_status': 'SUCCEEDED',
                'command_result': {
                    'clean_result': {'Log Data': 'aaaabbbbcccdddd'},
                    'clean_step': step,
                }
            }
        else:
            step['step'] = 'flash_firmware_sum'
            command = {
                'command_status': 'SUCCEEDED',
                'command_result': {
                    'deploy_result': {'Log Data': 'aaaabbbbcccdddd'},
                    'deploy_step': step,
                }
            }
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.driver.management._update_firmware_sum_final(
                task, command)
        self.assertFalse(store_mock.called)

    def test__update_firmware_sum_final_without_logs_clean(self):
        self._test__update_firmware_sum_final_without_logs(step_type='clean')

    def test__update_firmware_sum_final_without_logs_deploy(self):
        self._test__update_firmware_sum_final_without_logs(step_type='deploy')

    @mock.patch.object(sdflex_management, 'LOG', spec_set=True, autospec=True)
    @mock.patch.object(driver_utils, 'store_ramdisk_logs')
    def _test__update_firmware_sum_final_environment_error(self, store_mock,
                                                           log_mock,
                                                           step_type='clean'):
        self.config(deploy_logs_collect='always', group='agent')
        firmware_update_args = {
            'url': 'any_valid_url',
            'checksum': 'xxxx'}
        step = {'interface': 'management',
                'args': firmware_update_args}
        if step_type == 'clean':
            step['step'] = 'update_firmware_sum'
            node_state = states.CLEANWAIT
            command = {
                'command_status': 'SUCCEEDED',
                'command_result': {
                    'clean_result': {'Log Data': 'aaaabbbbcccdddd'},
                    'clean_step': step,
                }
            }
        else:
            step['step'] = 'flash_firmware_sum'
            node_state = states.DEPLOYWAIT
            command = {
                'command_status': 'SUCCEEDED',
                'command_result': {
                    'deploy_result': {'Log Data': 'aaaabbbbcccdddd'},
                    'deploy_step': step,
                }
            }
        store_mock.side_effect = EnvironmentError('Error')

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.provision_state = node_state
            task.driver.management._update_firmware_sum_final(
                task, command)
        self.assertTrue(log_mock.exception.called)

    def test__update_firmware_sum_final_environment_error_clean(self):
        self._test__update_firmware_sum_final_environment_error(
            step_type='clean')

    def test__update_firmware_sum_final_environment_error_deploy(self):
        self._test__update_firmware_sum_final_environment_error(
            step_type='deploy')

    @mock.patch.object(sdflex_management, 'LOG', spec_set=True, autospec=True)
    @mock.patch.object(driver_utils, 'store_ramdisk_logs')
    def _test__update_firmware_sum_final_unknown_exception(self, store_mock,
                                                           log_mock,
                                                           step_type='clean'):
        self.config(deploy_logs_collect='always', group='agent')
        firmware_update_args = {
            'url': 'any_valid_url',
            'checksum': 'xxxx'}
        step = {'interface': 'management',
                'args': firmware_update_args}
        if step_type == 'clean':
            step['step'] = 'update_firmware_sum'
            node_state = states.CLEANWAIT
            command = {
                'command_status': 'SUCCEEDED',
                'command_result': {
                    'clean_result': {'Log Data': 'aaaabbbbcccdddd'},
                    'clean_step': step,
                }
            }
        else:
            step['step'] = 'flash_firmware_sum'
            node_state = states.DEPLOYWAIT
            command = {
                'command_status': 'SUCCEEDED',
                'command_result': {
                    'deploy_result': {'Log Data': 'aaaabbbbcccdddd'},
                    'deploy_step': step,
                }
            }
        store_mock.side_effect = Exception('Error')

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.provision_state = node_state
            task.driver.management._update_firmware_sum_final(
                task, command)
        self.assertTrue(log_mock.exception.called)

    def test__update_firmware_sum_final_unknown_exception_clean(self):
        self._test__update_firmware_sum_final_unknown_exception(
            step_type='clean')

    def test__update_firmware_sum_final_unknown_exception_deploy(self):
        self._test__update_firmware_sum_final_unknown_exception(
            step_type='deploy')
