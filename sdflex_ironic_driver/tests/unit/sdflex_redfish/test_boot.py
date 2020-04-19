# Copyright 2015 Hewlett-Packard Development Company, L.P.
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
#
# Hewlett Packard Enterprise made changes in this file.

"""Test class for boot methods used by sdflex modules."""

import mock
from oslo_config import cfg
import six

from ironic.common import exception
from ironic.common import states
from ironic.conductor import task_manager
from ironic.conductor import utils as manager_utils
from ironic.drivers.modules import pxe

from sdflex_ironic_driver.sdflex_redfish import boot as sdflex_boot
from sdflex_ironic_driver.sdflex_redfish import common as sdflex_common
from sdflex_ironic_driver.tests.unit.sdflex_redfish import test_common


if six.PY3:
    import io
    file = io.BytesIO

CONF = cfg.CONF


class SdflexBootPrivateMethodsTestCase(test_common.BaseSdflexTest):

    boot_interface = 'sdflex-redfish'

    @mock.patch.object(sdflex_common, 'set_secure_boot_mode', spec_set=True,
                       autospec=True)
    @mock.patch.object(sdflex_common, 'get_secure_boot_mode', spec_set=True,
                       autospec=True)
    def test__disable_secure_boot_false(self,
                                        func_get_secure_boot_mode,
                                        func_set_secure_boot_mode):
        func_get_secure_boot_mode.return_value = False
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            sdflex_boot._disable_secure_boot(task)
            func_get_secure_boot_mode.assert_called_once_with(task)
            self.assertFalse(func_set_secure_boot_mode.called)

    @mock.patch.object(sdflex_common, 'set_secure_boot_mode', spec_set=True,
                       autospec=True)
    @mock.patch.object(sdflex_common, 'get_secure_boot_mode', spec_set=True,
                       autospec=True)
    def test__disable_secure_boot_true(self,
                                       func_get_secure_boot_mode,
                                       func_set_secure_boot_mode):
        func_get_secure_boot_mode.return_value = True
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            sdflex_boot._disable_secure_boot(task)
            func_get_secure_boot_mode.assert_called_once_with(task)
            func_set_secure_boot_mode.assert_called_once_with(task, False)

    @mock.patch.object(sdflex_boot, 'exception', spec_set=True, autospec=True)
    @mock.patch.object(sdflex_common, 'get_secure_boot_mode', spec_set=True,
                       autospec=True)
    def test__disable_secure_boot_exception(self,
                                            func_get_secure_boot_mode,
                                            exception_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            exception_mock.SDFlexOperationNotSupported = Exception
            func_get_secure_boot_mode.side_effect = Exception
            sdflex_boot._disable_secure_boot(task)
            func_get_secure_boot_mode.assert_called_once_with(task)

    @mock.patch.object(sdflex_boot, '_disable_secure_boot', spec_set=True,
                       autospec=True)
    @mock.patch.object(manager_utils, 'node_power_action', spec_set=True,
                       autospec=True)
    def test_prepare_node_for_deploy(self,
                                     func_node_power_action,
                                     func_disable_secure_boot):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_directed_lanboot'] = 'False'
            sdflex_boot.prepare_node_for_deploy(task)
            func_node_power_action.assert_called_once_with(task,
                                                           states.POWER_OFF)
            func_disable_secure_boot.assert_called_once_with(task)

    @mock.patch.object(sdflex_common, 'enable_directed_lan_boot',
                       spec_set=True, autospec=True)
    @mock.patch.object(sdflex_boot, '_disable_secure_boot', spec_set=True,
                       autospec=True)
    @mock.patch.object(manager_utils, 'node_power_action', spec_set=True,
                       autospec=True)
    def test_prepare_node_for_deploy_directed_lanboot_enable(
            self, func_node_power_action, func_disable_secure_boot,
            func_enable_dlan):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_directed_lanboot'] = 'True'
            sdflex_boot.prepare_node_for_deploy(task)
            func_node_power_action.assert_called_once_with(task,
                                                           states.POWER_OFF)
            func_disable_secure_boot.assert_called_once_with(task)

    @mock.patch.object(sdflex_boot, '_disable_secure_boot', spec_set=True,
                       autospec=True)
    @mock.patch.object(manager_utils, 'node_power_action', spec_set=True,
                       autospec=True)
    def test_prepare_node_for_deploy_directed_lanboot_disable(
            self, func_node_power_action, func_disable_secure_boot):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_directed_lanboot'] = 'False'
            sdflex_boot.prepare_node_for_deploy(task)
            func_node_power_action.assert_called_once_with(task,
                                                           states.POWER_OFF)
            func_disable_secure_boot.assert_called_once_with(task)


class SdflexPXEBootTestCase(test_common.BaseSdflexTest):

    boot_interface = 'sdflex-redfish'

    @mock.patch.object(sdflex_boot, 'prepare_node_for_deploy', spec_set=True,
                       autospec=True)
    @mock.patch.object(pxe.PXEBoot, 'prepare_ramdisk', spec_set=True,
                       autospec=True)
    def _test_prepare_ramdisk_needs_node_prep(self, pxe_prepare_ramdisk_mock,
                                              prepare_node_mock, prov_state):
        self.node.provision_state = prov_state
        self.node.save()
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            self.assertIsNone(
                task.driver.boot.prepare_ramdisk(task, None))

            prepare_node_mock.assert_called_once_with(task)
            pxe_prepare_ramdisk_mock.assert_called_once_with(
                mock.ANY, task, None)

    def test_prepare_ramdisk_in_deploying(self):
        self._test_prepare_ramdisk_needs_node_prep(prov_state=states.DEPLOYING)

    def test_prepare_ramdisk_in_rescuing(self):
        self._test_prepare_ramdisk_needs_node_prep(prov_state=states.RESCUING)

    def test_prepare_ramdisk_in_cleaning(self):
        self._test_prepare_ramdisk_needs_node_prep(prov_state=states.CLEANING)

    @mock.patch.object(sdflex_boot, 'prepare_node_for_deploy', spec_set=True,
                       autospec=True)
    @mock.patch.object(pxe.PXEBoot, 'prepare_ramdisk', spec_set=True,
                       autospec=True)
    def _test_prepare_ramdisk_does_not_need_node_prep(self,
                                                      pxe_prepare_ramdisk_mock,
                                                      prepare_node_mock,
                                                      prov_state):
        self.node.provision_state = prov_state
        self.node.save()
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            self.assertIsNone(
                task.driver.boot.prepare_ramdisk(task, None))

            assert prepare_node_mock.call_count == 0
            pxe_prepare_ramdisk_mock.assert_called_once_with(
                mock.ANY, task, None)

    def test_prepare_ramdisk_in_inspecting(self):
        self._test_prepare_ramdisk_does_not_need_node_prep(
            prov_state=states.INSPECTING)

    @mock.patch.object(sdflex_boot, 'disable_secure_boot_if_supported',
                       spec_set=True, autospec=True)
    @mock.patch.object(manager_utils, 'node_power_action', spec_set=True,
                       autospec=True)
    @mock.patch.object(pxe.PXEBoot, 'clean_up_instance', spec_set=True,
                       autospec=True)
    def test_clean_up_instance(self, pxe_cleanup_mock, node_power_mock,
                               disable_secure_boot_if_supported_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_directed_lanboot'] = 'False'
            task.driver.boot.clean_up_instance(task)
            node_power_mock.assert_called_once_with(task, states.POWER_OFF)
            disable_secure_boot_if_supported_mock.assert_called_once_with(task)
            pxe_cleanup_mock.assert_called_once_with(mock.ANY, task)

    @mock.patch.object(sdflex_common, 'update_secure_boot_mode', spec_set=True,
                       autospec=True)
    @mock.patch.object(pxe.PXEBoot, 'prepare_instance', spec_set=True,
                       autospec=True)
    def test_prepare_instance(self, pxe_prepare_instance_mock,
                              update_secure_boot_mode_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.driver.boot.prepare_instance(task)
            update_secure_boot_mode_mock.assert_called_once_with(task, True)
            pxe_prepare_instance_mock.assert_called_once_with(mock.ANY, task)

    @mock.patch.object(sdflex_common, 'disable_directed_lan_boot',
                       spec_set=True, autospec=True)
    @mock.patch.object(sdflex_boot, 'disable_secure_boot_if_supported',
                       spec_set=True, autospec=True)
    @mock.patch.object(manager_utils, 'node_power_action', spec_set=True,
                       autospec=True)
    @mock.patch.object(pxe.PXEBoot, 'clean_up_instance', spec_set=True,
                       autospec=True)
    def test_clean_up_instance_directed_lanboot_enable(
            self, pxe_cleanup_mock, node_power_mock,
            disable_secure_boot_if_supported_mock, disable_dlan):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_directed_lanboot'] = 'True'
            task.driver.boot.clean_up_instance(task)
            node_power_mock.assert_called_once_with(task, states.POWER_OFF)
            disable_secure_boot_if_supported_mock.assert_called_once_with(task)
            pxe_cleanup_mock.assert_called_once_with(mock.ANY, task)
            disable_dlan.assert_called_once_with(task.node)

    @mock.patch.object(sdflex_boot, 'disable_secure_boot_if_supported',
                       spec_set=True, autospec=True)
    @mock.patch.object(manager_utils, 'node_power_action', spec_set=True,
                       autospec=True)
    @mock.patch.object(pxe.PXEBoot, 'clean_up_instance', spec_set=True,
                       autospec=True)
    def test_clean_up_instance_directed_lanboot_disable(
            self, pxe_cleanup_mock, node_power_mock,
            disable_secure_boot_if_supported_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_directed_lanboot'] = 'False'
            task.driver.boot.clean_up_instance(task)
            node_power_mock.assert_called_once_with(task, states.POWER_OFF)
            disable_secure_boot_if_supported_mock.assert_called_once_with(task)
            pxe_cleanup_mock.assert_called_once_with(mock.ANY, task)

    @mock.patch.object(sdflex_boot, 'is_directed_lanboot_requested',
                       spec_set=True, autospec=True)
    @mock.patch.object(pxe.PXEBoot, 'validate', spec_set=True, autospec=True)
    def test_validate(self, func_validate, is_directed_lanboot_requested_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_directed_lanboot'] = 'True'
            task.driver.boot.validate(task)
            is_directed_lanboot_requested_mock.assert_called_once_with(
                task.node)

    def test_validate_fail(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_directed_lanboot'] = 'True'
            task.node.driver_info['directed_lan_data'] = {
                "UrlBootFile3": "tftp://1.1.1.24/tftpboot/bootx64.efi"}
            self.assertRaises(exception.MissingParameterValue,
                              task.driver.boot.validate, task)

    def test_validate_directed_lan_data_none(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_directed_lanboot'] = 'True'
            task.node.driver_info['directed_lan_data'] = None
            self.assertRaises(exception.MissingParameterValue,
                              task.driver.boot.validate, task)

    @mock.patch.object(pxe.PXEBoot, 'validate', spec_set=True, autospec=True)
    def test_validate_wrong_url(self, func_validate):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_directed_lanboot'] = 'True'
            task.node.driver_info['directed_lan_data'] = {
                "UrlBootFile": "1.1.1.24/tftpboot/bootx64.efi"}
            self.assertRaises(exception.InvalidParameterValue,
                              task.driver.boot.validate, task)

    @mock.patch.object(sdflex_boot, 'is_directed_lanboot_requested',
                       spec_set=True, autospec=True)
    def test_is_directed_lanboot_requested(self,
                                           is_directed_lanboot_requested):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_directed_lanboot'] = 'True'
            sdflex_boot.is_directed_lanboot_requested(task.node)
            is_directed_lanboot_requested.assert_called_once_with(task.node)

    @mock.patch.object(sdflex_boot, 'is_directed_lanboot_requested',
                       spec_set=True, autospec=True)
    def test_is_directed_lanboot_requested_none(
            self, is_directed_lanboot_requested):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_directed_lanboot'] = None
            sdflex_boot.is_directed_lanboot_requested(task.node)
            is_directed_lanboot_requested.assert_called_once_with(task.node)

    @mock.patch.object(sdflex_boot, 'is_directed_lanboot_requested',
                       spec_set=True, autospec=True)
    def test_is_directed_lanboot_requested_false(
            self, is_directed_lanboot_requested):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_directed_lanboot'] = 'False'
            sdflex_boot.is_directed_lanboot_requested(task.node)
            is_directed_lanboot_requested.assert_called_once_with(task.node)
