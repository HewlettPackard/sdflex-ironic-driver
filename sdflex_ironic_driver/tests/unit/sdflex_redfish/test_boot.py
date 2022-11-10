# Copyright 2015 Hewlett-Packard Development Company, L.P.
# Copyright 2019-2022 Hewlett Packard Enterprise Development LP
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

import os

import mock
import six

from oslo_config import cfg

from ironic.common import boot_devices
from ironic.common import exception
from ironic.common import images
from ironic.common import states
from ironic.conductor import task_manager
from ironic.conductor import utils as manager_utils
from ironic.drivers.modules import boot_mode_utils
from ironic.drivers.modules import deploy_utils
from ironic.drivers.modules import image_utils as redfish_image_utils
from ironic.drivers.modules import pxe
from ironic.drivers.modules.redfish import boot as redfish_boot
from ironic.drivers.modules.redfish import utils as redfish_utils

from ironic.tests.unit.objects import utils as obj_utils

from sdflex_ironic_driver import http_utils
from sdflex_ironic_driver.sdflex_redfish import boot as sdflex_boot
from sdflex_ironic_driver.sdflex_redfish import common as sdflex_common
from sdflex_ironic_driver.tests.unit.sdflex_redfish import test_common

if six.PY3:
    import io
    file = io.BytesIO

CONF = cfg.CONF


class SdflexBootPrivateMethodsTestCase(test_common.BaseSdflexTest):

    boot_interface = 'sdflex-redfish'

    def test_sdflex_update_driver_config(self):
        sdflex_boot.sdflex_update_driver_config(self, 'sdflex-redfish')
        self.assertEqual("sdflex-redfish", self._driver)
        self.assertEqual(False, self.swift_enabled)
        self.assertIsNone(self._container)
        self.assertEqual(900, self._timeout)
        self.assertEqual("sdflex-redfish", self._image_subdir)
        self.assertEqual(0o644, self._file_permission)
        self.assertEqual('nofb nomodeset vga=normal', self.kernel_params)

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
            task.node.driver_info['enable_uefi_httpboot'] = 'False'
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

    @mock.patch.object(sdflex_common, 'enable_uefi_http_boot',
                       spec_set=True, autospec=True)
    @mock.patch.object(http_utils, 'is_http_boot_requested',
                       spec_set=True, autospec=True)
    @mock.patch.object(sdflex_boot, '_disable_secure_boot', spec_set=True,
                       autospec=True)
    @mock.patch.object(manager_utils, 'node_power_action', spec_set=True,
                       autospec=True)
    def test_prepare_node_for_deploy_uefi_http_boot(
            self, func_node_power_action, func_disable_secure_boot,
            func_is_http_boot_enabled, func_enable_directed):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_directed_lanboot'] = 'False'
            task.node.driver_info['enable_uefi_httpboot'] = 'True'
            sdflex_boot.prepare_node_for_deploy(task)
            func_node_power_action.assert_called_once_with(task,
                                                           states.POWER_OFF)
            func_disable_secure_boot.assert_called_once_with(task)
            func_is_http_boot_enabled.assert_called_once_with(task.node)


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

    @mock.patch.object(sdflex_common, 'enable_directed_lan_boot',
                       spec_set=True, autospec=True)
    @mock.patch.object(http_utils, 'is_http_boot_requested',
                       spec_set=True, autospec=True)
    @mock.patch.object(http_utils, 'get_instance_image_info',
                       spec_set=True, autospec=True)
    @mock.patch.object(http_utils, 'get_image_info',
                       spec_set=True, autospec=True)
    @mock.patch.object(boot_mode_utils, 'sync_boot_mode',
                       spec_set=True, autospec=True)
    @mock.patch.object(http_utils, 'build_http_config_options',
                       spec_set=True, autospec=True)
    @mock.patch.object(http_utils, 'create_http_config',
                       spec_set=True, autospec=True)
    @mock.patch.object(http_utils, 'cache_ramdisk_kernel',
                       spec_set=True, autospec=True)
    @mock.patch.object(manager_utils, 'node_set_boot_device',
                       spec_set=True, autospec=True)
    @mock.patch.object(deploy_utils, 'get_pxe_config_template',
                       spec_set=True, autospec=True)
    @mock.patch.object(sdflex_boot, 'prepare_node_for_deploy', spec_set=True,
                       autospec=True)
    def _test_prepare_ramdisk_needs_node_prep_uefi_http_boot_enabled(
            self, prepare_node_mock, get_pxe_config_template_mock,
            node_set_boot_device_mock, cache_ramdisk_kernel_mock,
            create_http_config_mock, build_http_config_options_mock,
            sync_boot_mode_mock, get_image_info_mock,
            get_instance_image_info_mock, is_http_boot_requested_mock,
            func_set_data, prov_state):
        self.node.provision_state = prov_state
        self.node.save()
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_uefi_httpboot'] = 'True'
            task.node.driver_info['deploy_kernel'] = ''
            self.assertIsNone(
                task.driver.boot.prepare_ramdisk(task, None))
            is_http_boot_requested_mock.assert_called_once_with(task.node)

    def test_prepare_ramdisk_in_deploying(self):
        self._test_prepare_ramdisk_needs_node_prep(prov_state=states.DEPLOYING)

    def test_prepare_ramdisk_in_deploying_uefi_http_boot_enabled(self):
        self._test_prepare_ramdisk_needs_node_prep_uefi_http_boot_enabled(
            prov_state=states.DEPLOYING)

    def test_prepare_ramdisk_in_rescuing(self):
        self._test_prepare_ramdisk_needs_node_prep(prov_state=states.RESCUING)

    def test_prepare_ramdisk_in_cleaning(self):
        self._test_prepare_ramdisk_needs_node_prep(prov_state=states.CLEANING)

    def test_prepare_ramdisk_in_inspecting(self):
        self._test_prepare_ramdisk_needs_node_prep(
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

    @mock.patch.object(sdflex_boot, 'prepare_node_for_deploy', autospec=True)
    @mock.patch.object(http_utils, 'is_http_boot_requested', autospec=True)
    @mock.patch.object(deploy_utils, 'get_boot_option', autospec=True)
    @mock.patch.object(sdflex_common, 'update_secure_boot_mode', spec_set=True,
                       autospec=True)
    @mock.patch.object(pxe.PXEBoot, 'prepare_instance', spec_set=True,
                       autospec=True)
    def test_prepare_instance_with_boot_option_kickstart(
            self, pxe_prepare_instance_mock, update_secure_boot_mode_mock,
            mock_get_boot_option, mock_is_http_boot_requested,
            mock_prepare_node_for_deploy):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            mock_get_boot_option.return_value = 'kickstart'
            mock_is_http_boot_requested.return_value = False
            task.driver.boot.prepare_instance(task)
            update_secure_boot_mode_mock.assert_not_called()
            mock_is_http_boot_requested.assert_called_once_with(task.node)
            mock_prepare_node_for_deploy.assert_called_once_with(task)
            pxe_prepare_instance_mock.assert_called_once_with(mock.ANY, task)

    @mock.patch.object(http_utils, 'is_http_boot_requested', autospec=True)
    @mock.patch.object(http_utils, 'get_instance_image_info', autospec=True)
    @mock.patch.object(http_utils, 'clean_up_http_config', autospec=True)
    @mock.patch.object(http_utils, 'build_service_http_config', autospec=True)
    @mock.patch.object(sdflex_common, 'update_secure_boot_mode', autospec=True)
    @mock.patch.object(boot_mode_utils, 'sync_boot_mode', autospec=True)
    @mock.patch.object(manager_utils, 'node_set_boot_device', autospec=True)
    def test_prepare_instance_uefi_http_boot_requested(
            self, sync_boot_mode_mock, node_set_boot_device_mock,
            update_secure_boot_mode_mock, build_service_http_config_mock,
            clean_up_http_config,
            get_instance_image_info_mock,
            func_is_http_boot_requested):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_uefi_httpboot'] = 'True'
            task.node.driver_internal_info['root_uuid_or_disk_id'] = (
                "30212642-09d3-467f-8e09-21685826ab50")
            self.assertIsNone(
                task.driver.boot.prepare_instance(task))
            task.driver.boot.prepare_instance(task)
            update_secure_boot_mode_mock.assert_called_with(task, True)
            func_is_http_boot_requested.assert_called_with(task.node)

    @mock.patch.object(sdflex_common, 'reset_bios_settings',
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
            task.node.driver_info['http_boot_uri'] = None
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

    @mock.patch.object(sdflex_common, 'reset_bios_settings',
                       spec_set=True, autospec=True)
    @mock.patch.object(http_utils, 'is_http_boot_requested',
                       spec_set=True, autospec=True)
    @mock.patch.object(sdflex_boot, 'disable_secure_boot_if_supported',
                       spec_set=True, autospec=True)
    @mock.patch.object(manager_utils, 'node_power_action', spec_set=True,
                       autospec=True)
    @mock.patch.object(http_utils, 'clean_up_http_env', autospec=True)
    def test_clean_up_instance_uefi_httpboot_enable(
            self, clean_up_http_env_mock,
            node_power_mock, disable_secure_boot_if_supported_mock,
            func_http_boot_requested, func_reset_bios_settings):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_uefi_httpboot'] = 'True'
            task.node.driver_info['enable_directed_lanboot'] = 'False'
            task.node.driver_info['http_boot_uri'] = None
            task.driver.boot.clean_up_instance(task)
            node_power_mock.assert_called_once_with(task, states.POWER_OFF)
            clean_up_http_env_mock.assert_called_once_with(task, {})
            disable_secure_boot_if_supported_mock.assert_called_once_with(task)
            func_http_boot_requested.assert_called_with(task.node)
            func_reset_bios_settings.assert_called_once_with(task.node)

    @mock.patch.object(sdflex_common, 'get_sdflex_object',
                       spec_set=True, autospec=True)
    @mock.patch.object(sdflex_common, 'reset_bios_settings',
                       spec_set=True, autospec=True)
    @mock.patch.object(http_utils, 'is_http_boot_requested',
                       spec_set=True, autospec=True)
    @mock.patch.object(sdflex_boot, 'disable_secure_boot_if_supported',
                       spec_set=True, autospec=True)
    @mock.patch.object(manager_utils, 'node_power_action', spec_set=True,
                       autospec=True)
    @mock.patch.object(http_utils, 'clean_up_http_env', autospec=True)
    def test_clean_up_instance_uefi_httpboot_enable_httpbooturi(
            self, clean_up_http_env_mock,
            node_power_mock, disable_secure_boot_if_supported_mock,
            func_http_boot_requested, func_reset_bios_settings,
            mock_get_sdflex_object):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_uefi_httpboot'] = 'True'
            task.node.driver_info['enable_directed_lanboot'] = 'False'
            task.node.driver_info['http_boot_uri'] = 'http://1.2.3.4/bootx64.efi'  # noqa E501
            task.driver.boot.clean_up_instance(task)
            node_power_mock.assert_called_once_with(task, states.POWER_OFF)
            clean_up_http_env_mock.assert_called_once_with(task, {})
            disable_secure_boot_if_supported_mock.assert_called_once_with(task)
            func_http_boot_requested.assert_called_with(task.node)
            func_reset_bios_settings.assert_called_once_with(task.node)

    @mock.patch.object(sdflex_boot, 'disable_secure_boot_if_supported',
                       spec_set=True, autospec=True)
    @mock.patch.object(manager_utils, 'node_power_action', spec_set=True,
                       autospec=True)
    @mock.patch.object(pxe.PXEBoot, 'clean_up_instance', spec_set=True,
                       autospec=True)
    def test_clean_up_instance_uefi_httpboot_disable(
            self, pxe_cleanup_mock, node_power_mock,
            disable_secure_boot_if_supported_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_uefi_httpboot'] = 'False'
            task.node.driver_info['enable_directed_lanboot'] = 'False'
            task.driver.boot.clean_up_instance(task)
            node_power_mock.assert_called_once_with(task, states.POWER_OFF)
            disable_secure_boot_if_supported_mock.assert_called_once_with(task)
            pxe_cleanup_mock.assert_called_once_with(mock.ANY, task)

    @mock.patch.object(pxe.PXEBoot, 'validate', spec_set=True, autospec=True)
    def test_validate(self, func_validate):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.driver.boot.validate(task)

    def test_validate_fail(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_directed_lanboot'] = 'True'
            task.node.driver_info['boot_file_path'] = {
                "UrlBootFile3": "tftp://1.1.1.24/tftpboot/bootx64.efi"}
            self.assertRaises(exception.MissingParameterValue,
                              task.driver.boot.validate, task)

    def test_validate_fail_bfpv_with_wrong_deploy_interface(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.deploy_interface = 'direct'
            task.node.driver_info['bfpv'] = 'True'
            self.node.save()
            self.assertRaises(exception.InvalidParameterValue,
                              task.driver.boot.validate, task)

    def test_validate_directed_lanboot_boot_file_path_none(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_directed_lanboot'] = 'True'
            task.node.driver_info['boot_file_path'] = None
            self.assertRaises(exception.MissingParameterValue,
                              task.driver.boot.validate, task)

    def test_validate_uefi_httpboot_boot_file_path_none(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_directed_lanboot'] = 'False'
            task.node.driver_info['enable_uefi_httpboot'] = 'True'
            task.node.driver_info['boot_file_path'] = None
            self.assertRaises(exception.MissingParameterValue,
                              task.driver.boot.validate, task)

    def test_validate_uefi_httpboot_boot_deploy_interface_anaconda(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_directed_lanboot'] = 'False'
            task.node.driver_info['enable_uefi_httpboot'] = 'True'
            task.node.driver_info['boot_file_path'] = {
                "UrlBootFile": "http://1.1.1.24/tftpboot/bootx64.efi"}
            task.node.deploy_interface = 'anaconda'
            self.node.save()
            self.assertRaises(exception.InvalidParameterValue,
                              task.driver.boot.validate, task)

    @mock.patch.object(pxe.PXEBoot, 'validate', spec_set=True, autospec=True)
    def test_validate_directed_lanboot_wrong_url(self, func_validate):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_directed_lanboot'] = 'True'
            task.node.driver_info['boot_file_path'] = {
                "UrlBootFile": "1.1.1.24/tftpboot/bootx64.efi"}
            self.assertRaises(exception.InvalidParameterValue,
                              task.driver.boot.validate, task)

    @mock.patch.object(pxe.PXEBoot, 'validate', spec_set=True, autospec=True)
    def test_validate_directed_lanboot_wrong_http_url(self, func_validate):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_directed_lanboot'] = 'True'
            task.node.driver_info['boot_file_path'] = {
                "UrlBootFile": "http://1.1.1.24/tftpboot/bootx64.efi"}
            self.assertRaises(exception.InvalidParameterValue,
                              task.driver.boot.validate, task)

    @mock.patch.object(pxe.PXEBoot, 'validate', spec_set=True, autospec=True)
    def test_validate_uefi_httpboot_wrong_tftp_url(self, func_validate):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_uefi_httpboot'] = 'True'
            task.node.driver_info['http_boot_uri'] = None
            task.node.driver_info['boot_file_path'] = {
                "UrlBootFile": "tftp://1.1.1.24/tftpboot/bootx64.efi"}
            self.assertRaises(exception.InvalidParameterValue,
                              task.driver.boot.validate, task)

    @mock.patch.object(pxe.PXEBoot, 'validate', spec_set=True, autospec=True)
    def test_validate_uefi_httpboot_wrong_bootfilepath(self, func_validate):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_uefi_httpboot'] = 'True'
            task.node.driver_info['http_boot_uri'] = None
            task.node.driver_info['boot_file_path'] = {
                "UrlBootFile": "http://1.1.1.24/tftpboot/bootx64"}
            self.assertRaises(exception.InvalidParameterValue,
                              task.driver.boot.validate, task)

    @mock.patch.object(pxe.PXEBoot, 'validate', spec_set=True, autospec=True)
    def test_validate_uefi_httpboot_http_boot_uri(self, func_validate):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_uefi_httpboot'] = 'True'
            task.node.driver_info['http_boot_uri'] = "http://1.1.1.24/tftpboot/bootx64.efi"  # noqa E501
            task.driver.boot.validate(task)

    def test_validate_uefi_httpboot_http_boot_uri_tftp_url(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_uefi_httpboot'] = 'True'
            task.node.driver_info['http_boot_uri'] = "tftp://1.1.1.24/tftpboot/bootx64.efi"  # noqa E501
            self.assertRaises(exception.InvalidParameterValue,
                              task.driver.boot.validate, task)

    def test_validate_uefi_httpboot_http_boot_uri_invalid_url(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_uefi_httpboot'] = 'True'
            task.node.driver_info['http_boot_uri'] = "http://1.1.1.24/tftpboot/bootx64"  # noqa E501
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


class SdflexRedfishVirtualMediaBootTestCase(test_common.BaseSdflexTest):

    boot_interface = 'sdflex-redfish-vmedia'

    def setUp(self):
        super(SdflexRedfishVirtualMediaBootTestCase, self).setUp()
        self.config(enabled_hardware_types=['sdflex-redfish'],
                    enabled_power_interfaces=['sdflex-redfish'],
                    enabled_boot_interfaces=['sdflex-redfish-vmedia'],
                    enabled_management_interfaces=['sdflex-redfish'],
                    enabled_bios_interfaces=['sdflex-redfish'])
        self.node = obj_utils.create_test_node(
            self.context, driver='sdflex-redfish',
            driver_info=test_common.INFO_DICT)

    @mock.patch.object(os, 'link', autospec=True)
    @mock.patch.object(os, 'mkdir', autospec=True)
    @mock.patch.object(os, 'chmod', autospec=True)
    def test__publish_image_local_link(self, mock_chmod, mock_mkdir,
                                       mock_link):
        image_share_root = "/home/ubuntu/nfsfolder/"

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            object_name = '%s.iso' % task.node.uuid
            url = task.driver.boot._publish_image('file.iso', object_name,
                                                  image_share_root)
            new_file_location = image_share_root + object_name
            self.assertEqual(object_name, url)
            mock_chmod.assert_called_once_with(new_file_location, 0o777)
            mock_link.assert_called_once_with('file.iso', new_file_location)

    @mock.patch.object(sdflex_boot, 'shutil', autospec=True)
    @mock.patch.object(os, 'link', autospec=True)
    @mock.patch.object(os, 'mkdir', autospec=True)
    @mock.patch.object(os, 'chmod', autospec=True)
    def test__publish_image_local_copy(self, mock_chmod, mock_mkdir, mock_link,
                                       mock_shutil):
        image_share_root = "/home/ubuntu/nfsfolder/"
        mock_link.side_effect = OSError()

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            object_name = '%s.iso' % task.node.uuid
#             expected_url = '/home/ubuntu/nfsfolder/' + object_name
            new_file_location = image_share_root + object_name

            url = task.driver.boot._publish_image('file.iso', object_name,
                                                  image_share_root)
            self.assertEqual(object_name, url)
            mock_chmod.assert_called_once_with(new_file_location, 0o777)
            mock_shutil.copyfile.assert_called_once_with(
                'file.iso', new_file_location)

    @mock.patch.object(sdflex_boot, 'ironic_utils', autospec=True)
    def test__unpublish_image_local(self, mock_ironic_utils):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            nfs_server_location = "/home/ubuntu/nfsfolder"
            object_name = 'image-%s.iso' % task.node.uuid

            expected_file = '/home/ubuntu/nfsfolder/' + object_name

            task.driver.boot._unpublish_image(object_name, nfs_server_location)

            mock_ironic_utils.unlink_without_raise.assert_called_once_with(
                expected_file)

    @mock.patch.object(sdflex_boot.SdflexRedfishVirtualMediaBoot,
                       '_unpublish_image', autospec=True)
    def test__cleanup_iso_image(self, mock_unpublish):

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:

            task.node.driver_info['remote_image_share_root'] = (
                "/home/ubuntu/nfsfolder")
            task.node.driver_info['remote_image_share_type'] = 'nfs'
            task.driver.boot._cleanup_iso_image(task)

            object_name = 'boot-%s.iso' % task.node.uuid
            nfs_server_location = "/home/ubuntu/nfsfolder"
            mock_unpublish.assert_called_once_with(mock.ANY, object_name,
                                                   nfs_server_location)

    @mock.patch.object(sdflex_boot.SdflexRedfishVirtualMediaBoot,
                       '_publish_image', autospec=True)
    @mock.patch.object(images, 'create_boot_iso', autospec=True)
    def test__prepare_iso_image(
            self, mock_create_boot_iso, mock__publish_image):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.node.instance_info.update(deploy_boot_mode='uefi')
            task.node.instance_info.update(
                kernel_append_params='nofb nomodeset vga=normal')

            object_name = 'boot-%s.iso' % task.node.uuid
            expected_url = '/home/ubuntu/nfsfolder/' + object_name

            mock__publish_image.return_value = expected_url

            url = task.driver.boot._prepare_iso_image(
                task, 'http://kernel/img', 'http://ramdisk/img',
                'http://bootloader/img', root_uuid=task.node.uuid)

            mock__publish_image.assert_called_once()

            mock_create_boot_iso.assert_called_once_with(
                mock.ANY, mock.ANY, 'http://kernel/img', 'http://ramdisk/img',
                boot_mode='uefi', esp_image_href='http://bootloader/img',
                kernel_params='nofb nomodeset vga=normal',
                root_uuid='1be26c0b-03f2-4d2e-ae87-c02d7f33c123')

            self.assertEqual(expected_url, url)

    @mock.patch.object(sdflex_boot.SdflexRedfishVirtualMediaBoot,
                       '_publish_image', autospec=True)
    @mock.patch.object(images, 'create_boot_iso', autospec=True)
    def test__prepare_iso_image_kernel_params(
            self, mock_create_boot_iso, mock__publish_image):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            kernel_params = 'network-config=base64-cloudinit-blob'

            task.node.instance_info.update(kernel_append_params=kernel_params)

            task.driver.boot._prepare_iso_image(
                task, 'http://kernel/img', 'http://ramdisk/img',
                bootloader_href=None, root_uuid=task.node.uuid)

            mock_create_boot_iso.assert_called_once_with(
                mock.ANY, mock.ANY, 'http://kernel/img', 'http://ramdisk/img',
                boot_mode=None, esp_image_href=None,
                kernel_params=kernel_params,
                root_uuid='1be26c0b-03f2-4d2e-ae87-c02d7f33c123')

    @mock.patch.object(sdflex_boot.SdflexRedfishVirtualMediaBoot,
                       '_prepare_iso_image', autospec=True)
    def test__prepare_deploy_iso(self, mock__prepare_iso_image):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:

            task.node.driver_info.update(
                {'deploy_kernel': 'kernel',
                 'deploy_ramdisk': 'ramdisk',
                 'bootloader': 'bootloader'}
            )
            task.node.instance_info.update(deploy_boot_mode='uefi')
            task.driver.boot._prepare_deploy_iso(task, {}, 'deploy')
            mock__prepare_iso_image.assert_called_once()

    @mock.patch.object(sdflex_boot.SdflexRedfishVirtualMediaBoot,
                       '_prepare_iso_image', autospec=True)
    @mock.patch.object(images, 'create_boot_iso', autospec=True)
    def test__prepare_boot_iso(self, mock_create_boot_iso,
                               mock__prepare_iso_image):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.node.driver_info.update(
                {'deploy_kernel': 'kernel',
                 'deploy_ramdisk': 'ramdisk',
                 'bootloader': 'bootloader'}
            )
            task.node.instance_info.update(
                {'image_source': 'http://boot/iso',
                 'kernel': 'http://kernel/img',
                 'ramdisk': 'http://ramdisk/img'})

            task.driver.boot._prepare_boot_iso(task, root_uuid=task.node.uuid)

            mock__prepare_iso_image.assert_called_once_with(
                mock.ANY, task, 'http://kernel/img', 'http://ramdisk/img',
                'bootloader', root_uuid=task.node.uuid)

    @mock.patch.object(redfish_boot.RedfishVirtualMediaBoot, 'validate',
                       autospec=True)
    @mock.patch.object(redfish_utils, 'parse_driver_info', autospec=True)
    @mock.patch.object(boot_mode_utils, 'get_boot_mode_for_deploy',
                       autospec=True)
    def test_validate_nfs(self, mock_get_boot_mode,
                          mock_parse_driver_info,
                          mock_redfish_virtualmedia_validate):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.node.instance_info.update(
                {'kernel': 'kernel',
                 'ramdisk': 'ramdisk',
                 'image_source': 'http://image/source'}
            )

            task.node.driver_info.update(
                {'deploy_kernel': 'kernel',
                 'deploy_ramdisk': 'ramdisk',
                 'bootloader': 'bootloader',
                 'remote_image_share_root': '/home/ubuntu/nfsfolder/',
                 'remote_image_server': '1.2.3.4',
                 'remote_image_share_type': 'nfs'}
            )

            mock_get_boot_mode.return_value = 'uefi'

            task.driver.boot.validate(task)

            mock_redfish_virtualmedia_validate.assert_called_once()

    @mock.patch.object(redfish_boot.RedfishVirtualMediaBoot, 'validate',
                       autospec=True)
    @mock.patch.object(redfish_utils, 'parse_driver_info', autospec=True)
    @mock.patch.object(boot_mode_utils, 'get_boot_mode_for_deploy',
                       autospec=True)
    def test_validate_cifs(self, mock_get_boot_mode,
                           mock_parse_driver_info,
                           mock_redfish_virtualmedia_validate):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.node.instance_info.update(
                {'kernel': 'kernel',
                 'ramdisk': 'ramdisk',
                 'image_source': 'http://image/source'}
            )

            task.node.driver_info.update(
                {'deploy_kernel': 'kernel',
                 'deploy_ramdisk': 'ramdisk',
                 'bootloader': 'bootloader',
                 'remote_image_share_root': '/home/ubuntu/cifs/',
                 'image_share_root': '/cifs',
                 'remote_image_server': '1.2.3.4',
                 'remote_image_share_type': 'cifs',
                 'remote_image_user_name': 'mock',
                 'remote_image_user_password': 'mock'
                 }
            )

            mock_get_boot_mode.return_value = 'uefi'

            task.driver.boot.validate(task)

            mock_redfish_virtualmedia_validate.assert_called_once()

    @mock.patch.object(redfish_utils, 'parse_driver_info', autospec=True)
    @mock.patch.object(deploy_utils, 'validate_image_properties',
                       autospec=True)
    def test_validate_missing(self, mock_validate_image_properties,
                              mock_parse_driver_info):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.node.driver_info.update(
                {'deploy_kernel': 'kernel',
                 'deploy_ramdisk': 'ramdisk',
                 'bootloader': 'bootloader',
                 'remote_image_share_root': '/home/ubuntu/nfsfolder/',
                 'remote_image_server': '1.2.3.4',
                 'remote_image_share_type': 'cifs',
                 }
            )
            self.assertRaises(exception.MissingParameterValue,
                              task.driver.boot.validate, task)

    @mock.patch.object(redfish_utils, 'parse_driver_info', autospec=True)
    @mock.patch.object(deploy_utils, 'validate_image_properties',
                       autospec=True)
    def test_validate_invalid(self, mock_validate_image_properties,
                              mock_parse_driver_info):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.node.driver_info.update(
                {'deploy_kernel': 'kernel',
                 'deploy_ramdisk': 'ramdisk',
                 'bootloader': 'bootloader',
                 'remote_image_share_root': '/home/ubuntu/nfsfolder/',
                 'remote_image_server': '1.2.3.4',
                 'remote_image_share_type': 'cifsdfd',
                 }
            )
            self.assertRaises(exception.InvalidParameterValue,
                              task.driver.boot.validate, task)

    @mock.patch.object(sdflex_boot.manager_utils, 'node_set_boot_device',
                       autospec=True)
    @mock.patch.object(sdflex_boot.SdflexRedfishVirtualMediaBoot,
                       '_prepare_deploy_iso', autospec=True)
    @mock.patch.object(sdflex_common, 'eject_vmedia', autospec=True)
    @mock.patch.object(sdflex_common, 'insert_vmedia', autospec=True)
    @mock.patch.object(sdflex_boot.manager_utils, 'node_power_action',
                       autospec=True)
    @mock.patch.object(sdflex_boot, 'boot_mode_utils', autospec=True)
    def test_prepare_ramdisk_with_params_nfs(self, mock_boot_mode_utils,
                                             mock_node_power_action,
                                             mock__insert_vmedia,
                                             mock__eject_vmedia,
                                             mock__prepare_deploy_iso,
                                             mock_node_set_boot_device):

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info.update(
                {'deploy_kernel': 'kernel',
                 'deploy_ramdisk': 'ramdisk',
                 'bootloader': 'bootloader',
                 'remote_image_share_root': 'home/ubuntu/nfsfolder',
                 'remote_image_server': '1.2.3.4',
                 'remote_image_share_type': 'nfs',
                 'remote_image_user_name': 'mock',
                 'remote_image_user_password': 'mock'
                 }
            )
            task.node.provision_state = states.DEPLOYING

            mock__prepare_deploy_iso.return_value = 'image-url'
            expected_url = "nfs://1.2.3.4/home/ubuntu/nfsfolder/image-url"
            remote_server_data = {'remote_image_share_type': 'nfs',
                                  'remote_image_user_name': 'mock',
                                  'remote_image_user_password': 'mock'}
            task.driver.boot.prepare_ramdisk(task, {})

            mock_node_power_action.assert_called_once_with(
                task, states.POWER_OFF)

            mock__eject_vmedia.assert_called_once_with(
                task, "cd0")

            mock__insert_vmedia.assert_called_once_with(
                task, expected_url, "cd0",
                remote_server_data)

            expected_params = {
                'BOOTIF': None,
                'ipa-agent-token': mock.ANY,
                'ipa-debug': '1',
            }

            mock__prepare_deploy_iso.assert_called_once_with(
                mock.ANY, task, expected_params, 'deploy')

            mock_node_set_boot_device.assert_called_once_with(
                task, 'cd', False)

            mock_boot_mode_utils.sync_boot_mode.assert_called_once_with(task)

    @mock.patch.object(sdflex_boot.manager_utils, 'node_set_boot_device',
                       autospec=True)
    @mock.patch.object(sdflex_boot.SdflexRedfishVirtualMediaBoot,
                       '_prepare_deploy_iso', autospec=True)
    @mock.patch.object(sdflex_common, 'eject_vmedia', autospec=True)
    @mock.patch.object(sdflex_common, 'insert_vmedia', autospec=True)
    @mock.patch.object(sdflex_boot.manager_utils, 'node_power_action',
                       autospec=True)
    @mock.patch.object(sdflex_boot, 'boot_mode_utils', autospec=True)
    def test_prepare_ramdisk_with_params_cifs(self, mock_boot_mode_utils,
                                              mock_node_power_action,
                                              mock__insert_vmedia,
                                              mock__eject_vmedia,
                                              mock__prepare_deploy_iso,
                                              mock_node_set_boot_device):

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info.update(
                {'deploy_kernel': 'kernel',
                 'deploy_ramdisk': 'ramdisk',
                 'bootloader': 'bootloader',
                 'remote_image_share_root': '/home/ubuntu/cifs',
                 'remote_image_server': '1.2.3.4',
                 'remote_image_share_type': 'cifs',
                 'remote_image_user_name': 'mock',
                 'remote_image_user_password': 'mock',
                 'image_share_root': 'cifs'
                 }
            )
            task.node.provision_state = states.DEPLOYING

            mock__prepare_deploy_iso.return_value = 'image-url'
            expected_url = "cifs://1.2.3.4//home/ubuntu/cifs/image-url"
            remote_server_data = {'remote_image_share_type': 'cifs',
                                  'remote_image_user_name': 'mock',
                                  'remote_image_user_password': 'mock'}
            task.driver.boot.prepare_ramdisk(task, {})

            mock_node_power_action.assert_called_once_with(
                task, states.POWER_OFF)

            mock__eject_vmedia.assert_called_once_with(
                task, "cd0")

            mock__insert_vmedia.assert_called_once_with(
                task, expected_url, "cd0",
                remote_server_data)

            expected_params = {
                'BOOTIF': None,
                'ipa-agent-token': mock.ANY,
                'ipa-debug': '1',
            }

            mock__prepare_deploy_iso.assert_called_once_with(
                mock.ANY, task, expected_params, 'deploy')

            mock_node_set_boot_device.assert_called_once_with(
                task, 'cd', False)

            mock_boot_mode_utils.sync_boot_mode.assert_called_once_with(task)

    @mock.patch.object(sdflex_common, 'eject_vmedia', autospec=True)
    @mock.patch.object(sdflex_boot.SdflexRedfishVirtualMediaBoot,
                       '_cleanup_iso_image', autospec=True)
    def test_clean_up_ramdisk(self, mock__cleanup_iso_image,
                              mock__eject_vmedia):

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.node.provision_state = states.DEPLOYING

            task.driver.boot.clean_up_ramdisk(task)

            mock__cleanup_iso_image.assert_called_once_with(mock.ANY, task)

            eject_calls = [
                mock.call(task, "cd0"),
            ]

            mock__eject_vmedia.assert_has_calls(eject_calls)

    @mock.patch.object(sdflex_boot.SdflexRedfishVirtualMediaBoot,
                       'clean_up_instance', autospec=True)
    @mock.patch.object(sdflex_boot.SdflexRedfishVirtualMediaBoot,
                       '_prepare_boot_iso', autospec=True)
    @mock.patch.object(sdflex_common, 'eject_vmedia', autospec=True)
    @mock.patch.object(sdflex_common, 'insert_vmedia', autospec=True)
    @mock.patch.object(redfish_boot, 'manager_utils', autospec=True)
    @mock.patch.object(sdflex_boot, 'deploy_utils', autospec=True)
    @mock.patch.object(sdflex_boot, 'boot_mode_utils', autospec=True)
    def test_prepare_instance_normal_boot(
            self, mock_boot_mode_utils, mock_deploy_utils, mock_manager_utils,
            mock__insert_vmedia, mock__eject_vmedia,
            mock__prepare_boot_iso, mock_clean_up_instance):

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.node.provision_state = states.DEPLOYING
            task.node.driver_internal_info[
                'root_uuid_or_disk_id'] = self.node.uuid
            task.node.driver_info.update(
                {
                    'deploy_kernel': 'kernel',
                    'deploy_ramdisk': 'ramdisk',
                    'bootloader': 'bootloader',
                    'remote_image_share_root': '/home/ubuntu/cifs',
                    'remote_image_server': '1.2.3.4',
                    'remote_image_share_type': 'cifs',
                    'remote_image_user_name': 'mock',
                    'remote_image_user_password': 'mock'
                }
            )
            mock_deploy_utils.get_boot_option.return_value = 'net'

            expected_iso = "image-url"
            expected_url = 'cifs://1.2.3.4//home/ubuntu/cifs/image-url'
            mock__prepare_boot_iso.return_value = expected_iso

            task.driver.boot.prepare_instance(task)

            expected_params = {
                'root_uuid': self.node.uuid
            }
            remote_server_data = {
                'remote_image_share_type': 'cifs',
                'remote_image_user_name': 'mock',
                'remote_image_user_password': 'mock'
            }

            mock__prepare_boot_iso.assert_called_once_with(
                mock.ANY, task, **expected_params)

            mock__eject_vmedia.assert_called_once_with(
                task, "cd0")

            mock__insert_vmedia.assert_called_once_with(
                task, expected_url,
                "cd0",
                remote_server_data)

            mock_manager_utils.node_set_boot_device.assert_called_once()

            mock_boot_mode_utils.sync_boot_mode.assert_called_once_with(task)

    @mock.patch.object(sdflex_boot.SdflexRedfishVirtualMediaBoot,
                       'clean_up_instance', autospec=True)
    @mock.patch.object(sdflex_boot.SdflexRedfishVirtualMediaBoot,
                       '_prepare_boot_iso', autospec=True)
    @mock.patch.object(sdflex_common, 'eject_vmedia', autospec=True)
    @mock.patch.object(sdflex_common, 'insert_vmedia', autospec=True)
    @mock.patch.object(redfish_boot, 'manager_utils', autospec=True)
    @mock.patch.object(sdflex_boot, 'deploy_utils', autospec=True)
    @mock.patch.object(sdflex_boot, 'boot_mode_utils', autospec=True)
    def test_prepare_instance_ramdisk_boot(
            self, mock_boot_mode_utils, mock_deploy_utils, mock_manager_utils,
            mock__insert_vmedia, mock__eject_vmedia,
            mock__prepare_boot_iso, mock_clean_up_instance):

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.node.driver_info.update(
                {
                    'deploy_kernel': 'kernel',
                    'deploy_ramdisk': 'ramdisk',
                    'bootloader': 'bootloader',
                    'remote_image_share_root': '/home/ubuntu/cifs',
                    'remote_image_server': '1.2.3.4',
                    'remote_image_share_type': 'cifs',
                    'remote_image_user_name': 'mock',
                    'remote_image_user_password': 'mock'
                }
            )
            task.node.provision_state = states.DEPLOYING
            task.node.driver_internal_info[
                'root_uuid_or_disk_id'] = self.node.uuid

            mock_deploy_utils.get_boot_option.return_value = 'ramdisk'

            expected_iso = "image-url"
            expected_url = "cifs://1.2.3.4//home/ubuntu/cifs/image-url"
            mock__prepare_boot_iso.return_value = expected_iso

            task.driver.boot.prepare_instance(task)
            remote_server_data = {
                'remote_image_share_type': 'cifs',
                'remote_image_user_name': 'mock',
                'remote_image_user_password': 'mock'
            }
            mock__prepare_boot_iso.assert_called_once_with(mock.ANY, task)

            mock__eject_vmedia.assert_called_once_with(
                task, "cd0")

            mock__insert_vmedia.assert_called_once_with(
                task, expected_url, "cd0",
                remote_server_data)

            mock_manager_utils.node_set_boot_device.assert_called_once_with(
                task, 'cd', persistent=True)

            mock_boot_mode_utils.sync_boot_mode.assert_called_once_with(task)

    @mock.patch.object(sdflex_common, 'eject_vmedia', autospec=True)
    @mock.patch.object(sdflex_boot.SdflexRedfishVirtualMediaBoot,
                       '_cleanup_iso_image', autospec=True)
    @mock.patch.object(redfish_boot, 'manager_utils', autospec=True)
    def _test_prepare_instance_local_boot(
            self, mock_manager_utils,
            mock__cleanup_iso_image, mock__eject_vmedia):

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.node.provision_state = states.DEPLOYING
            task.node.driver_internal_info[
                'root_uuid_or_disk_id'] = self.node.uuid
            task.node.driver_info.update(
                {'remote_image_share_type': 'nfs',
                 'remote_image_share_root': '/home/ubuntu/nfsfolder/',
                 'remote_image_server': '1.2.3.4'}
            )
            task.driver.boot.prepare_instance(task)

            mock_manager_utils.node_set_boot_device.assert_called_once_with(
                task, boot_devices.DISK, persistent=True)
            mock__cleanup_iso_image.assert_called_once_with(mock.ANY, task)
            mock__eject_vmedia.assert_called_once_with(
                task, "cd0")

    def test_prepare_instance_local_whole_disk_image(self):
        self.node.driver_internal_info = {'is_whole_disk_image': True}
        self.node.save()
        self._test_prepare_instance_local_boot()

    def test_prepare_instance_local_boot_option(self):
        instance_info = self.node.instance_info
        instance_info['capabilities'] = '{"boot_option": "local"}'
        self.node.instance_info = instance_info
        self.node.save()
        self._test_prepare_instance_local_boot()

    @mock.patch.object(sdflex_common, 'eject_vmedia', autospec=True)
    @mock.patch.object(sdflex_boot.SdflexRedfishVirtualMediaBoot,
                       '_cleanup_iso_image', autospec=True)
    def test_clean_up_instance(self, mock__cleanup_iso_image,
                               mock__eject_vmedia):

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:

            task.driver.boot.clean_up_instance(task)
            mock__cleanup_iso_image.assert_called_once_with(mock.ANY, task)
            eject_calls = [mock.call(
                task, "cd0")]
            mock__eject_vmedia.assert_has_calls(eject_calls)


class SdflexRedfishDhcplessBoot(test_common.BaseSdflexTest):

    boot_interface = 'sdflex-redfish-dhcpless'

    @mock.patch.object(sdflex_common, 'set_network_setting_dhcpless_boot',
                       spec_set=True, autospec=True)
    @mock.patch.object(redfish_image_utils, 'prepare_deploy_iso',
                       spec_set=True, autospec=True)
    @mock.patch.object(boot_mode_utils, 'sync_boot_mode',
                       spec_set=True, autospec=True)
    @mock.patch.object(manager_utils, 'node_set_boot_device',
                       spec_set=True, autospec=True)
    @mock.patch.object(pxe.PXEBoot, 'prepare_ramdisk', spec_set=True,
                       autospec=True)
    def _test_prepare_ramdisk_needs_node_prep(
            self, pxe_prepare_ramdisk_mock,
            prepare_deploy_iso_mock, node_set_boot_device_mock,
            sync_boot_mode_mock, set_network_setting_dhcpless_boot_mock,
            prov_state):
        self.node.provision_state = prov_state
        self.node.save()
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info.update(
                {'deploy_kernel': 'kernel',
                 'deploy_ramdisk': 'ramdisk',
                 'bootloader': 'bootloader',
                 'rescue_kernel': 'rescue_kernel',
                 'rescue_ramdisk': 'rescue_ramdisk'})
            self.assertIsNone(
                task.driver.boot.prepare_ramdisk(task, None))

    def test_prepare_ramdisk_in_deploying(self):
        self._test_prepare_ramdisk_needs_node_prep(prov_state=states.DEPLOYING)

    def test_prepare_ramdisk_in_rescuing(self):
        self._test_prepare_ramdisk_needs_node_prep(prov_state=states.RESCUING)

    def test_prepare_ramdisk_in_cleaning(self):
        self._test_prepare_ramdisk_needs_node_prep(prov_state=states.CLEANING)

    def test_prepare_ramdisk_in_inspecting(self):
        self._test_prepare_ramdisk_needs_node_prep(
            prov_state=states.INSPECTING)

    @mock.patch.object(sdflex_boot, 'disable_secure_boot_if_supported',
                       spec_set=True, autospec=True)
    @mock.patch.object(manager_utils, 'node_power_action', spec_set=True,
                       autospec=True)
    @mock.patch.object(sdflex_common, 'reset_network_setting_dhcpless_boot',
                       spec_set=True, autospec=True)
    def test_clean_up_instance(self, reset_network_setting_dhcpless_boot_mock,
                               node_power_mock,
                               disable_secure_boot_if_supported_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_directed_lanboot'] = 'False'
            task.driver.boot.clean_up_instance(task)
            node_power_mock.assert_called_once_with(task, states.POWER_OFF)
            disable_secure_boot_if_supported_mock.assert_called_once_with(task)

    @mock.patch.object(sdflex_boot.SdflexRedfishDhcplessBoot,
                       'clean_up_instance', spec_set=True, autospec=True)
    @mock.patch.object(sdflex_common, 'update_secure_boot_mode', autospec=True)
    @mock.patch.object(boot_mode_utils, 'sync_boot_mode', autospec=True)
    @mock.patch.object(manager_utils, 'node_set_boot_device', autospec=True)
    def test_prepare_instance(
            self, node_set_boot_device_mock, sync_boot_mode_mock,
            update_secure_boot_mode_mock,
            clean_up_instance_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            self.assertIsNone(
                task.driver.boot.prepare_instance(task))
            task.driver.boot.prepare_instance(task)
            update_secure_boot_mode_mock.assert_called_with(task, True)

    def test_validate(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            network_data = {'links': [{'id': 'enp1s0', 'type': 'phy', 'ethernet_mac_address': '94:40:C9:D6:03:84', 'mtu': 1500}],  # noqa E501
                            'networks': [{'id': 'provisioning IPv4', 'type': 'ipv4', 'link': 'enp1s0', 'ip_address': '10.229.136.128',  # noqa E501
                                          'netmask': '255.255.248.0',
                                          'routes': [{'network': '10.229.136.0', 'netmask': '255.255.248.0', 'gateway': '10.229.136.1'},  # noqa E501
                                                     {'network': '0.0.0.0', 'netmask': '0.0.0.0', 'gateway': '10.229.136.1'}],  # noqa E501
                                          'network_id': ''}],
                            'services': [{'type': 'dns', 'address': '10.229.136.1'}]}  # noqa E501
            task.node.update({'network_data': network_data})
            task.driver.boot.validate(task)

    def test_validate_fail(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['boot_file_path'] = {
                "UrlBootFile3": "tftp://1.1.1.24/tftpboot/bootx64.efi"}
            self.assertRaises(exception.MissingParameterValue,
                              task.driver.boot.validate, task)

    def test_validate_invalid_parameters(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            network_data = {'links': [{'id': 'enp1s0', 'type': 'phy', 'ethernet_mac_address': '94:40:C9:D6:03:84', 'mtu': 1500}],  # noqa E501
                            'networks': [{'id': 'provisioning IPv4', 'type': 'ipv4', 'link': 'enp1s0',  # noqa E501
                                          'netmask': '255.255.248.0',
                                          'routes': [{'network': '10.229.136.0'},  # noqa E501
                                                     {'network': '0.0.0.0', 'netmask': '0.0.0.0', 'gateway': '10.229.136.1'}],  # noqa E501
                                          'network_id': ''}],
                            'services': [{'type': 'dns', 'address': '10.229.136.1'}]}  # noqa E501
            task.node.update({'network_data': network_data})
            self.assertRaises(exception.InvalidParameterValue,
                              task.driver.boot.validate, task)
