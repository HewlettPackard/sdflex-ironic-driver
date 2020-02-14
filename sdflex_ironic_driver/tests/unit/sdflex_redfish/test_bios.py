# Copyright 2018 DMTF. All rights reserved.
# Copyright 2019 Hewlett Packard Enterprise Development LP
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
# Hewlett Packard Enterprise made some changes to this file

import mock
from oslo_utils import importutils

from ironic.common import exception
from ironic.common import states
from ironic.conductor import task_manager
from ironic.conductor import utils as manager_utils
from ironic.drivers.modules import deploy_utils
from ironic.drivers.modules import pxe as pxe_boot
from ironic.drivers.modules.redfish import utils as redfish_utils
from ironic import objects
from ironic.tests.unit.db import base as db_base
from ironic.tests.unit.db import utils as db_utils
from ironic.tests.unit.objects import utils as obj_utils

from sdflex_ironic_driver import exception as sdflex_exception
from sdflex_ironic_driver.sdflex_redfish import bios as redfish_bios

sushy = importutils.try_import('sushy')

INFO_DICT = db_utils.get_test_redfish_info()


class NoBiosSystem(object):
    identity = '/redfish/v1/Systems/1234'

    @property
    def bios(self):
        raise sushy.exceptions.MissingAttributeError(attribute='Bios',
                                                     resource=self)


@mock.patch('eventlet.greenthread.sleep', lambda _t: None)
class SdflexRedfishBiosTestCase(db_base.DbTestCase):

    def setUp(self):
        super(SdflexRedfishBiosTestCase, self).setUp()
        self.config(enabled_bios_interfaces=['sdflex-redfish'],
                    enabled_hardware_types=['sdflex-redfish'],
                    enabled_boot_interfaces=['sdflex-redfish'],
                    enabled_power_interfaces=['sdflex-redfish'],
                    enabled_management_interfaces=['sdflex-redfish'])
        self.node = obj_utils.create_test_node(
            self.context, driver='sdflex-redfish', driver_info=INFO_DICT)

    @mock.patch.object(redfish_bios, 'sushy', None)
    def test_loading_error(self):
        self.assertRaisesRegex(
            exception.DriverLoadError,
            'Unable to import the sushy library',
            redfish_bios.SdflexRedfishBios)

    def test_get_properties(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            properties = task.driver.get_properties()
            for prop in redfish_utils.COMMON_PROPERTIES:
                self.assertIn(prop, properties)

    @mock.patch.object(redfish_utils, 'parse_driver_info', autospec=True)
    def test_validate(self, mock_parse_driver_info):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.driver.bios.validate(task)
            mock_parse_driver_info.assert_called_once_with(task.node)

    @mock.patch.object(redfish_utils, 'get_system', autospec=True)
    @mock.patch.object(objects, 'BIOSSettingList', autospec=True)
    def test_cache_bios_settings_noop(self, mock_setting_list,
                                      mock_get_system):
        create_list = []
        update_list = []
        delete_list = []
        nochange_list = [{'name': 'EmbeddedSata', 'value': 'Raid'},
                         {'name': 'NicBoot1', 'value': 'NetworkBoot'}]
        mock_setting_list.sync_node_setting.return_value = (
            create_list, update_list, delete_list, nochange_list
        )

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            attributes = mock_get_system(task.node).bios.attributes
            settings = [{'name': k, 'value': v} for k, v in attributes.items()]
            mock_get_system.reset_mock()

            task.driver.bios.cache_bios_settings(task)
            mock_get_system.assert_called_once_with(task.node)
            mock_setting_list.sync_node_setting.assert_called_once_with(
                task.context, task.node.id, settings)
            mock_setting_list.create.assert_not_called()
            mock_setting_list.save.assert_not_called()
            mock_setting_list.delete.assert_not_called()

    @mock.patch.object(redfish_utils, 'get_system', autospec=True)
    @mock.patch.object(objects, 'BIOSSettingList', autospec=True)
    def test_cache_bios_settings_no_bios(self, mock_setting_list,
                                         mock_get_system):
        create_list = []
        update_list = []
        delete_list = []
        nochange_list = [{'name': 'EmbeddedSata', 'value': 'Raid'},
                         {'name': 'NicBoot1', 'value': 'NetworkBoot'}]
        mock_setting_list.sync_node_setting.return_value = (
            create_list, update_list, delete_list, nochange_list
        )
        mock_get_system.return_value = NoBiosSystem()

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            self.assertRaisesRegex(exception.UnsupportedDriverExtension,
                                   'BIOS settings are not supported',
                                   task.driver.bios.cache_bios_settings, task)
            mock_get_system.assert_called_once_with(task.node)
            mock_setting_list.sync_node_setting.assert_not_called()
            mock_setting_list.create.assert_not_called()
            mock_setting_list.save.assert_not_called()
            mock_setting_list.delete.assert_not_called()

    @mock.patch.object(redfish_utils, 'get_system', autospec=True)
    @mock.patch.object(objects, 'BIOSSettingList', autospec=True)
    def test_cache_bios_settings(self, mock_setting_list, mock_get_system):
        create_list = [{'name': 'DebugMode', 'value': 'enabled'}]
        update_list = [{'name': 'BootMode', 'value': 'Uefi'},
                       {'name': 'NicBoot2', 'value': 'NetworkBoot'}]
        delete_list = [{'name': 'AdminPhone', 'value': '555-867-5309'}]
        nochange_list = [{'name': 'EmbeddedSata', 'value': 'Raid'},
                         {'name': 'NicBoot1', 'value': 'NetworkBoot'}]
        delete_names = []
        for setting in delete_list:
            delete_names.append(setting.get('name'))
        mock_setting_list.sync_node_setting.return_value = (
            create_list, update_list, delete_list, nochange_list
        )

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            attributes = mock_get_system(task.node).bios.attributes
            settings = [{'name': k, 'value': v} for k, v in attributes.items()]
            mock_get_system.reset_mock()

            task.driver.bios.cache_bios_settings(task)
            mock_get_system.assert_called_once_with(task.node)
            mock_setting_list.sync_node_setting.assert_called_once_with(
                task.context, task.node.id, settings)
            mock_setting_list.create.assert_called_once_with(
                task.context, task.node.id, create_list)
            mock_setting_list.save.assert_called_once_with(
                task.context, task.node.id, update_list)
            mock_setting_list.delete.assert_called_once_with(
                task.context, task.node.id, delete_names)

    @mock.patch.object(redfish_utils, 'get_system', autospec=True)
    def test_factory_reset_fail(self, mock_get_system):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            bios = mock_get_system(task.node).bios
            bios.reset_bios.side_effect = (
                sdflex_exception.SDFlexOperationNotSupported)
            self.assertRaises(
                sdflex_exception.SDFlexOperationNotSupported,
                task.driver.bios.factory_reset, task)

    @mock.patch.object(pxe_boot.PXEBoot, 'prepare_ramdisk',
                       spec_set=True, autospec=True)
    @mock.patch.object(deploy_utils, 'build_agent_options', autospec=True)
    @mock.patch.object(redfish_utils, 'get_system', autospec=True)
    @mock.patch.object(manager_utils, 'node_power_action', autospec=True)
    def test_apply_configuration_step1(self, mock_power_action,
                                       mock_get_system,
                                       mock_build_agent_options,
                                       mock_prepare):
        settings = [{'name': 'ProcTurboMode', 'value': 'Disabled'},
                    {'name': 'NicBoot1', 'value': 'NetworkBoot'}]
        attributes = {s['name']: s['value'] for s in settings}
        mock_build_agent_options.return_value = {'a': 'b'}
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.driver.bios.apply_configuration(task, settings)
            mock_get_system.assert_called_with(task.node)
            mock_power_action.assert_called_once_with(task, states.REBOOT)
            bios = mock_get_system(task.node).bios
            bios.set_attributes.assert_called_once_with(attributes)
            mock_build_agent_options.assert_called_once_with(task.node)
            mock_prepare.assert_called_once_with(mock.ANY, task, {'a': 'b'})
            info = task.node.driver_internal_info
            self.assertTrue(
                all(x in info for x in (
                    'post_config_reboot_requested', 'cleaning_reboot',
                    'skip_current_clean_step')))

    @mock.patch.object(redfish_utils, 'get_system', autospec=True)
    def test_apply_configuration_step2(self, mock_get_system):
        settings = [{'name': 'ProcTurboMode', 'value': 'Disabled'},
                    {'name': 'NicBoot1', 'value': 'NetworkBoot'}]
        requested_attrs = {'ProcTurboMode': 'Enabled'}
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            driver_internal_info = task.node.driver_internal_info
            driver_internal_info['post_config_reboot_requested'] = True
            driver_internal_info['requested_bios_attrs'] = requested_attrs
            task.node.driver_internal_info = driver_internal_info
            task.node.save()
            task.driver.bios.apply_configuration(task, settings)
            mock_get_system.assert_called_with(task.node)
            info = task.node.driver_internal_info
            self.assertNotIn('post_config_reboot_requested', info)
            self.assertNotIn('requested_bios_attrs', info)

    @mock.patch.object(redfish_utils, 'get_system', autospec=True)
    def test_apply_configuration_not_supported(self, mock_get_system):
        settings = [{'name': 'ProcTurboMode', 'value': 'Disabled'},
                    {'name': 'NicBoot1', 'value': 'NetworkBoot'}]
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            mock_get_system.return_value = NoBiosSystem()
            self.assertRaisesRegex(exception.RedfishError,
                                   'BIOS settings are not supported',
                                   task.driver.bios.apply_configuration,
                                   task, settings)
            mock_get_system.assert_called_once_with(task.node)

    @mock.patch.object(redfish_utils, 'get_system', autospec=True)
    def test_check_bios_attrs(self, mock_get_system):
        settings = [{'name': 'ProcTurboMode', 'value': 'Disabled'},
                    {'name': 'NicBoot1', 'value': 'NetworkBoot'}]
        requested_attrs = {'ProcTurboMode': 'Enabled'}
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            attributes = mock_get_system(task.node).bios.attributes
            task.node.driver_internal_info[
                'post_config_reboot_requested'] = True
            task.node.driver_internal_info[
                'requested_bios_attrs'] = requested_attrs
            task.driver.bios._check_bios_attrs = mock.MagicMock()
            task.driver.bios.apply_configuration(task, settings)
            task.driver.bios._check_bios_attrs \
                .assert_called_once_with(task, attributes, requested_attrs)

    @mock.patch.object(redfish_utils, 'get_system', autospec=True)
    def test_apply_configuration_fail(self, mock_get_system):
        settings = [{'name': 'ProcTurboMode', 'value': 'Disabled'},
                    {'name': 'NicBoot1', 'value': 'NetworkBoot'}]
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            bios = mock_get_system(task.node).bios
            bios.set_attributes.side_effect = sushy.exceptions.SushyError
            self.assertRaisesRegex(
                exception.RedfishError, 'BIOS apply configuration failed',
                task.driver.bios.apply_configuration, task, settings)

    @mock.patch.object(redfish_utils, 'get_system', autospec=True)
    def test_post_configuration(self, mock_get_system):
        settings = [{'name': 'ProcTurboMode', 'value': 'Disabled'},
                    {'name': 'NicBoot1', 'value': 'NetworkBoot'}]
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.driver.bios.post_configuration = mock.MagicMock()
            task.driver.bios.apply_configuration(task, settings)
            task.driver.bios.post_configuration\
                .assert_called_once_with(task, settings)
