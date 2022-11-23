# Copyright 2014 Hewlett-Packard Development Company, L.P.
# Copyright 2019-2022 Hewlett Packard Enterprise Development LP
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

"""Test class for common methods used by sdflex modules."""

import os

import mock
from oslo_config import cfg
from oslo_utils import importutils
from oslo_utils import uuidutils
import six

from ironic.common import exception as ironic_exception
from ironic.conductor import task_manager
from ironic.drivers.modules import deploy_utils
from ironic.tests.unit.db import base as db_base
from ironic.tests.unit.objects import utils as obj_utils

from sdflex_ironic_driver import exception as exception
from sdflex_ironic_driver.sdflex_redfish import common as sdflex_common

INFO_DICT = {
    "redfish_address": "1.2.3.4",
    "redfish_username": "admin",
    "redfish_password": "fake",
    "redfish_system_id": "/redfish/v1/Systems/Partition2",
    "enable_directed_lanboot": False,
    "enable_uefi_httpboot": False,
    "boot_file_path": {"UrlBootFile": "tftp://1.1.1.4/tftpboot/bootx64.efi"},
    "http_boot_uri": "http://1.2.3.4/bootx64.efi"
}
sdflex_client = importutils.try_import('sdflexutils.redfish.client')
sdflex_error = importutils.try_import('sdflexutils.exception')

if six.PY3:
    import io
    file = io.BytesIO


CONF = cfg.CONF


class BaseSdflexTest(db_base.DbTestCase):

    boot_interface = None
    bios_interface = 'sdflex-redfish'
    deploy_interface = 'sdflex-redfish'

    def setUp(self):
        super(BaseSdflexTest, self).setUp()
        self.config(enabled_hardware_types=['sdflex-redfish', 'fake-hardware'],
                    enabled_boot_interfaces=['sdflex-redfish',
                                             'sdflex-redfish-vmedia',
                                             'sdflex-redfish-dhcpless',
                                             'fake'],
                    enabled_power_interfaces=['sdflex-redfish', 'fake'],
                    enabled_bios_interfaces=['sdflex-redfish', 'fake'],
                    enabled_deploy_interfaces=['sdflex-redfish', 'fake'],
                    enabled_management_interfaces=['sdflex-redfish', 'fake'],
                    enabled_vendor_interfaces=['sdflex-redfish', 'redfish',
                                               'no-vendor', 'fake'],
                    enabled_inspect_interfaces=['inspector', 'fake',
                                                'no-inspect'])
        self.info = INFO_DICT.copy()
        self.node = obj_utils.create_test_node(
            self.context, uuid=uuidutils.generate_uuid(),
            driver='sdflex-redfish', boot_interface=self.boot_interface,
            bios_interface=self.bios_interface,
            deploy_interface=self.deploy_interface,
            driver_info=self.info)


class SdflexValidateParametersTestCase(BaseSdflexTest):

    @mock.patch.object(os.path, 'isfile', return_value=True, autospec=True)
    def _test_parse_driver_info(self, isFile_mock):
        info = sdflex_common.parse_driver_info(self.node)
        self.assertEqual(INFO_DICT['redfish_address'],
                         info['redfish_address'])
        self.assertEqual(INFO_DICT['redfish_username'],
                         info['redfish_username'])
        self.assertEqual(INFO_DICT['redfish_password'],
                         info['redfish_password'])
        self.assertEqual(INFO_DICT['redfish_system_id'],
                         info['redfish_system_id'])
        self.assertEqual(60, info['client_timeout'])
        self.assertEqual(443, info['client_port'])
        self.assertEqual('/home/user/cafile.pem', info['ca_file'])

    def test_parse_driver_info_missing_address(self):
        del self.node.driver_info['redfish_address']
        self.assertRaises(ironic_exception.MissingParameterValue,
                          sdflex_common.parse_driver_info, self.node)

    def test_parse_driver_info_missing_username(self):
        del self.node.driver_info['redfish_username']
        self.assertRaises(ironic_exception.MissingParameterValue,
                          sdflex_common.parse_driver_info, self.node)

    def test_parse_driver_info_missing_password(self):
        del self.node.driver_info['redfish_password']
        self.assertRaises(ironic_exception.MissingParameterValue,
                          sdflex_common.parse_driver_info, self.node)

    def test_parse_driver_info_missing_system_id(self):
        del self.node.driver_info['redfish_system_id']
        self.assertRaises(ironic_exception.MissingParameterValue,
                          sdflex_common.parse_driver_info, self.node)

    def test_parse_driver_info_missing_multiple_params(self):
        del self.node.driver_info['redfish_password']
        del self.node.driver_info['redfish_address']
        e = self.assertRaises(ironic_exception.MissingParameterValue,
                              sdflex_common.parse_driver_info, self.node)
        self.assertIn('redfish_password', str(e))
        self.assertIn('redfish_address', str(e))


class SdflexCommonMethodsTestCase(BaseSdflexTest):

    @mock.patch.object(os.path, 'isfile', return_value=True, autospec=True)
    @mock.patch.object(sdflex_client, 'SdflexClient', spec_set=True,
                       autospec=True)
    def _test_get_sdflex_object(self, sdflex_client_mock, isFile_mock,
                                ca_file=None):
        self.info['client_timeout'] = 600
        self.info['client_port'] = 433
        self.info['ca_file'] = ca_file
        self.node.driver_info = self.info
        sdflex_client_mock.return_value = 'sdflex_object'
        returned_sdflex_object = sdflex_common.get_sdflex_object(self.node)
        sdflex_client_mock.assert_called_with(
            self.info['redfish_address'],
            self.info['redfish_username'],
            self.info['redfish_password'],
            self.info['redfish_system_id'],
            self.info['client_timeout'],
            self.info['client_port'],
            cacert=self.info['ca_file'])
        self.assertEqual('sdflex_object', returned_sdflex_object)

    @mock.patch.object(sdflex_common, 'get_sdflex_object', spec_set=True,
                       autospec=True)
    def test_get_secure_boot_mode(self, get_sdflex_object_mock):
        sdflex_object_mock = get_sdflex_object_mock.return_value
        sdflex_object_mock.get_secure_boot_mode.return_value = True
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            ret = sdflex_common.get_secure_boot_mode(task)
            sdflex_object_mock.get_secure_boot_mode.assert_called_once_with()
            self.assertTrue(ret)
        self.assertTrue(True)

    @mock.patch.object(sdflex_common, 'get_sdflex_object', spec_set=True,
                       autospec=True)
    def test_get_secure_boot_mode_not_supported(self,
                                                sdflex_object_mock):
        sdflex_mock_object = sdflex_object_mock.return_value
        exc = sdflex_error.SDFlexCommandNotSupportedError('error')
        sdflex_mock_object.get_secure_boot_mode.side_effect = exc

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            self.assertRaises(exception.SDFlexOperationNotSupported,
                              sdflex_common.get_secure_boot_mode,
                              task)
        sdflex_mock_object.get_secure_boot_mode.assert_called_once_with()

    @mock.patch.object(sdflex_common, 'get_sdflex_object', spec_set=True,
                       autospec=True)
    def test_set_secure_boot_mode(self,
                                  get_sdflex_object_mock):
        sdflex_object_mock = get_sdflex_object_mock.return_value
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            sdflex_common.set_secure_boot_mode(task, True)
            sdflex_object_mock.set_secure_boot_mode.assert_called_once_with(
                True)

    @mock.patch.object(sdflex_common, 'get_sdflex_object', spec_set=True,
                       autospec=True)
    def test_set_secure_boot_mode_not_supported(self,
                                                sdflex_object_mock):
        sdflex_mock_object = sdflex_object_mock.return_value
        exc = sdflex_error.SDFlexCommandNotSupportedError('error')
        sdflex_mock_object.set_secure_boot_mode.side_effect = exc

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            self.assertRaises(exception.SDFlexOperationNotSupported,
                              sdflex_common.set_secure_boot_mode,
                              task, False)
        sdflex_mock_object.set_secure_boot_mode.assert_called_once_with(False)

    @mock.patch.object(deploy_utils, 'is_secure_boot_requested', spec_set=True,
                       autospec=True)
    @mock.patch.object(sdflex_common, 'set_secure_boot_mode', spec_set=True,
                       autospec=True)
    def test_update_secure_boot_mode_passed_true(self,
                                                 func_set_secure_boot_mode,
                                                 func_is_secure_boot_req):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            func_is_secure_boot_req.return_value = True
            sdflex_common.update_secure_boot_mode(task, True)
            func_set_secure_boot_mode.assert_called_once_with(task, True)

    @mock.patch.object(deploy_utils, 'is_secure_boot_requested', spec_set=True,
                       autospec=True)
    @mock.patch.object(sdflex_common, 'set_secure_boot_mode', spec_set=True,
                       autospec=True)
    def test_update_secure_boot_mode_passed_false(self,
                                                  func_set_secure_boot_mode,
                                                  func_is_secure_boot_req):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            func_is_secure_boot_req.return_value = False
            sdflex_common.update_secure_boot_mode(task, False)
            self.assertFalse(func_set_secure_boot_mode.called)

    @mock.patch.object(sdflex_common, 'get_sdflex_object', spec_set=True,
                       autospec=True)
    def test_set_secure_boot_mode_fail(self,
                                       get_sdflex_object_mock):
        sdflex_mock_object = get_sdflex_object_mock.return_value
        exc = sdflex_error.SDFlexError('error')
        sdflex_mock_object.set_secure_boot_mode.side_effect = exc

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            self.assertRaises(exception.SDFlexOperationError,
                              sdflex_common.set_secure_boot_mode,
                              task, False)
        sdflex_mock_object.set_secure_boot_mode.assert_called_once_with(False)

    @mock.patch.object(sdflex_common, 'get_sdflex_object', spec_set=True,
                       autospec=True)
    def test_enable_directed_lan_boot(self, get_sdflex_object_mock):
        sdflex_object_mock = get_sdflex_object_mock.return_value
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            boot_file_path = task.node.driver_info['boot_file_path']
            sdflex_common.enable_directed_lan_boot(task.node)
            sdflex_object_mock.set_bios_settings.assert_called_once_with(
                boot_file_path)

    @mock.patch.object(sdflex_common, 'get_sdflex_object', spec_set=True,
                       autospec=True)
    def test_enable_directed_lan_boot_fail(self, get_sdflex_object_mock):
        sdflex_object_mock = get_sdflex_object_mock.return_value
        sdflex_object_mock.set_bios_settings.side_effect = (
            sdflex_error.SDFlexError('error'))
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            boot_file_path = None
            task.node.driver_info['boot_file_path'] = boot_file_path
            self.assertRaises(exception.SDFlexOperationError,
                              sdflex_common.enable_directed_lan_boot,
                              task.node)
            sdflex_object_mock.set_bios_settings.assert_called_once_with(
                boot_file_path)

    @mock.patch.object(sdflex_common, 'get_sdflex_object', spec_set=True,
                       autospec=True)
    def test_set_network_setting_dhcpless_boot(self, get_sdflex_object_mock):
        sdflex_object_mock = get_sdflex_object_mock.return_value
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
            url = 'http:/1.2.3.4/boot.iso'
            expected_data = {'UrlBootFile': 'http:/1.2.3.4/boot.iso',
                             'Ipv4Address': '10.229.136.128',
                             'Ipv4Gateway': '10.229.136.1',
                             'Ipv4SubnetMask': '255.255.248.0',
                             'Dhcpv4': 'Disabled'}
            sdflex_common.set_network_setting_dhcpless_boot(task.node, url)
            sdflex_object_mock.set_bios_settings.assert_called_once_with(
                expected_data)

    @mock.patch.object(sdflex_common, 'get_sdflex_object', spec_set=True,
                       autospec=True)
    def test_set_network_setting_dhcpless_boot_fail(self,
                                                    get_sdflex_object_mock):
        sdflex_object_mock = get_sdflex_object_mock.return_value
        sdflex_object_mock.set_bios_settings.side_effect = (
            sdflex_error.SDFlexError('error'))
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
            url = 'http:/1.2.3.4/boot.iso'
            self.assertRaises(exception.SDFlexOperationError,
                              sdflex_common.set_network_setting_dhcpless_boot,
                              task.node, url)

    @mock.patch.object(sdflex_common, 'get_sdflex_object', spec_set=True,
                       autospec=True)
    def test_reset_network_setting_dhcpless_boot(self, get_sdflex_object_mock):
        sdflex_object_mock = get_sdflex_object_mock.return_value
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            bios_setting = {'UrlBootFile': '', 'Ipv4Address': '',
                            'Ipv4Gateway': '', 'Ipv4SubnetMask': '',
                            'Dhcpv4': 'Enabled'}
            sdflex_common.reset_network_setting_dhcpless_boot(task.node)
            sdflex_object_mock.set_bios_settings.assert_called_once_with(
                bios_setting)

    @mock.patch.object(sdflex_common, 'get_sdflex_object', spec_set=True,
                       autospec=True)
    def test_reset_network_setting_dhcpless_boot_fail(self,
                                                      get_sdflex_object_mock):
        sdflex_object_mock = get_sdflex_object_mock.return_value
        sdflex_object_mock.set_bios_settings.side_effect = (
            sdflex_error.SDFlexError('error'))
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            bios_setting = {'UrlBootFile': '', 'Ipv4Address': '',
                            'Ipv4Gateway': '', 'Ipv4SubnetMask': '',
                            'Dhcpv4': 'Enabled'}
            self.assertRaises(
                exception.SDFlexOperationError,
                sdflex_common.reset_network_setting_dhcpless_boot, task.node)
            sdflex_object_mock.set_bios_settings.assert_called_once_with(
                bios_setting)

    @mock.patch.object(sdflex_common, 'get_sdflex_object', spec_set=True,
                       autospec=True)
    def test_reset_bios_settings(self, get_sdflex_object_mock):
        sdflex_object_mock = get_sdflex_object_mock.return_value
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            boot_file_path = {'UrlBootFile': None, 'UrlBootFile2': None}
            task.node.driver_info['boot_file_path'] = boot_file_path
            sdflex_common.enable_directed_lan_boot(task.node)
            sdflex_object_mock.set_bios_settings.assert_called_once_with(
                boot_file_path)

    @mock.patch.object(sdflex_common, 'get_sdflex_object', spec_set=True,
                       autospec=True)
    def test_reset_bios_settings_fail(self, get_sdflex_object_mock):
        sdflex_object_mock = get_sdflex_object_mock.return_value
        sdflex_object_mock.set_bios_settings.side_effect = (
            sdflex_error.SDFlexError('error'))
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            boot_file_path = task.node.driver_info['boot_file_path']
            self.assertRaises(exception.SDFlexOperationError,
                              sdflex_common.enable_directed_lan_boot,
                              task.node)
            sdflex_object_mock.set_bios_settings.assert_called_once_with(
                boot_file_path)

    @mock.patch.object(sdflex_common, 'get_sdflex_object', spec_set=True,
                       autospec=True)
    def test_enable_uefi_http_boot_file(self, get_sdflex_object_mock):
        sdflex_object_mock = get_sdflex_object_mock.return_value
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            boot_file_path = task.node.driver_info['boot_file_path']
            task.node.driver_info['http_boot_uri'] = None
            sdflex_common.enable_uefi_http_boot(task.node)
            sdflex_object_mock.set_bios_settings.assert_called_once_with(
                boot_file_path)

    @mock.patch.object(sdflex_common, 'get_sdflex_object', spec_set=True,
                       autospec=True)
    def test_enable_uefi_http_boot_uri(self, get_sdflex_object_mock):
        sdflex_object_mock = get_sdflex_object_mock.return_value
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            http_boot_uri = task.node.driver_info['http_boot_uri']
            sdflex_common.enable_uefi_http_boot(task.node)
            sdflex_object_mock.set_http_boot_uri.assert_called_once_with(
                http_boot_uri)

    @mock.patch.object(sdflex_common, 'get_sdflex_object', spec_set=True,
                       autospec=True)
    def test_enable_uefi_http_boot_file_fail(self, get_sdflex_object_mock):
        sdflex_object_mock = get_sdflex_object_mock.return_value
        sdflex_object_mock.set_bios_settings.side_effect = (
            sdflex_error.SDFlexError('error'))
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            boot_file_path = None
            task.node.driver_info['boot_file_path'] = boot_file_path
            task.node.driver_info['http_boot_uri'] = None
            self.assertRaises(exception.SDFlexOperationError,
                              sdflex_common.enable_uefi_http_boot,
                              task.node)

    @mock.patch.object(sdflex_common, 'get_sdflex_object', spec_set=True,
                       autospec=True)
    def test_enable_uefi_http_boot_uri_fail(self, get_sdflex_object_mock):
        sdflex_object_mock = get_sdflex_object_mock.return_value
        sdflex_object_mock.set_http_boot_uri.side_effect = (
            sdflex_error.SDFlexError('error'))
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            set_http_boot_uri = None
            task.node.driver_info['boot_file_path'] = None
            task.node.driver_info['http_boot_uri'] = set_http_boot_uri
            self.assertRaises(exception.SDFlexOperationError,
                              sdflex_common.enable_uefi_http_boot,
                              task.node)
