#
# Copyright 2014 Rackspace, Inc
# All Rights Reserved
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
# Most of the methods/code snippets in this file are owned by Rackspace, Inc

import os
import tempfile

from ironic_lib import utils as ironic_utils
import mock
from oslo_config import cfg
from oslo_utils import fileutils
from oslo_utils import uuidutils

from ironic.common import exception
from ironic.common.glance_service import image_service
from ironic.common import states
from ironic.conductor import task_manager
from ironic.drivers.modules import deploy_utils
from ironic.drivers.modules import pxe
from ironic.tests.unit.db import base as db_base
from ironic.tests.unit.db import utils as db_utils
from ironic.tests.unit.objects import utils as object_utils

from sdflex_ironic_driver import http_utils
CONF = cfg.CONF
INST_INFO_DICT = db_utils.get_test_pxe_instance_info()
DRV_INFO_DICT = db_utils.get_test_pxe_driver_info()
DRV_INTERNAL_INFO_DICT = db_utils.get_test_pxe_driver_internal_info()


# Prevent /httpboot validation on creating the node
@mock.patch('ironic.drivers.modules.pxe.PXEBoot.__init__', lambda self: None)
class TestHTTPUtils(db_base.DbTestCase):

    def setUp(self):
        super(TestHTTPUtils, self).setUp()

        self.http_options = {
            'deployment_aki_path': u'/httpboot/1be26c0b-03f2-4d2e-ae87-'
                                   u'c02d7f33c123/deploy_kernel',
            'aki_path': u'/httpboot/1be26c0b-03f2-4d2e-ae87-c02d7f33c123/'
                        u'kernel',
            'ari_path': u'/httpboot/1be26c0b-03f2-4d2e-ae87-c02d7f33c123/'
                        u'ramdisk',
            'kernel_append_params': 'test_param',
            'deployment_ari_path': u'/httpboot/1be26c0b-03f2-4d2e-ae87-c02d7'
                                   u'f33c123/deploy_ramdisk',
            'ipa-api-url': 'http://192.168.122.184:6385',
            'ipxe_timeout': 0,
            'ramdisk_opts': 'ramdisk_param',
        }

        self.node = object_utils.create_test_node(
            self.context,
            uuid='1be26c0b-03f2-4d2e-ae87-c02d7f33c123',
            driver_info=DRV_INFO_DICT)

    @mock.patch('ironic.common.utils.create_link_without_raise', autospec=True)
    @mock.patch('ironic_lib.utils.unlink_without_raise', autospec=True)
    def test__write_mac_http_configs(self, unlink_mock, create_link_mock):
        port_1 = object_utils.create_test_port(
            self.context, node_id=self.node.id,
            address='11:22:33:44:55:66', uuid=uuidutils.generate_uuid())
        port_2 = object_utils.create_test_port(
            self.context, node_id=self.node.id,
            address='11:22:33:44:55:67', uuid=uuidutils.generate_uuid())
        create_link_calls = [
            mock.call(u'1be26c0b-03f2-4d2e-ae87-c02d7f33c123/config',
                      '/httpboot/11:22:33:44:55:66.conf'),
            mock.call(u'1be26c0b-03f2-4d2e-ae87-c02d7f33c123/config',
                      '/httpboot/11:22:33:44:55:67.conf')
        ]
        unlink_calls = [
            mock.call('/httpboot/11:22:33:44:55:66.conf'),
            mock.call('/httpboot/11:22:33:44:55:67.conf')
        ]
        with task_manager.acquire(self.context, self.node.uuid) as task:
            task.ports = [port_1, port_2]
            http_utils._link_mac_http_configs(task)

        unlink_mock.assert_has_calls(unlink_calls)
        create_link_mock.assert_has_calls(create_link_calls)

    @mock.patch('ironic.common.utils.create_link_without_raise', autospec=True)
    @mock.patch('ironic_lib.utils.unlink_without_raise', autospec=True)
    @mock.patch('ironic.common.dhcp_factory.DHCPFactory.provider',
                autospec=True)
    def test__link_ip_address_http_configs(self, provider_mock, unlink_mock,
                                           create_link_mock):
        ip_address = '10.10.0.1'
        address = "aa:aa:aa:aa:aa:aa"
        object_utils.create_test_port(self.context, node_id=self.node.id,
                                      address=address)

        provider_mock.get_ip_addresses.return_value = [ip_address]
        create_link_calls = [
            mock.call(u'1be26c0b-03f2-4d2e-ae87-c02d7f33c123/config',
                      u'/httpboot/10.10.0.1.conf'),
        ]
        with task_manager.acquire(self.context, self.node.uuid) as task:
            http_utils._link_ip_address_http_configs(task)

        unlink_mock.assert_called_once_with('/httpboot/10.10.0.1.conf')
        create_link_mock.assert_has_calls(create_link_calls)

    @mock.patch.object(os, 'chmod', autospec=True)
    @mock.patch('ironic.common.utils.write_to_file', autospec=True)
    @mock.patch('ironic.common.utils.render_template', autospec=True)
    @mock.patch('oslo_utils.fileutils.ensure_tree', autospec=True)
    @mock.patch.object(http_utils, '_link_ip_address_http_configs',
                       autospec=True)
    def test_create_http_config(self, link_ip_addr_mock, ensure_tree_mock,
                                render_mock, write_mock, chmod_mock):
        with task_manager.acquire(self.context, self.node.uuid) as task:
            http_utils.create_http_config(task, self.http_options,
                                          CONF.pxe.pxe_config_template)
            render_mock.assert_called_with(
                CONF.pxe.pxe_config_template,
                {'http_options': self.http_options,
                 'ROOT': '(( ROOT ))',
                 'DISK_IDENTIFIER': '(( DISK_IDENTIFIER ))'}
            )
        node_dir = os.path.join(CONF.deploy.http_root, self.node.uuid)
        pxe_dir = os.path.join(CONF.deploy.http_root, 'pxelinux.cfg')
        ensure_calls = [
            mock.call(node_dir), mock.call(pxe_dir),
        ]
        ensure_tree_mock.assert_has_calls(ensure_calls)
        chmod_mock.assert_not_called()

        http_cfg_file_path = http_utils.get_http_config_file_path(
            self.node.uuid)
        write_mock.assert_called_with(http_cfg_file_path,
                                      render_mock.return_value)

    @mock.patch.object(os, 'chmod', autospec=True)
    @mock.patch('ironic.common.utils.write_to_file', autospec=True)
    @mock.patch('ironic.common.utils.render_template', autospec=True)
    @mock.patch('oslo_utils.fileutils.ensure_tree', autospec=True)
    @mock.patch('sdflex_ironic_driver.http_utils._link_ip_address_http_configs',  # noqa: E501
                autospec=True)
    def test_create_http_config_set_dir_permission(
            self, link_ip_address_mock, ensure_tree_mock,
            render_mock, write_mock, chmod_mock):
        self.config(dir_permission=0o755, group='pxe')
        with task_manager.acquire(self.context, self.node.uuid) as task:
            http_utils.create_http_config(task, self.http_options,
                                          CONF.pxe.pxe_config_template)
            render_mock.assert_called_with(
                CONF.pxe.pxe_config_template,
                {'http_options': self.http_options,
                 'ROOT': '(( ROOT ))',
                 'DISK_IDENTIFIER': '(( DISK_IDENTIFIER ))'}
            )
        node_dir = os.path.join(CONF.deploy.http_root, self.node.uuid)
        pxe_dir = os.path.join(CONF.deploy.http_root, 'pxelinux.cfg')
        ensure_calls = [
            mock.call(node_dir), mock.call(pxe_dir),
        ]
        ensure_tree_mock.assert_has_calls(ensure_calls)
        chmod_calls = [mock.call(node_dir, 0o755), mock.call(pxe_dir, 0o755)]
        chmod_mock.assert_has_calls(chmod_calls)
        http_cfg_file_path = (
            http_utils.get_http_config_file_path(self.node.uuid))
        write_mock.assert_called_with(http_cfg_file_path,
                                      render_mock.return_value)

    @mock.patch.object(os.path, 'isdir', autospec=True)
    @mock.patch.object(os, 'chmod', autospec=True)
    @mock.patch('ironic.common.utils.write_to_file', autospec=True)
    @mock.patch('ironic.common.utils.render_template', autospec=True)
    @mock.patch('oslo_utils.fileutils.ensure_tree', autospec=True)
    @mock.patch('sdflex_ironic_driver.http_utils._link_ip_address_http_configs',  # noqa: E501
                autospec=True)
    def test_create_http_config_existing_dirs(
            self, link_ip_address_mock, ensure_tree_mock,
            render_mock, write_mock, chmod_mock, isdir_mock):
        self.config(dir_permission=0o755, group='pxe')
        with task_manager.acquire(self.context, self.node.uuid) as task:
            isdir_mock.return_value = True
            http_utils.create_http_config(task, self.http_options,
                                          CONF.pxe.pxe_config_template)
            render_mock.assert_called_with(
                CONF.pxe.pxe_config_template,
                {'http_options': self.http_options,
                 'ROOT': '(( ROOT ))',
                 'DISK_IDENTIFIER': '(( DISK_IDENTIFIER ))'}
            )
        ensure_tree_mock.assert_has_calls([])
        chmod_mock.assert_not_called()
        isdir_mock.assert_has_calls([])
        http_cfg_file_path = (
            http_utils.get_http_config_file_path(self.node.uuid))
        write_mock.assert_called_with(http_cfg_file_path,
                                      render_mock.return_value)

    @mock.patch.object(os, 'chmod', autospec=True)
    @mock.patch('sdflex_ironic_driver.http_utils._link_ip_address_http_configs',  # noqa: E501
                autospec=True)
    @mock.patch('ironic.common.utils.write_to_file', autospec=True)
    @mock.patch('ironic.common.utils.render_template', autospec=True)
    @mock.patch('oslo_utils.fileutils.ensure_tree', autospec=True)
    def test_create_http_config_uefi_grub(self, ensure_tree_mock, render_mock,
                                          write_mock, link_ip_configs_mock,
                                          chmod_mock):
        grub_tmplte = "sdflex_ironic_driver/tests/unit/templates/http_grub_config.template"  # noqa: E501
        with task_manager.acquire(self.context, self.node.uuid) as task:
            task.node.properties['capabilities'] = 'boot_mode:uefi'
            task.node.driver_info['enable_http_boot'] = 'False'
            http_utils.create_http_config(task, self.http_options,
                                          grub_tmplte)

            ensure_calls = [
                mock.call(os.path.join(CONF.deploy.http_root, self.node.uuid)),
                mock.call(os.path.join(CONF.deploy.http_root, 'pxelinux.cfg')),
            ]
            ensure_tree_mock.assert_has_calls(ensure_calls)
            chmod_mock.assert_not_called()
            render_mock.assert_called_with(
                grub_tmplte,
                {'http_options': self.http_options,
                 'ROOT': '(( ROOT ))',
                 'DISK_IDENTIFIER': '(( DISK_IDENTIFIER ))'})
            link_ip_configs_mock.assert_called_once_with(task)

        http_cfg_file_path = (
            http_utils.get_http_config_file_path(self.node.uuid))
        write_mock.assert_called_with(http_cfg_file_path,
                                      render_mock.return_value)

    @mock.patch.object(os, 'chmod', autospec=True)
    @mock.patch('sdflex_ironic_driver.http_utils._link_mac_http_configs',
                autospec=True)
    @mock.patch('sdflex_ironic_driver.http_utils._link_ip_address_http_configs',  # noqa: E501
                autospec=True)
    @mock.patch('ironic.common.utils.write_to_file', autospec=True)
    @mock.patch('ironic.common.utils.render_template', autospec=True)
    @mock.patch('oslo_utils.fileutils.ensure_tree', autospec=True)
    def test_create_http_config_uefi_mac_address(
            self, ensure_tree_mock, render_mock,
            write_mock, link_ip_configs_mock,
            link_mac_http_configs_mock, chmod_mock):
        # TODO(TheJulia): We should... like... fix the template to
        # enable mac address usage.....
        grub_tmplte = "sdflex_ironic_driver/tests/unit/templates/http_grub_config.template"  # noqa: E501
        self.config(dhcp_provider='none', group='dhcp')
        link_ip_configs_mock.side_effect = \
            exception.FailedToGetIPAddressOnPort(port_id='blah')
        with task_manager.acquire(self.context, self.node.uuid) as task:
            task.node.driver_info['enable_http_boot'] = 'False'
            task.node.properties['capabilities'] = 'boot_mode:uefi'
            http_utils.create_http_config(task, self.http_options,
                                          grub_tmplte)

            ensure_calls = [
                mock.call(os.path.join(CONF.deploy.http_root, self.node.uuid)),
                mock.call(os.path.join(CONF.deploy.http_root, 'pxelinux.cfg')),
            ]
            ensure_tree_mock.assert_has_calls(ensure_calls)
            chmod_mock.assert_not_called()
            render_mock.assert_called_with(
                grub_tmplte,
                {'http_options': self.http_options,
                 'ROOT': '(( ROOT ))',
                 'DISK_IDENTIFIER': '(( DISK_IDENTIFIER ))'})
            link_mac_http_configs_mock.assert_called_once_with(task)
            link_ip_configs_mock.assert_called_once_with(task)

        http_cfg_file_path = (
            http_utils.get_http_config_file_path(self.node.uuid))
        write_mock.assert_called_with(http_cfg_file_path,
                                      render_mock.return_value)

    @mock.patch('ironic.common.utils.rmtree_without_raise', autospec=True)
    @mock.patch('ironic_lib.utils.unlink_without_raise', autospec=True)
    @mock.patch('ironic.common.dhcp_factory.DHCPFactory.provider',
                autospec=True)
    def test_clean_up_http_config(self, provider_mock, unlink_mock,
                                  rmtree_mock):
        address = '00:11:22:33:44:55'
        ip_address = '10.10.0.1'
        provider_mock.get_ip_addresses.return_value = [ip_address]
        port_1 = object_utils.create_test_port(self.context,
                                               node_id=self.node.id,
                                               address=address,
                                               uuid=uuidutils.generate_uuid())

        with task_manager.acquire(self.context, self.node.uuid) as task:
            task.node.driver_info['enable_http_boot'] = 'True'
            task.ports = [port_1]
            http_utils.clean_up_http_config(task)

        ensure_calls = [
            mock.call("/httpboot/%s.conf" % ip_address),
            mock.call("/httpboot/%s.conf" % address)
        ]

        unlink_mock.assert_has_calls(ensure_calls)
        rmtree_mock.assert_called_once_with(
            os.path.join(CONF.deploy.http_root, self.node.uuid))

    def test__get_http_mac_path(self):
        mac = '00:11:22:33:44:55:66'
        self.assertEqual('/httpboot/pxelinux.cfg/01-00-11-22-33-44-55-66',
                         http_utils._get_http_mac_path(mac))

    def test__get_http_ip_address_path(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_http_boot'] = 'True'
            ipaddress = '10.10.0.1'
            self.assertEqual('/httpboot/10.10.0.1.conf',
                             http_utils._get_http_ip_address_path(ipaddress))

    def test_get_http_boot_dir(self):
        expected_dir = '/httpboot'
        self.config(http_root=expected_dir, group='deploy')
        self.assertEqual(expected_dir, http_utils.get_http_boot_dir())

    def test_get_http_config_file_path(self):
        self.assertEqual(os.path.join(CONF.deploy.http_root,
                                      self.node.uuid, 'config'),
                         http_utils.get_http_config_file_path(self.node.uuid))

    def _test_get_kernel_ramdisk_info(self, expected_dir, mode='deploy'):
        driver_info = {
            '%s_kernel' % mode: 'glance://%s-kernel' % mode,
            '%s_ramdisk' % mode: 'glance://%s-ramdisk' % mode,
        }

        expected = {}
        for k, v in driver_info.items():
            expected[k] = (v, expected_dir + '/1be26c0b-03f2-4d2e-ae87-c02d7f33c123/%s' % k)  # noqa: E501
        kr_info = http_utils.get_kernel_ramdisk_info(self.node, driver_info,
                                                     mode=mode)
        self.assertEqual(expected, kr_info)

    def test_get_kernel_ramdisk_info(self):
        expected_dir = '/httpboot'
        self.config(http_root=expected_dir, group='deploy')
        self._test_get_kernel_ramdisk_info(expected_dir)

    def test_get_kernel_ramdisk_info_bad_driver_info(self):
        self.config(http_root='/httpboot', group='deploy')
        driver_info = {}
        self.assertRaises(KeyError, http_utils.get_kernel_ramdisk_info,
                          self.node, driver_info)

    def test_get_rescue_kr_info(self):
        expected_dir = '/httpboot'
        self.config(http_root=expected_dir, group='deploy')
        self._test_get_kernel_ramdisk_info(expected_dir, mode='rescue')

    @mock.patch('ironic.common.utils.rmtree_without_raise', autospec=True)
    @mock.patch('ironic_lib.utils.unlink_without_raise', autospec=True)
    @mock.patch('ironic.common.dhcp_factory.DHCPFactory.provider',
                autospec=True)
    def test_clean_up_http_config_uefi_instance_info(
            self, provider_mock, unlink_mock, rmtree_mock):
        ip_address = '10.10.0.1'
        address = "aa:aa:aa:aa:aa:aa"
        object_utils.create_test_port(self.context, node_id=self.node.id,
                                      address=address)

        provider_mock.get_ip_addresses.return_value = [ip_address]

        with task_manager.acquire(self.context, self.node.uuid) as task:
            task.node.instance_info['deploy_boot_mode'] = 'uefi'
            http_utils.clean_up_http_config(task)

            unlink_calls = [
                mock.call('/httpboot/' + address + ".conf")
            ]
            unlink_mock.assert_has_calls(unlink_calls)
            rmtree_mock.assert_called_once_with(
                os.path.join(CONF.deploy.http_root, self.node.uuid))

    def test_get_http_path_prefix_with_trailing_slash(self):
        self.config(http_root='/httpboot-path/', group='deploy')
        path_prefix = http_utils.get_http_path_prefix()
        self.assertEqual(path_prefix, '/httpboot-path/')

    def test_get_tftp_path_prefix_without_trailing_slash(self):
        self.config(http_root='/httpboot-path', group='deploy')
        path_prefix = http_utils.get_http_path_prefix()
        self.assertEqual(path_prefix, '/httpboot-path/')

    def test_get_path_relative_to_http_root_with_trailing_slash(self):
        self.config(http_root='/httpboot-path/', group='deploy')
        test_file_path = '/httpboot-path/pxelinux.cfg/test'
        relpath = http_utils.get_path_relative_to_http_root(test_file_path)
        self.assertEqual(relpath, 'pxelinux.cfg/test')

    def test_get_path_relative_to_http_root_without_trailing_slash(self):
        self.config(http_root='/httpboot-path', group='deploy')
        test_file_path = '/httpboot-path/pxelinux.cfg/test'
        relpath = http_utils.get_path_relative_to_http_root(test_file_path)
        self.assertEqual(relpath, 'pxelinux.cfg/test')


@mock.patch.object(pxe.PXEBoot, '__init__', lambda self: None)
class PXEInterfacesTestCase(db_base.DbTestCase):

    def setUp(self):
        super(PXEInterfacesTestCase, self).setUp()
        n = {
            'driver': 'fake-hardware',
            'boot_interface': 'pxe',
            'instance_info': INST_INFO_DICT,
            'driver_info': DRV_INFO_DICT,
            'driver_internal_info': DRV_INTERNAL_INFO_DICT,
        }
        self.config_temp_dir('http_root', group='deploy')
        self.node = object_utils.create_test_node(self.context, **n)

    def _test_parse_driver_info_missing_kernel(self, mode='deploy'):
        del self.node.driver_info['%s_kernel' % mode]
        if mode == 'rescue':
            self.node.provision_state = states.RESCUING
        self.assertRaises(exception.MissingParameterValue,
                          http_utils.parse_driver_info, self.node, mode=mode)

    def test_parse_driver_info_missing_deploy_kernel(self):
        self._test_parse_driver_info_missing_kernel()

    def test_parse_driver_info_missing_rescue_kernel(self):
        self._test_parse_driver_info_missing_kernel(mode='rescue')

    def _test_parse_driver_info_missing_ramdisk(self, mode='deploy'):
        del self.node.driver_info['%s_ramdisk' % mode]
        if mode == 'rescue':
            self.node.provision_state = states.RESCUING
        self.assertRaises(exception.MissingParameterValue,
                          http_utils.parse_driver_info, self.node, mode=mode)

    def test_parse_driver_info_missing_deploy_ramdisk(self):
        self._test_parse_driver_info_missing_ramdisk()

    def test_parse_driver_info_missing_rescue_ramdisk(self):
        self._test_parse_driver_info_missing_ramdisk(mode='rescue')

    def _test_parse_driver_info(self, mode='deploy'):
        exp_info = {'%s_ramdisk' % mode: 'glance://%s_ramdisk_uuid' % mode,
                    '%s_kernel' % mode: 'glance://%s_kernel_uuid' % mode}
        image_info = http_utils.parse_driver_info(self.node, mode=mode)
        self.assertEqual(exp_info, image_info)

    def test_parse_driver_info_deploy(self):
        self._test_parse_driver_info()

    def test_parse_driver_info_rescue(self):
        self._test_parse_driver_info(mode='rescue')

    def _test_parse_driver_info_from_conf(self, mode='deploy'):
        del self.node.driver_info['%s_kernel' % mode]
        del self.node.driver_info['%s_ramdisk' % mode]
        exp_info = {'%s_ramdisk' % mode: 'glance://%s_ramdisk_uuid' % mode,
                    '%s_kernel' % mode: 'glance://%s_kernel_uuid' % mode}
        self.config(group='conductor', **exp_info)
        image_info = http_utils.parse_driver_info(self.node, mode=mode)
        self.assertEqual(exp_info, image_info)

    def test_parse_driver_info_from_conf_deploy(self):
        self._test_parse_driver_info_from_conf()

    def test_parse_driver_info_from_conf_rescue(self):
        self._test_parse_driver_info_from_conf(mode='rescue')

    def test_parse_driver_info_mixed_source_deploy(self):
        self.config(deploy_kernel='file:///image',
                    deploy_ramdisk='file:///image',
                    group='conductor')
        self._test_parse_driver_info_missing_ramdisk()

    def test_parse_driver_info_mixed_source_rescue(self):
        self.config(rescue_kernel='file:///image',
                    rescue_ramdisk='file:///image',
                    group='conductor')
        self._test_parse_driver_info_missing_ramdisk(mode='rescue')

    def test__get_deploy_image_info(self):
        expected_info = {'deploy_ramdisk':
                         (DRV_INFO_DICT['deploy_ramdisk'],
                          os.path.join(CONF.deploy.http_root,
                                       self.node.uuid,
                                       'deploy_ramdisk')),
                         'deploy_kernel':
                         (DRV_INFO_DICT['deploy_kernel'],
                          os.path.join(CONF.deploy.http_root,
                                       self.node.uuid,
                                       'deploy_kernel'))}
        image_info = http_utils.get_image_info(self.node)
        self.assertEqual(expected_info, image_info)

    def test__get_deploy_image_info_missing_deploy_kernel(self):
        del self.node.driver_info['deploy_kernel']
        self.assertRaises(exception.MissingParameterValue,
                          http_utils.get_image_info, self.node)

    def test__get_deploy_image_info_deploy_ramdisk(self):
        del self.node.driver_info['deploy_ramdisk']
        self.assertRaises(exception.MissingParameterValue,
                          http_utils.get_image_info, self.node)

    @mock.patch.object(deploy_utils, 'get_boot_option', autospec=True)
    def _test_get_instance_image_info(self, get_boot_option_mock):
        properties = {'properties': {u'kernel_id': u'instance_kernel_uuid',
                      u'ramdisk_id': u'instance_ramdisk_uuid'}}
        print(properties)
        self.context.auth_token = 'fake'
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            get_boot_option_mock.return_value = 'local'
            image_info = http_utils.get_instance_image_info(task)
            self.assertEqual({}, image_info)

    def test_get_instance_image_info(self):
        self._test_get_instance_image_info()

    def test_get_instance_image_info_without_is_whole_disk_image(self):
        # Tests when 'is_whole_disk_image' doesn't exists in
        # driver_internal_info
        del self.node.driver_internal_info['is_whole_disk_image']
        self.node.save()
        self._test_get_instance_image_info()

    @mock.patch('ironic.drivers.modules.deploy_utils.get_boot_option',
                return_value='local')
    def test_get_instance_image_info_localboot(self, boot_opt_mock):
        self.node.driver_internal_info['is_whole_disk_image'] = False
        self.node.save()
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            image_info = http_utils.get_instance_image_info(task)
            self.assertEqual({}, image_info)
            boot_opt_mock.assert_called_once_with(task.node)

    @mock.patch.object(image_service.GlanceImageService, 'show', autospec=True)
    def test_get_instance_image_info_whole_disk_image(self, show_mock):
        properties = {'properties': None}
        show_mock.return_value = properties
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.node.driver_internal_info['is_whole_disk_image'] = True
            image_info = http_utils.get_instance_image_info(task)
        self.assertEqual({}, image_info)

    @mock.patch('ironic.common.utils.render_template', autospec=True)
    def _test_build_http_config_options_pxe(self, render_mock,
                                            whle_dsk_img=False,
                                            debug=False, mode='deploy'):
        self.config(debug=debug)
        self.config(kernel_append_params='test_param', group='pxe')
        driver_internal_info = self.node.driver_internal_info
        driver_internal_info['is_whole_disk_image'] = whle_dsk_img
        self.node.driver_internal_info = driver_internal_info
        self.node.save()

        http_server = os.path.join(CONF.deploy.http_root, self.node.uuid)

        kernel_label = '%s_kernel' % mode
        ramdisk_label = '%s_ramdisk' % mode

        pxe_kernel = os.path.join(self.node.uuid, kernel_label)
        pxe_ramdisk = os.path.join(self.node.uuid, ramdisk_label)
        kernel = os.path.join(self.node.uuid, 'kernel')
        ramdisk = os.path.join(self.node.uuid, 'ramdisk')
        root_dir = CONF.deploy.http_root

        image_info = {
            kernel_label: (kernel_label,
                           os.path.join(root_dir, self.node.uuid,
                                        kernel_label)),
            ramdisk_label: (ramdisk_label,
                            os.path.join(root_dir, self.node.uuid,
                                         ramdisk_label))
        }

        if (whle_dsk_img or (
                deploy_utils.get_boot_option(self.node) == 'local')):
                ramdisk = 'no_ramdisk'
                kernel = 'no_kernel'
        else:
            image_info.update({
                'kernel': ('kernel_id',
                           os.path.join(root_dir,
                                        self.node.uuid,
                                        'kernel')),
                'ramdisk': ('ramdisk_id',
                            os.path.join(root_dir,
                                         self.node.uuid,
                                         'ramdisk'))
            })

        expected_pxe_params = 'test_param'
        if debug:
            expected_pxe_params += ' ipa-debug=1'

        expected_options = {
            'deployment_ari_path': pxe_ramdisk,
            'kernel_append_params': expected_pxe_params,
            'deployment_aki_path': pxe_kernel,
            'http_server': http_server,
            'ipxe_timeout': 0,
            'ari_path': ramdisk,
            'aki_path': kernel,
        }

        if mode == 'rescue':
            self.node.provision_state = states.RESCUING
            self.node.save()

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            options = http_utils.build_http_config_options(task, image_info)
        self.assertEqual(expected_options, options)

    def test_build_http_config_options_pxe(self):
        self._test_build_http_config_options_pxe(whle_dsk_img=True)

    def test_build_http_config_options_pxe_local_boot(self):
        del self.node.driver_internal_info['is_whole_disk_image']
        i_info = self.node.instance_info
        i_info.update({'capabilities': {'boot_option': 'local'}})
        self.node.instance_info = i_info
        self.node.save()
        self._test_build_http_config_options_pxe(whle_dsk_img=False)

    def test_build_http_config_options_pxe_without_is_whole_disk_image(self):
        del self.node.driver_internal_info['is_whole_disk_image']
        self.node.save()
        self._test_build_http_config_options_pxe(whle_dsk_img=False)

    def test_build_http_config_options_pxe_no_kernel_no_ramdisk(self):
        del self.node.driver_internal_info['is_whole_disk_image']
        self.node.save()
        pxe_params = 'my-pxe-append-params ipa-debug=0'
        self.config(group='pxe', kernel_append_params=pxe_params)
        self.config(group='deploy', http_root='/http-path/')
        image_info = {
            'deploy_kernel': ('deploy_kernel',
                              os.path.join(CONF.deploy.http_root,
                                           'path-to-deploy_kernel')),
            'deploy_ramdisk': ('deploy_ramdisk',
                               os.path.join(CONF.deploy.http_root,
                                            'path-to-deploy_ramdisk'))}

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            options = http_utils.build_http_config_options(task, image_info)

        expected_options = {
            'aki_path': 'no_kernel',
            'ari_path': 'no_ramdisk',
            'deployment_aki_path': 'path-to-deploy_kernel',
            'deployment_ari_path': 'path-to-deploy_ramdisk',
            'kernel_append_params': pxe_params,
            'http_server': '/http-path//1be26c0b-03f2-4d2e-ae87-c02d7f33c123',
            'ipxe_timeout': 0}
        self.assertEqual(expected_options, options)

    @mock.patch.object(deploy_utils, 'fetch_images', autospec=True)
    def test__cache_tftp_images_master_path(self, mock_fetch_image):
        temp_dir = tempfile.mkdtemp()
        self.config(http_root=temp_dir, group='deploy')
        self.config(tftp_master_path=os.path.join(temp_dir,
                                                  'tftp_master_path'),
                    group='pxe')
        image_path = os.path.join(temp_dir, self.node.uuid,
                                  'deploy_kernel')
        image_info = {'deploy_kernel': ('deploy_kernel', image_path)}
        fileutils.ensure_tree(CONF.pxe.tftp_master_path)
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            http_utils.cache_ramdisk_kernel(task, image_info)

        mock_fetch_image.assert_called_once_with(self.context,
                                                 mock.ANY,
                                                 [('deploy_kernel',
                                                   image_path)],
                                                 True)

    @mock.patch.object(http_utils, 'TFTPImageCache', lambda: None)
    @mock.patch.object(fileutils, 'ensure_tree', autospec=True)
    @mock.patch.object(deploy_utils, 'fetch_images', autospec=True)
    def test_cache_ramdisk_kernel(self, mock_fetch_image, mock_ensure_tree):
        fake_pxe_info = {'foo': 'bar'}
        expected_path = os.path.join(CONF.deploy.http_root, self.node.uuid)
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            http_utils.cache_ramdisk_kernel(task, fake_pxe_info)
        mock_ensure_tree.assert_called_with(expected_path)
        mock_fetch_image.assert_called_once_with(
            self.context, mock.ANY, list(fake_pxe_info.values()), True)

    @mock.patch.object(http_utils, 'is_http_boot_requested',
                       spec_set=True, autospec=True)
    def test_is_is_http_boot_requested(self, is_http_boot_requested):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_http_boot'] = 'True'
            http_utils.is_http_boot_requested(task.node)
            is_http_boot_requested.assert_called_once_with(task.node)

    @mock.patch.object(http_utils, 'is_http_boot_requested',
                       spec_set=True, autospec=True)
    def test_is_directed_lanboot_requested_none(
            self, is_http_boot_requested):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_http_boot'] = None
            http_utils.is_http_boot_requested(task.node)
            is_http_boot_requested.assert_called_once_with(task.node)

    @mock.patch.object(http_utils, 'is_http_boot_requested',
                       spec_set=True, autospec=True)
    def test_is_directed_lanboot_requested_false(
            self, is_http_boot_requested):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.driver_info['enable_http_boot'] = 'False'
            http_utils.is_http_boot_requested(task.node)
            is_http_boot_requested.assert_called_once_with(task.node)


@mock.patch.object(ironic_utils, 'unlink_without_raise', autospec=True)
@mock.patch.object(http_utils, 'clean_up_http_config', autospec=True)
@mock.patch.object(http_utils, 'TFTPImageCache', autospec=True)
class CleanUpHTTPEnvTestCase(db_base.DbTestCase):
    def setUp(self):
        super(CleanUpHTTPEnvTestCase, self).setUp()
        instance_info = INST_INFO_DICT
        instance_info['deploy_key'] = 'fake-56789'
        self.node = object_utils.create_test_node(
            self.context, boot_interface='pxe',
            instance_info=instance_info,
            driver_info=DRV_INFO_DICT,
            driver_internal_info=DRV_INTERNAL_INFO_DICT,
        )

    def test__clean_up_http_env(self, mock_cache, mock_http_clean,
                                mock_unlink):
        image_info = {'label': ['', 'deploy_kernel']}
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            http_utils.clean_up_http_env(task, image_info)
            mock_http_clean.assert_called_once_with(task)
            mock_unlink.assert_any_call('deploy_kernel')
        mock_cache.return_value.clean_up.assert_called_once_with()


class TFTPImageCacheTestCase(db_base.DbTestCase):
    @mock.patch.object(fileutils, 'ensure_tree')
    def test_with_master_path(self, mock_ensure_tree):
        self.config(tftp_master_path='/fake/path', group='pxe')
        self.config(image_cache_size=500, group='pxe')
        self.config(image_cache_ttl=30, group='pxe')

        cache = http_utils.TFTPImageCache()

        mock_ensure_tree.assert_called_once_with('/fake/path')
        self.assertEqual(500 * 1024 * 1024, cache._cache_size)
        self.assertEqual(30 * 60, cache._cache_ttl)

    @mock.patch.object(fileutils, 'ensure_tree')
    def test_without_master_path(self, mock_ensure_tree):
        self.config(tftp_master_path='', group='pxe')
        self.config(image_cache_size=500, group='pxe')
        self.config(image_cache_ttl=30, group='pxe')

        cache = http_utils.TFTPImageCache()

        mock_ensure_tree.assert_not_called()
        self.assertEqual(500 * 1024 * 1024, cache._cache_size)
        self.assertEqual(30 * 60, cache._cache_ttl)
