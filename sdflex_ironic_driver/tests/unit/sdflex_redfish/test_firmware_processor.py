# Copyright 2016-2020 Hewlett Packard Enterprise Development Company LP
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

"""Test class for Firmware Processor used by iLO management interface."""

import builtins
import io
from urllib import parse as urlparse

import mock
from oslo_utils import importutils

from ironic.common import exception
from sdflex_ironic_driver.sdflex_redfish import firmware_processor \
    as fw_processor
from ironic.tests import base


class FirmwareProcessorTestCase(base.TestCase):

    def setUp(self):
        super(FirmwareProcessorTestCase, self).setUp()
        self.any_url = 'http://netloc/path'


    def test_get_and_validate_firmware_image_info(self):
        # | GIVEN |
        firmware_image_info = {
            'url': self.any_url,
            'checksum': 'b64c8f7799cfbb553d384d34dc43fafe336cc889',
        }
        # | WHEN |
        url, checksum = (
            fw_processor.get_and_validate_firmware_image_info(
            firmware_image_info))
        # | THEN |
        self.assertEqual(self.any_url, url)
        self.assertEqual('b64c8f7799cfbb553d384d34dc43fafe336cc889', checksum)

    def test_get_and_validate_firmware_image_info_fails_for_missing_parameter(
            self):
        # | GIVEN |
        invalid_firmware_image_info = {
            'url': self.any_url,
        }
        # | WHEN | & | THEN |
        self.assertRaisesRegex(
            exception.MissingParameterValue, 'checksum',
            fw_processor.get_and_validate_firmware_image_info,
            invalid_firmware_image_info)

    @mock.patch.object(builtins, 'open', autospec=True)
    def test_verify_image_checksum(self, open_mock):
        # | GIVEN |
        data = b'Yankee Doodle went to town riding on a pony;'
        file_like_object = io.BytesIO(data)
        open_mock().__enter__.return_value = file_like_object
        actual_hash = hashlib.md5(data).hexdigest()
        # | WHEN |
        fw_processor.verify_image_checksum(file_like_object, actual_hash)
        # | THEN |
        # no any exception thrown

    def test_verify_image_checksum_throws_for_nonexistent_file(self):
        # | GIVEN |
        invalid_file_path = '/some/invalid/file/path'
        # | WHEN | & | THEN |
        self.assertRaises(exception.ImageRefValidationFailed,
                          fw_processor.verify_image_checksum,
                          invalid_file_path, 'hash_xxx')

    @mock.patch.object(builtins, 'open', autospec=True)
    def test_verify_image_checksum_throws_for_failed_validation(self,
                                                                open_mock):
        # | GIVEN |
        data = b'Yankee Doodle went to town riding on a pony;'
        file_like_object = io.BytesIO(data)
        open_mock().__enter__.return_value = file_like_object
        invalid_hash = 'invalid_hash_value'
        # | WHEN | & | THEN |
        self.assertRaises(exception.ImageRefValidationFailed,
                          fw_processor.verify_image_checksum,
                          file_like_object,
                          invalid_hash)
