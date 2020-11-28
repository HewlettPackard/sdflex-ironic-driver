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

from ironic.common import exception
from ironic.tests import base

from sdflex_ironic_driver.sdflex_redfish import firmware_processor \
    as fw_processor


class FirmwareProcessorTestCase(base.TestCase):

    def setUp(self):
        super(FirmwareProcessorTestCase, self).setUp()
        self.any_url = 'http://netloc/path'

    def test_validate_firmware_image_info(self):
        # | GIVEN |
        firmware_image_info = {
            'url': self.any_url,
            'checksum': 'b64c8f7799cfbb553d384d34dc43fafe336cc889',
        }
        # | WHEN |
        fw_processor.validate_firmware_image_info(firmware_image_info)

    def test_validate_firmware_image_info_fails_for_missing_parameter(
            self):
        # | GIVEN |
        invalid_firmware_image_info = {
            'url': self.any_url,
        }
        # | WHEN | & | THEN |
        self.assertRaisesRegex(
            exception.MissingParameterValue, 'checksum',
            fw_processor.validate_firmware_image_info,
            invalid_firmware_image_info)
