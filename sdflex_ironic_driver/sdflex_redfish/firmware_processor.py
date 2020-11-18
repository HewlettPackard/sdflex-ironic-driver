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
"""
Firmware file processor
"""

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import fileutils

from ironic.common import exception
from ironic.common.i18n import _

# Mandatory fields to be provided as part of firmware image update
# with manual clean step
FIRMWARE_IMAGE_INFO_FIELDS = {'url', 'checksum'}

CONF = cfg.CONF

LOG = logging.getLogger(__name__)


def verify_image_checksum(image_location, expected_checksum):
    """Verifies checksum (md5) of image file against the expected one.

    This method generates the checksum of the image file on the fly and
    verifies it against the expected checksum provided as argument.

    :param image_location: location of image file whose checksum is verified.
    :param expected_checksum: checksum to be checked against
    :raises: ImageRefValidationFailed, if invalid file path or
             verification fails.
    """
    try:
        actual_checksum = fileutils.compute_file_checksum(image_location,
                                                          algorithm='sha256')
    except IOError as e:
        LOG.error("Error opening file: %(file)s", {'file': image_location})
        raise exception.ImageRefValidationFailed(image_href=image_location,
                                                 reason=e)

    if actual_checksum != expected_checksum:
        msg = (_('Error verifying image checksum. Image %(image)s failed to '
                 'verify against checksum %(checksum)s. Actual checksum is: '
                 '%(actual_checksum)s') %
               {'image': image_location, 'checksum': expected_checksum,
                'actual_checksum': actual_checksum})
        LOG.error(msg)
        raise exception.ImageRefValidationFailed(image_href=image_location,
                                                 reason=msg)


def get_and_validate_firmware_image_info(firmware_image_info):
    """Validates the firmware image info and returns the retrieved values.

    :param firmware_image_info: dict object containing the firmware image info
    :raises: MissingParameterValue, for missing fields (or values) in
             image info.
    """
    image_info = firmware_image_info or {}

    LOG.debug("Validating firmware image info: %s ... in progress", image_info)
    missing_fields = []
    for field in FIRMWARE_IMAGE_INFO_FIELDS:
        if not image_info.get(field):
            missing_fields.append(field)

    if missing_fields:
        msg = (_("Firmware image info: %(image_info)s is missing the "
                 "required %(missing)s field/s.") %
               {'image_info': image_info,
                'missing': ", ".join(missing_fields)})
        LOG.error(msg)
        raise exception.MissingParameterValue(msg)
