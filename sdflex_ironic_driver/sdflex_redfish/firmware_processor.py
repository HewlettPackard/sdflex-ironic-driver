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

from ironic.common import exception
from ironic.common.i18n import _

# Mandatory fields to be provided as part of firmware image update
# with manual clean step
FIRMWARE_IMAGE_INFO_FIELDS = {'url', 'checksum'}

CONF = cfg.CONF

LOG = logging.getLogger(__name__)


def validate_firmware_image_info(firmware_image_info):
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
