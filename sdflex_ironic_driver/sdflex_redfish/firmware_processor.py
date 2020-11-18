# Copyright 2016 Hewlett Packard Enterprise Development Company LP
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

import os
import types
from urllib import parse as urlparse

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import fileutils
from oslo_utils import importutils

from ironic_lib import utils as ironic_utils

from ironic.common import exception
from ironic.common.i18n import _
from ironic.common import image_service

# Mandatory fields to be provided as part of firmware image update
# with manual clean step
FIRMWARE_IMAGE_INFO_FIELDS = {'url', 'checksum'}

CONF = cfg.CONF

LOG = logging.getLogger(__name__)

sdflexutils_error = importutils.try_import('sdflexutils.exception')
sdflexutils_utils = importutils.try_import('sdflexutils.utils')


def remove_image_from_web_server(object_name):
    """Removes the given image from the configured web server.

    This method removes the given image from the http_root location,
    if the image exists.

    :param object_name: The name of the image file which needs to be removed
                        from the web server root.
    """
    image_path = os.path.join(CONF.deploy.http_root, object_name)
    ironic_utils.unlink_without_raise(image_path)


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
                                                          algorithm='md5')
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


def get_and_validate_firmware_image_info(firmware_image_info,
                                         firmware_update_mode):
    """Validates the firmware image info and returns the retrieved values.

    :param firmware_image_info: dict object containing the firmware image info
    :raises: MissingParameterValue, for missing fields (or values) in
             image info.
    :raises: InvalidParameterValue, for unsupported firmware component
    :returns: tuple of firmware url, checksum, component when the firmware
        update is ilo based.
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


class FirmwareProcessor(object):
    """Firmware file processor

    This class helps in downloading the firmware file from url, extracting
    the firmware file (if its in compact format) and makes it ready for
    firmware update operation. In future, methods can be added as and when
    required to extend functionality for different firmware file types.
    """
    def __init__(self, url):
        # :attribute ``self.parsed_url``: structure returned by urlparse
        self._fine_tune_fw_processor(url)

    def _fine_tune_fw_processor(self, url):
        """Fine tunes the firmware processor object based on specified url

        :param url: url of firmware file
        :raises: InvalidParameterValue, for unsupported firmware url
        """
        parsed_url = urlparse.urlparse(url)
        self.parsed_url = parsed_url

        url_scheme = parsed_url.scheme
        if url_scheme in ('http', 'https'):
            self._download_fw_to = types.MethodType(
                _download_http_based_fw_to, self)
        else:
            raise exception.InvalidParameterValue(
                _('This method does not support URL scheme %(url_scheme)s. '
                  'Invalid URL %(url)s. The supported firmware URL schemes '
                  'are "http" and "https"') %
                {'url': url, 'url_scheme': url_scheme})


def _download_http_based_fw_to(self, target_file):
    """HTTP based firmware file downloader

    It downloads the file (url) to temporary location (file location).
    Original firmware file location (url) is expected in the format
    "http://.."
    :param target_file: destination file for downloading the original firmware
                        file.
    :raises: ImageDownloadFailed, on failure to download the original file.
    """
    src_file = self.parsed_url.geturl()
    with open(target_file, 'wb') as fd:
        image_service.HttpImageService().download(src_file, fd)


class FirmwareImageLocation(object):
    """Firmware image location class

    This class acts as a wrapper class for the firmware image location.
    It primarily helps in removing the firmware files from their respective
    locations, made available for firmware update operation.
    """

    def __init__(self, fw_image_location, fw_image_filename):
        """Keeps hold of image location and image filename"""
        self.fw_image_location = fw_image_location
        self.fw_image_filename = fw_image_filename

    def remove(self):
        """Exposed method to remove the wrapped firmware file

        This method gets overridden by the remove method for the respective
        type of firmware file location it wraps.
        """
        pass


def _remove_webserver_based_me(self):
    """Removes webserver based firmware image location (by its file name)"""
    remove_image_from_web_server(self.fw_image_filename)
