# Copyright 2017 Red Hat, Inc.
# All Rights Reserved.
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
# Hewlett Packard Enterprise made changes in this file.

from oslo_log import log as logging
from oslo_utils import importutils

from ironic.common import exception as ironic_exception
from ironic.drivers.modules.redfish import management as redfish_management

LOG = logging.getLogger(__name__)

sushy = importutils.try_import('sushy')


if sushy:
    redfish_management.BOOT_DEVICE_MAP.update(
        {sushy.BOOT_SOURCE_TARGET_UEFI_HTTP: 'uefi http'})

    redfish_management.BOOT_DEVICE_MAP_REV = {
        v: k for k, v in redfish_management.BOOT_DEVICE_MAP.items()}


class SdflexRedfishManagement(redfish_management.RedfishManagement):

    def __init__(self):
        """Initialize the Redfish management interface.

        :raises: DriverLoadError if the driver can't be loaded due to
            missing dependencies
        """
        super(SdflexRedfishManagement, self).__init__()
        if not sushy:
            raise ironic_exception.DriverLoadError(
                driver='sdfelx-redfish',
                reason=_('Unable to import the sushy library'))
