# Copyright 2017 Red Hat, Inc.
# Copyright 2019 Hewlett Packard Enterprise Development LP
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

from oslo_utils import importutils

from ironic.common import exception as ironic_exception
from ironic.drivers.modules import redfish

sushy = importutils.try_import('sushy')


class SdflexRedfishPower(redfish.power.RedfishPower):

    def __init__(self):
        """Initialize the Redfish power interface.

        :raises: DriverLoadError if the driver can't be loaded due to
            missing dependencies
        """
        super(SdflexRedfishPower, self).__init__()
        if not sushy:
            raise ironic_exception.DriverLoadError(
                driver='sdflex-redfish',
                reason=_('Unable to import the sushy library'))
