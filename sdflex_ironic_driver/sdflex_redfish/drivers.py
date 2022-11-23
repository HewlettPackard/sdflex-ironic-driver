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

from ironic.drivers.modules import agent
from ironic.drivers.modules import pxe
from ironic.drivers import redfish

from sdflex_ironic_driver.sdflex_redfish import bios as sdflex_bios
from sdflex_ironic_driver.sdflex_redfish import boot as sdflex_boot
from sdflex_ironic_driver.sdflex_redfish import deploy as sdflex_deploy
from sdflex_ironic_driver.sdflex_redfish import management as sdflex_mgmt
from sdflex_ironic_driver.sdflex_redfish import power as sdflex_power
from sdflex_ironic_driver.sdflex_redfish import vendor as sdflex_vendor


class SdflexRedfishHardware(redfish.RedfishHardware):
    """Sdflex Redfish hardware type."""

    @property
    def supported_management_interfaces(self):
        """List of supported management interfaces."""
        return [sdflex_mgmt.SdflexRedfishManagement]

    @property
    def supported_power_interfaces(self):
        """List of supported power interfaces."""
        return [sdflex_power.SdflexRedfishPower]

    @property
    def supported_boot_interfaces(self):
        """List of supported boot interfaces."""
        return [sdflex_boot.SdflexPXEBoot,
                sdflex_boot.SdflexRedfishVirtualMediaBoot,
                sdflex_boot.SdflexRedfishDhcplessBoot]

    @property
    def supported_bios_interfaces(self):
        """List of supported Bios interfaces."""
        return [sdflex_bios.SdflexRedfishBios] + super(
            SdflexRedfishHardware, self).supported_bios_interfaces

    @property
    def supported_deploy_interfaces(self):
        """List of supported Deploy interfaces."""
        return [agent.AgentDeploy, pxe.PXEAnacondaDeploy,
                sdflex_deploy.SDFlexAgentDeploy]

    @property
    def supported_vendor_interfaces(self):
        """List of supported Deploy interfaces."""
        return [sdflex_vendor.SdflexRedfishVendorPassthru] + super(
            SdflexRedfishHardware, self).supported_vendor_interfaces
