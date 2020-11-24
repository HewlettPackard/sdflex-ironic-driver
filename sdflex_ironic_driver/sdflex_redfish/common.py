# Copyright 2014 Hewlett-Packard Development Company, L.P.
# Copyright 2019-2021 Hewlett Packard Enterprise Development LP
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
#
# Hewlett Packard Enterprise made changes in this file.

"""
Common functionalities shared between different SDFlex modules.
"""

from oslo_log import log as logging
from oslo_utils import importutils

from ironic.common import exception as ironic_exception
from ironic.common.i18n import _
from ironic.drivers.modules import deploy_utils

from sdflex_ironic_driver import exception

sdflex_client = importutils.try_import('sdflexutils.client')
sdflex_error = importutils.try_import('sdflexutils.exception')

LOG = logging.getLogger(__name__)

REQUIRED_PROPERTIES = {
    'redfish_address': _("IP address or hostname of the SDFlex. Required."),
    'redfish_system_id': _("IP address or hostname of the SDFlex. Required."),
    'redfish_username': _("username for the redfish with administrator"
                          "privileges. Required."),
    'redfish_password': _("password for redfish_username. Required.")
}

COMMON_PROPERTIES = REQUIRED_PROPERTIES.copy()


def get_sdflex_object(node):
    """Gets SDFlexClient object from sdflexutils library.

    Given an ironic node object, this method gives back a SDFlexClient object
    to do operations on the SDFlex.

    :param node: an ironic node object.
    :returns: an SDFlexClient object.
    :raises: InvalidParameterValue on invalid inputs.
    :raises: MissingParameterValue if some mandatory information
        is missing on the node
    """
    driver_info = parse_driver_info(node)
    sdflex_object = sdflex_client.SDFlexClient(
        driver_info['redfish_address'], driver_info['redfish_username'],
        driver_info['redfish_password'], driver_info['redfish_system_id'])
    return sdflex_object


def parse_driver_info(node):
    """Gets the driver specific Node info.

    This method validates whether the 'driver_info' property of the
    supplied node contains the required information for this driver.

    :param node: an ironic Node object.
    :returns: a dict containing information from driver_info (or where
        applicable, config values).
    :raises: InvalidParameterValue if any parameters are incorrect
    :raises: MissingParameterValue if some mandatory information
        is missing on the node
    """
    info = node.driver_info
    d_info = {}

    missing_info = []
    for param in REQUIRED_PROPERTIES:
        try:
            d_info[param] = info[param]
        except KeyError:
            missing_info.append(param)
    if missing_info:
        raise ironic_exception.MissingParameterValue(_(
            "The following required Sdflex parameters are missing from the "
            "node's driver_info: %s") % missing_info)

    return d_info


def get_secure_boot_mode(task):
    """Retrieves current enabled state of UEFI secure boot on the node

    Returns the current enabled state of UEFI secure boot on the node.

    :param task: a task from TaskManager.
    :raises: MissingParameterValue if a required SDFlex parameter is missing.
    :raises: SDFlexOperationError on an error from SdflexClient library.
    :raises: SDFlexOperationNotSupported if UEFI secure boot is not supported.
    :returns: Boolean value indicating current state of UEFI secure boot
              on the node.
    """

    operation = _("Get secure boot mode for node %s.") % task.node.uuid
    secure_boot_state = False
    sdflex_object = get_sdflex_object(task.node)

    try:
        secure_boot_state = sdflex_object.get_secure_boot_mode()

    except sdflex_error.SDFlexCommandNotSupportedError as sdflex_exception:
        raise exception.SDFlexOperationNotSupported(operation=operation,
                                                    error=sdflex_exception)

    LOG.debug("Get secure boot mode for node %(node)s returned %(value)s",
              {'value': secure_boot_state, 'node': task.node.uuid})
    return secure_boot_state


def set_secure_boot_mode(task, flag):
    """Enable or disable UEFI Secure Boot for the next boot

    Enable or disable UEFI Secure Boot for the next boot

    :param task: a task from TaskManager.
    :param flag: Boolean value. True if the secure boot to be
                       enabled in next boot.
    :raises: SDFlexOperationError on an error from SdflexClient library.
    :raises: SDFlexOperationNotSupported if UEFI secure boot is not supported.
    """

    operation = (_("Setting secure boot to %(flag)s for node %(node)s.") %
                 {'flag': flag, 'node': task.node.uuid})
    sdflex_object = get_sdflex_object(task.node)

    try:
        sdflex_object.set_secure_boot_mode(flag)
        LOG.debug(operation)

    except sdflex_error.SDFlexCommandNotSupportedError as sdflex_exception:
        raise exception.SDFlexOperationNotSupported(operation=operation,
                                                    error=sdflex_exception)

    except sdflex_error.SDFlexError as sdflex_exception:
        raise exception.SDFlexOperationError(operation=operation,
                                             error=sdflex_exception)


def update_secure_boot_mode(task, mode):
    """Changes secure boot mode for next boot on the node.

    This method changes secure boot mode on the node for next boot. It changes
    the secure boot mode setting on node only if the deploy has requested for
    the secure boot.
    During deploy, this method is used to enable secure boot on the node by
    passing 'mode' as 'True'.
    During teardown, this method is used to disable secure boot on the node by
    passing 'mode' as 'False'.

    :param task: a TaskManager instance containing the node to act on.
    :param mode: Boolean value requesting the next state for secure boot
    :raises: SDFlexOperationNotSupported, if operation is not supported
             on  SDFlex
    :raises: SDFlexOperationError, if some operation on SDFlex failed.
    """
    if deploy_utils.is_secure_boot_requested(task.node):
        set_secure_boot_mode(task, mode)
        LOG.info('Changed secure boot to %(mode)s for node %(node)s',
                 {'mode': mode, 'node': task.node.uuid})


def enable_directed_lan_boot(node):
    """Enable Directed Lan boot.

    Set 'UrlBootFile,UrlBootFile2' in the bios setting to enable Directed Lan
    boot.
    """
    operation = (_("Setting bios setting for enabling Directed Lan boot"
                   "for node %(node)s.") % {'node': node.uuid})
    boot_file_path = node.driver_info['boot_file_path']
    sdflex_object = get_sdflex_object(node)
    try:
        sdflex_object.set_bios_settings(boot_file_path)
        LOG.debug(operation)

    except sdflex_error.SDFlexError as sdflex_exception:
        raise exception.SDFlexOperationError(operation=operation,
                                             error=sdflex_exception)


def set_network_setting_dhcpless_boot(node, url):
    """Set HTTP URI for DHCP Less Boot and Static Ip address

    """
    operation = (_("Setting bios setting for enabling DHCPLESS Boot"
                   "for node %(node)s.") % {'node': node.uuid})

    sdflex_object = get_sdflex_object(node)

    network_data = node.network_data.get('networks')[0]

    ipv4_address = network_data.get('ip_address')

    routes = network_data.get('routes')[0]

    ipv4_gateway = routes.get('gateway')

    ipv4_subnet_mask = routes.get('netmask')

    bios_setting = {'UrlBootFile': url, 'Ipv4Address': ipv4_address,
                    'Ipv4Gateway': ipv4_gateway,
                    'Ipv4SubnetMask': ipv4_subnet_mask, 'Dhcpv4': 'Disabled'}
    try:
        sdflex_object.set_bios_settings(bios_setting)
        LOG.debug(operation)
    except sdflex_error.SDFlexError as sdflex_exception:
        raise exception.SDFlexOperationError(operation=operation,
                                             error=sdflex_exception)


def reset_network_setting_dhcpless_boot(node):
    """Disable DHCPLESS Boot

    Unset the 'IPV4Address, Ipv4Gateway, Ipv4SubnetMask,  UrlBootFile'
    in the bios setting to disable DHCPLESS boot.
    """
    operation = (_("Setting 'IPV4Address, Ipv4Gateway, Ipv4SubnetMask,"
                   " UrlBootFile' as '', in the bios setting for disabling"
                   " DHCPLESS boot for node"
                   "%(node)s.") % {'node': node.uuid})
    bios_setting = {'UrlBootFile': '', 'Ipv4Address': '',
                    'Ipv4Gateway': '', 'Ipv4SubnetMask': '',
                    'Dhcpv4': 'Enabled'}
    sdflex_object = get_sdflex_object(node)
    try:
        sdflex_object.set_bios_settings(bios_setting)
        LOG.debug(operation)
    except sdflex_error.SDFlexError as sdflex_exception:
        raise exception.SDFlexOperationError(operation=operation,
                                             error=sdflex_exception)


def reset_bios_settings(node):
    """Disable Directed LAN Boot or UEFI HTTP Boot.

    Unset the 'UrlBootFile,UrlBootFile2' in the bios setting to disable
    Directed Lan boot.
    """

    operation = (_("Setting 'UrlBootFile' and 'UrlBootFile2' as '', in the"
                   "bios setting for disabling Directed Lan boot for node"
                   "%(node)s.") % {'node': node.uuid})
    boot_file_path = {'UrlBootFile': '', 'UrlBootFile2': ''}
    sdflex_object = get_sdflex_object(node)

    try:
        sdflex_object.set_bios_settings(boot_file_path)
        LOG.debug(operation)

    except sdflex_error.SDFlexError as sdflex_exception:
        raise exception.SDFlexOperationError(operation=operation,
                                             error=sdflex_exception)


def enable_uefi_http_boot(node):
    """Enable UEFI HTTP boot.

    Set 'HTTPBootURI' or 'UrlBootFile,UrlBootFile2' in the bios setting to
    enable UEFI HTTP Boot.
    """
    operation = (_("Setting bios setting for enabling UEFI HTTP boot"
                   "for node %(node)s.") % {'node': node.uuid})
    boot_file_path = node.driver_info.get('boot_file_path', False)
    http_boot_uri = node.driver_info.get('http_boot_uri', False)
    sdflex_object = get_sdflex_object(node)
    try:
        if http_boot_uri:
            sdflex_object.set_http_boot_uri(http_boot_uri)
        elif boot_file_path:
            sdflex_object.set_bios_settings(boot_file_path)
        else:
            raise exception.SDFlexOperationError(
                operation=operation, error='boot_file_path or http_boot_uri '
                'is not present in the driver info of the node %(node)s.'
                % {'node': node.uuid})
        LOG.debug(operation)
    except sdflex_error.SDFlexError as sdflex_exception:
        raise exception.SDFlexOperationError(operation=operation,
                                             error=sdflex_exception)


def eject_vmedia(task, device):
    """Eject the Vmedia.

    device: Ejects this device
    """

    sdflex_object = get_sdflex_object(task.node)
    sdflex_object.eject_vmedia(device)


def insert_vmedia(task, url, device, remote_server_data):
    """Insert's the Vmedia.

    url: URL of the iso which has to be inserted
    device: Insert the URL to this device
    """
    sdflex_object = get_sdflex_object(task.node)
    sdflex_object.insert_vmedia(url, device, remote_server_data)
