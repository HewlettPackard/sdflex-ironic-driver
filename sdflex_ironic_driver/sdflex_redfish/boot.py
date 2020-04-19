# Copyright 2015 Hewlett-Packard Development Company, L.P.
# Copyright 2019 Hewlett Packard Enterprise Development LP
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
Boot Interface for SDFlex driver and its supporting methods.
"""

from ironic_lib import metrics_utils
from oslo_config import cfg
from oslo_log import log as logging

from ironic.common import exception as ironic_exception
from ironic.common.i18n import _
from ironic.common import states
from ironic.conductor import utils as manager_utils
from ironic.drivers.modules import pxe

from sdflex_ironic_driver import exception
from sdflex_ironic_driver.sdflex_redfish import common as sdflex_common

LOG = logging.getLogger(__name__)

METRICS = metrics_utils.get_metrics_logger(__name__)

CONF = cfg.CONF

# COMMON_PROPERTIES = REQUIRED_PROPERTIES


def _disable_secure_boot(task):
    """Disables secure boot on node, if secure boot is enabled on node.

    This method checks if secure boot is enabled on node. If enabled, it
    disables same and returns True.

    :param task: a TaskManager instance containing the node to act on.
    :returns: It returns True, if secure boot was successfully disabled on
              the node.
              It returns False, if secure boot on node is in disabled state
              or if secure boot feature is not supported by the node.
    :raises: SDFlexOperationError, if some operation on SDFlex failed.
    """
    cur_sec_state = False
    try:
        cur_sec_state = sdflex_common.get_secure_boot_mode(task)
    except exception.SDFlexOperationNotSupported:
        LOG.debug('Secure boot mode is not supported for node %s',
                  task.node.uuid)
    else:
        if cur_sec_state:
            LOG.debug('Disabling secure boot for node %s', task.node.uuid)
            sdflex_common.set_secure_boot_mode(task, False)


def is_directed_lanboot_requested(node):
    """Checks if directed lanboot is requested

    """
    directed_lanboot_requested = (
        node.driver_info.get('enable_directed_lanboot', 'false').lower())
    return directed_lanboot_requested == 'true'


def prepare_node_for_deploy(task):
    """Preparatory steps for sdflex-redfish driver.

    This method performs preparatory steps required for sdflex-redfish driver.
    1. Power off node
    2. Disables secure boot, if it is in enabled state.
    3. Enables Directed Lanboot, if requested.

    :param task: a TaskManager instance containing the node to act on.
    :raises: SDFlexOperationError, if some operation on SDFlex failed.
    """
    manager_utils.node_power_action(task, states.POWER_OFF)

    # Disable secure boot on the node if it is in enabled state.
    _disable_secure_boot(task)

    node = task.node
    if is_directed_lanboot_requested(node):
        sdflex_common.enable_directed_lan_boot(node)


def disable_secure_boot_if_supported(task):
    """Disables secure boot on node, does not throw if its not supported.

    :param task: a TaskManager instance containing the node to act on.
    :raises: SDFlexOperationError, if some operation on SDFlex failed.
    """
    try:
        sdflex_common.update_secure_boot_mode(task, False)
    # We need to handle SDFlexOperationNotSupported exception so that if
    # the user has incorrectly specified the Node capability
    # 'secure_boot' to a node that does not have that capability and
    # attempted deploy. Handling this exception here, will help the
    # user to tear down such a Node.
    except exception.SDFlexOperationNotSupported:
        LOG.warning('Secure boot mode is not supported for node %s',
                    task.node.uuid)


class SdflexPXEBoot(pxe.PXEBoot):

    @METRICS.timer('SdflexPXEBoot.prepare_ramdisk')
    def prepare_ramdisk(self, task, ramdisk_params):
        """Prepares the boot of Ironic ramdisk using PXE.

        This method prepares the boot of the deploy or rescue ramdisk after
        reading relevant information from the node's driver_info and
        instance_info.

        :param task: a task from TaskManager.
        :param ramdisk_params: the parameters to be passed to the ramdisk.
        :returns: None
        :raises: MissingParameterValue, if some information is missing in
            node's driver_info or instance_info.
        :raises: InvalidParameterValue, if some information provided is
            invalid.
        :raises: SDFlexOperationError, if some operation on SDFlex failed.
        """

        if task.node.provision_state in (states.DEPLOYING, states.RESCUING,
                                         states.CLEANING):
            prepare_node_for_deploy(task)

        super(SdflexPXEBoot, self).prepare_ramdisk(task, ramdisk_params)

    @METRICS.timer('SdflexPXEBoot.prepare_instance')
    def prepare_instance(self, task):
        """Prepares the boot of instance.

        This method prepares the boot of the instance after reading
        relevant information from the node's instance_info. In case of netboot,
        it updates the dhcp entries and switches the PXE config. In case of
        localboot, it cleans up the PXE config.
        In case of 'boot from volume', it updates the iSCSI info onto SDFlex
        and sets the node to boot from 'UefiTarget' boot device.

        :param task: a task from TaskManager.
        :returns: None
        :raises: SDFlexOperationError, if some operation on SDFlex failed.
        """

        # Need to enable secure boot, if being requested.
        # update_secure_boot_mode checks and enables secure boot only if the
        # deploy has requested secure boot
        sdflex_common.update_secure_boot_mode(task, True)

        super(SdflexPXEBoot, self).prepare_instance(task)

    @METRICS.timer('SdflexPXEBoot.clean_up_instance')
    def clean_up_instance(self, task):
        """Cleans up the boot of instance.

        This method cleans up the PXE environment that was setup for booting
        the instance. It unlinks the instance kernel/ramdisk in the node's
        directory in tftproot and removes it's PXE config.
        In case of UEFI iSCSI booting, it cleans up iSCSI target information
        from the node.

        :param task: a task from TaskManager.
        :returns: None
        :raises: SDFlexOperationError, if some operation on SDFlex failed.
        """
        manager_utils.node_power_action(task, states.POWER_OFF)
        disable_secure_boot_if_supported(task)

        node = task.node
        if is_directed_lanboot_requested(node):
            sdflex_common.disable_directed_lan_boot(node)

        # PXE boot interface
        super(SdflexPXEBoot, self).clean_up_instance(task)

    @METRICS.timer('SdflexPXEBoot.validate')
    def validate(self, task):
        """Validate the deployment information for the task's node.

        :param task: a TaskManager instance containing the node to act on.
        :raises: InvalidParameterValue, if some information is invalid.
        :raises: MissingParameterValue if some mandatory information
        is missing on the node
        """
        node = task.node
        sdflex_common.parse_driver_info(node)
        if is_directed_lanboot_requested(node):
            directed_lan_data = node.driver_info.get('directed_lan_data')
            if directed_lan_data is None:
                raise ironic_exception.MissingParameterValue(_(
                    "Missing URLBootFile or UrlBootFile2 as keys in "
                    "driver_info['directed_lan_data']"))
            url_data1 = directed_lan_data.get('UrlBootFile', False)
            url_data2 = directed_lan_data.get('UrlBootFile2', False)
            if url_data1:
                if not url_data1.startswith('tftp://'):
                    raise ironic_exception.InvalidParameterValue(_(
                        "Directed Lan boot accepts only tftp url's as "
                        "values for UrlBootFile in"
                        "driver_info['directed_lan_data']"))
            elif url_data2:
                if not url_data2.startswith('tftp://'):
                    raise ironic_exception.InvalidParameterValue(_(
                        "Directed Lan boot accepts only tftp url's as "
                        "values for UrlBootFile2 in"
                        "driver_info['directed_lan_data']"))
            else:
                raise ironic_exception.MissingParameterValue(_(
                    "Missing URLBootFile or UrlBootFile2 as keys in "
                    "driver_info['directed_lan_data']"))
