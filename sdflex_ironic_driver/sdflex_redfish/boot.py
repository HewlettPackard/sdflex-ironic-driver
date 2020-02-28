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

from ironic.common import boot_devices
from ironic.common import exception as ironic_exception
from ironic.common.i18n import _
from ironic.common import states
from ironic.conductor import utils as manager_utils
from ironic.drivers.modules import boot_mode_utils
from ironic.drivers.modules import deploy_utils
from ironic.drivers.modules import pxe

from sdflex_ironic_driver import exception
from sdflex_ironic_driver import http_utils
from sdflex_ironic_driver.sdflex_redfish import common as sdflex_common

LOG = logging.getLogger(__name__)

boot_devices.UEFIHTTP = 'uefi http'

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
        str(node.driver_info.get('enable_directed_lanboot', 'false')).lower())
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
    if (is_directed_lanboot_requested(node) or
            http_utils.is_http_boot_requested(task.node)):
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
        if not http_utils.is_http_boot_requested(task.node):
            super(SdflexPXEBoot, self).prepare_ramdisk(task, ramdisk_params)
        else:
            node = task.node
            # Label indicating a deploy or rescue operation being carried out
            # on the node, 'deploy' or 'rescue'. Unless the node is in a
            # rescue like state, the mode is set to 'deploy', indicating
            # deploy operation is being carried out.
            mode = deploy_utils.rescue_or_deploy_mode(node)

            http_info = http_utils.get_image_info(node, mode=mode)

            # NODE: Try to validate and fetch instance images only
            # if we are in DEPLOYING state.
            if node.provision_state == states.DEPLOYING:
                http_info.update(http_utils.get_instance_image_info(task))
                boot_mode_utils.sync_boot_mode(task)

            http_options = http_utils.build_http_config_options(task,
                                                                http_info)
            http_options.update(ramdisk_params)
            http_config_template = deploy_utils.get_pxe_config_template(node)
            http_utils.create_http_config(task, http_options,
                                          http_config_template)
            manager_utils.node_set_boot_device(task, boot_devices.UEFIHTTP,
                                               persistent=False)
            if http_info:
                http_utils.cache_ramdisk_kernel(task, http_info)

    @METRICS.timer('SdflexPXEBoot.prepare_instance')
    def prepare_instance(self, task):
        """Prepares the boot of instance.

        This method prepares the boot of the instance after reading relevant
        information from the node's instance_info. In case of UEFI HTTP Boot,
        it switches to UEFI HTTP config. In case of localboot, it cleans up
        the PXE config. In case of  'boot from volume', it updates the iSCSI
        info onto SDFlex and sets the node to boot from 'UefiTarget' boot
        device.

        :param task: a task from TaskManager.
        :returns: None
        :raises: SDFlexOperationError, if some operation on SDFlex failed.
        """

        # Need to enable secure boot, if being requested.
        # update_secure_boot_mode checks and enables secure boot only if the
        # deploy has requested secure boot
        sdflex_common.update_secure_boot_mode(task, True)
        if not http_utils.is_http_boot_requested(task.node):
            super(SdflexPXEBoot, self).prepare_instance(task)
        else:
            boot_mode_utils.sync_boot_mode(task)
            node = task.node
            boot_option = deploy_utils.get_boot_option(node)
            boot_device = None
            instance_image_info = {}
            if boot_option == "ramdisk":
                instance_image_info = http_utils.get_instance_image_info(task)
                http_utils.cache_ramdisk_kernel(task, instance_image_info)
            if deploy_utils.is_iscsi_boot(task) or boot_option == "ramdisk":
                http_utils.prepare_instance_http_config(
                    task, instance_image_info,
                    iscsi_boot=deploy_utils.is_iscsi_boot(task),
                    ramdisk_boot=(boot_option == "ramdisk"))
                if http_utils.is_http_boot_requested(task.node):
                    boot_device = boot_devices.UEFIHTTP
                else:
                    boot_device = boot_devices.PXE
            elif boot_option != "local":
                if task.driver.storage.should_write_image(task):
                    # Make sure that the instance kernel/ramdisk is cached.
                    # This is for the takeover scenario for active nodes.
                    instance_image_info = (
                        http_utils.get_instance_image_info(task))
                    http_utils.cache_ramdisk_kernel(task, instance_image_info)
                iwdi = (
                    task.node.driver_internal_info.get('is_whole_disk_image'))
                try:
                    root_uuid_or_disk_id = task.node.driver_internal_info[
                        'root_uuid_or_disk_id'
                    ]
                except KeyError:
                    if not task.driver.storage.should_write_image(task):
                        pass
                    elif not iwdi:
                        LOG.warning("The UUID for the root partition can't be"
                                    " found, unable to switch the pxe config "
                                    "from deployment mode to service (boot) "
                                    "mode for node %(node)s",
                                    {"node": task.node.uuid})
                    else:
                        LOG.warning("The disk id for the whole disk image "
                                    "can't be found, unable to switch the "
                                    "pxe config from deployment mode to "
                                    "service (boot) mode for node %(node)s. "
                                    "Booting the instance from disk.",
                                    {"node": task.node.uuid})
                        http_utils.clean_up_http_config(task)
                        boot_device = boot_devices.DISK
                else:
                    http_utils.build_service_http_config(task,
                                                         instance_image_info,
                                                         root_uuid_or_disk_id)
                    if http_utils.is_http_boot_requested(task.node):
                        boot_device = boot_devices.UEFIHTTP
                    else:
                        boot_device = boot_devices.PXE
            else:
                # If it's going to boot from the local disk, we don't need
                # PXE config files. They still need to be generated as part
                # of the prepare() because the deployment does PXE boot the
                # deploy ramdisk
                http_utils.clean_up_http_config(task)
                boot_device = boot_devices.DISK

            # NOTE(pas-ha) do not re-set boot device on ACTIVE nodes
            # during takeover
            if boot_device and task.node.provision_state != states.ACTIVE:
                persistent = True
                if node.driver_info.get('force_persistent_boot_device',
                                        'Default') == 'Never':
                    persistent = False
                manager_utils.node_set_boot_device(task, boot_device,
                                                   persistent=persistent)

    @METRICS.timer('SdflexPXEBoot.clean_up_instance')
    def clean_up_instance(self, task):
        """Cleans up the boot of instance.

        This method cleans up the PXE / HTTP environment that was setup for
        booting the instance. It unlinks the instance kernel/ramdisk in the
        node's directory in tftproot / httproot and removes it's PXE config
        / HTTP config.
        In case of Directed LAN Boot / UEFI HTTP Boot BIOS setting are reset.
        In case of UEFI iSCSI booting, it cleans up iSCSI target information
        from the node.
        Secure boot is also disabled if it was set earlier during provisioning
        of the ironic node.

        :param task: a task from TaskManager.
        :returns: None
        :raises: SDFlexOperationError, if some operation on SDFlex failed.
        """
        manager_utils.node_power_action(task, states.POWER_OFF)
        disable_secure_boot_if_supported(task)

        node = task.node
        if (is_directed_lanboot_requested(node) or
                http_utils.is_http_boot_requested(node)):
            # In this cleaning step it sets the URLBOOTFILE & URLBOOTFILE2
            # path as ''.
            sdflex_common.reset_bios_settings(node)

        if http_utils.is_http_boot_requested(node):
            try:
                images_info = http_utils.get_instance_image_info(task)
            except ironic_exception.MissingParameterValue as e:
                LOG.warning('Could not get instance image info '
                            'to clean up images for node %(node)s: %(err)s',
                            {'node': node.uuid, 'err': e})
            else:
                http_utils.clean_up_http_env(task, images_info)
        else:
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
        if (is_directed_lanboot_requested(node)
                or http_utils.is_http_boot_requested(node)):
            boot_file_path = node.driver_info.get('boot_file_path')
            if boot_file_path is None:
                raise ironic_exception.MissingParameterValue(_(
                    "Missing URLBootFile or UrlBootFile2 as keys in "
                    "driver_info['boot_file_path']"))
            url_data1 = boot_file_path.get('UrlBootFile', False)
            url_data2 = boot_file_path.get('UrlBootFile2', False)
            if url_data1 and is_directed_lanboot_requested(node):
                if not url_data1.startswith('tftp://'):
                    raise ironic_exception.InvalidParameterValue(_(
                        "Directed Lan boot accepts only tftp url's as "
                        "values for UrlBootFile in"
                        "driver_info['boot_file_path']"))
            elif url_data2 and is_directed_lanboot_requested(node):
                if not url_data2.startswith('tftp://'):
                    raise ironic_exception.InvalidParameterValue(_(
                        "Directed Lan boot accepts only tftp url's as "
                        "values for UrlBootFile2 in"
                        "driver_info['boot_file_path']"))
            elif url_data1 and http_utils.is_http_boot_requested(node):
                if not url_data1.startswith('http://'):
                    raise ironic_exception.InvalidParameterValue(_(
                        "UEFI HTTP boot accepts only http url's as "
                        "values for UrlBootFile in"
                        "driver_info['boot_file_path']"))
            elif url_data2 and http_utils.is_http_boot_requested(node):
                if not url_data2.startswith('http://'):
                    raise ironic_exception.InvalidParameterValue(_(
                        "UEFI HTTP boot accepts only http url's as "
                        "values for UrlBootFile2 in"
                        "driver_info['boot_file_path']"))
            else:
                raise ironic_exception.MissingParameterValue(_(
                    "Missing URLBootFile or UrlBootFile2 as keys in "
                    "driver_info['boot_file_path']"))
