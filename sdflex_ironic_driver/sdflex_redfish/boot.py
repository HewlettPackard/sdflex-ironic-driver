# Copyright 2015 Hewlett-Packard Development Company, L.P.
# Copyright 2019 Red Hat, Inc.
# All Rights Reserved.
# Copyright 2019-2022 Hewlett Packard Enterprise Development LP
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
# Some of the methods/code snippets in this file are owned by Red Hat, Inc

"""
Boot Interface for SDFlex driver and its supporting methods.
"""

import os
import shutil
import tempfile
from urllib import parse as urlparse

from ironic_lib import metrics_utils
from ironic_lib import utils as ironic_utils

from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import base64
from oslo_utils import importutils

from ironic.common import boot_devices
from ironic.common import exception as ironic_exception
from ironic.common.i18n import _
from ironic.common import images
from ironic.common import states
from ironic.conductor import utils as manager_utils
from ironic.drivers.modules import boot_mode_utils
from ironic.drivers.modules import deploy_utils
from ironic.drivers.modules import image_utils
from ironic.drivers.modules import pxe
from ironic.drivers.modules.redfish import boot as redfish_boot

from sdflexutils.redfish.resources.system import constants as sdflexutils_constants  # noqa E501

from sushy.resources.system import constants as sushy_constants

from sdflex_ironic_driver import exception
from sdflex_ironic_driver import http_utils
from sdflex_ironic_driver.sdflex_redfish import common as sdflex_common

sushy = importutils.try_import('sushy')


LOG = logging.getLogger(__name__)
boot_devices.UEFIHTTP = 'uefi http'
boot_devices.CD = sushy_constants.BOOT_SOURCE_TARGET_CD
vmedia_device = 'cd0'

METRICS = metrics_utils.get_metrics_logger(__name__)

CONF = cfg.CONF


def sdflex_update_driver_config(self, driver):
    _SWIFT_MAP = {
        "sdflex-redfish": {
            "swift_enabled": False,
            "container": None,
            "timeout": 900,
            "image_subdir": "sdflex-redfish",
            "file_permission": 0o644,
            "kernel_params": CONF.pxe.kernel_append_params
        },
    }

    self._driver = driver
    self.swift_enabled = _SWIFT_MAP[driver].get("swift_enabled")
    self._container = _SWIFT_MAP[driver].get("container")
    self._timeout = _SWIFT_MAP[driver].get("timeout")
    self._image_subdir = _SWIFT_MAP[driver].get("image_subdir")
    self._file_permission = _SWIFT_MAP[driver].get("file_permission")
    # To get the kernel parameters
    self.kernel_params = _SWIFT_MAP[driver].get("kernel_params")


image_utils.ImageHandler.update_driver_config = sdflex_update_driver_config


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
    if is_directed_lanboot_requested(node):
        sdflex_common.enable_directed_lan_boot(node)
    elif http_utils.is_http_boot_requested(task.node):
        sdflex_common.enable_uefi_http_boot(task.node)
    else:
        LOG.info("Booting through PXE as Directed LAN Boot and "
                 "UEFI HTTP boot are not enabled.")


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
                                         states.CLEANING, states.INSPECTING):
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
        bfpv = str(task.node.driver_info.get('bfpv', 'false')).lower()
        if bfpv == 'true':
            node = task.node
            driver_internal_info = node.driver_internal_info
            driver_internal_info['bfpv_started'] = 'false'
            node.driver_internal_info = driver_internal_info
            node.save()

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
        boot_option = deploy_utils.get_boot_option(task.node)
        if boot_option != "kickstart":
            sdflex_common.update_secure_boot_mode(task, True)
        if not http_utils.is_http_boot_requested(task.node):
            if boot_option == "kickstart":
                prepare_node_for_deploy(task)
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
            # In this cleaning step it sets the URLBOOTFILE & URLBOOTFILE2 &
            # HttpBootUri path as ''.
            sdflex_common.reset_bios_settings(node)
            http_boot_uri = node.driver_info.get('http_boot_uri')
            if http_boot_uri:
                sdflex_object = sdflex_common.get_sdflex_object(node)
                sdflex_object.set_http_boot_uri(None)

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
        bfpv = str(task.node.driver_info.get('bfpv', 'false')).lower()
        sdflex_common.parse_driver_info(node)
        if is_directed_lanboot_requested(node):
            self.validate_directed_lanboot(node)
        elif http_utils.is_http_boot_requested(node):
            self.validate_uefi_httpboot(node)
        if bfpv == 'false':
            super(SdflexPXEBoot, self).validate(task)
        elif node.get_interface('deploy') != 'sdflex-redfish':
            raise ironic_exception.InvalidParameterValue(_(
                "Node %(node)s has bfpv set to true and "
                "deploy_interface is not set to sdflex-redfish. "
                "bfpv is supported with deploy_interface sdflex-redfish.")
                % {'node': node.uuid})

    def validate_directed_lanboot(self, node):
        boot_file_path = node.driver_info.get('boot_file_path')
        if not boot_file_path:
            raise ironic_exception.MissingParameterValue(_(
                "Missing URLBootFile or UrlBootFile2 as keys in "
                "driver_info['boot_file_path'] for node %(node)s")
                % {'node': node.uuid})
        url_data1 = boot_file_path.get('UrlBootFile')
        url_data2 = boot_file_path.get('UrlBootFile2')
        if url_data1 and not url_data1.startswith('tftp://'):
            raise ironic_exception.InvalidParameterValue(_(
                "Directed Lan boot accepts only tftp url's as values"
                "for UrlBootFile in driver_info['boot_file_path'] for "
                "node %(node)s") % {'node': node.uuid})
        elif url_data2 and not url_data2.startswith('tftp://'):
            raise ironic_exception.InvalidParameterValue(_(
                "Directed Lan boot accepts only tftp url's as values "
                "for UrlBootFile2 in driver_info['boot_file_path'] for "
                "node %(node)s") % {'node': node.uuid})
        elif not url_data1 and not url_data2:
            raise ironic_exception.MissingParameterValue(_(
                "Missing URLBootFile or UrlBootFile2 as keys in "
                "driver_info['boot_file_path'] for "
                "node %(node)s") % {'node': node.uuid})

    def validate_uefi_httpboot(self, node):
        if (http_utils.is_http_boot_requested(node) and
            deploy_utils.is_anaconda_deploy(node)):
            raise ironic_exception.InvalidParameterValue(_(
                "Node %(node)s has enable_uefi_httpboot set to true and "
                "deploy_interface as anaconda. Uefi http boot is not "
                "supported with deploy_interface as anaconda.")
                % {'node': node.uuid})
        http_boot_uri = node.driver_info.get('http_boot_uri')
        boot_file_path = node.driver_info.get('boot_file_path')
        if http_boot_uri:
            if (not http_boot_uri.startswith('http://') or
                not http_boot_uri.endswith(".efi")):
                raise ironic_exception.InvalidParameterValue(_(
                    "'%(http_boot_uri)s' is an invalid value in "
                    "driver_info['http_boot_uri'] for node %(node)s."
                    "For UEFI HTTP boot, bootloader name ending with '.efi'"
                    " is valid inputs for 'http_boot_uri'. ") %
                    {'http_boot_uri': http_boot_uri, 'node': node.uuid})
        elif boot_file_path:
            url_data1 = boot_file_path.get('UrlBootFile')
            url_data2 = boot_file_path.get('UrlBootFile2')
            if url_data1:
                if (not url_data1.startswith('http://') or
                    not url_data1.endswith(".efi")):
                    raise ironic_exception.InvalidParameterValue(_(
                        "'%(UrlBootFile)s' is an invalid value in "
                        "driver_info['http_boot_uri'] for node %(node)s"
                        "For UEFI HTTP boot, bootloaders ending with '.efi' "
                        "is valid inputs for 'UrlBootFile' ") %
                        {'UrlBootFile': url_data1, 'node': node.uuid})
            if url_data2:
                if (not url_data2.startswith('http://') or
                    not url_data2.endswith(".efi")):
                    raise ironic_exception.InvalidParameterValue(_(
                        "'%(UrlBootFile)s' is an invalid value in "
                        "driver_info['http_boot_uri'] for node %(node)s"
                        "For UEFI HTTP boot, bootloaders ending with '.efi' "
                        "is valid inputs for 'UrlBootFile' ") %
                        {'UrlBootFile': url_data2, 'node': node.uuid})
        else:
            raise ironic_exception.MissingParameterValue(_(
                "Missing URLBootFile or UrlBootFile2 as keys in "
                "driver_info['boot_file_path'] or HTTP Boot URI is missing "
                "for node %(node)s") % {'node': node.uuid})


class SdflexRedfishVirtualMediaBoot(redfish_boot.RedfishVirtualMediaBoot):

    def __init__(self):
        """Initialize the Sdflex-Redfish Virtual Media Boot interface.

        :raises: DriverLoadError if the driver can't be loaded due to
            missing dependencies
        """
        super(SdflexRedfishVirtualMediaBoot, self).__init__()
        if not sushy:
            raise ironic_exception.DriverLoadError(
                driver='sdfelx-redfish',
                reason=_('Unable to import the sushy library'))

    @staticmethod
    def _get_iso_image_name(node):
        """Returns the boot iso image name for a given node.

        :param node: the node for which image name is to be provided.
        """
        return "boot-%s.iso" % node.uuid

    def _publish_image(self, image_file, object_name, image_share_root):
        """Make image file downloadable.

        Depending on ironic settings, pushes given file into NFS & CIFS
        and returns publicly accessible URL leading to the given file.

        :param image_file: path to file to publish
        :param object_name: name of the published file
        :param remote_image_share_root: Server location address where the
                                    image file have to be placed
        :return: a URL to download published file
        """
        public_dir = image_share_root

        if not os.path.exists(public_dir):
            os.mkdir(public_dir, 0x755)

        published_file = os.path.join(public_dir, object_name)

        try:
            os.link(image_file, published_file)
        except OSError as exc:
            LOG.debug(
                "Could not hardlink image file %(image)s to public "
                "location %(public)s (will copy it over): "
                "%(error)s", {'image': image_file,
                              'public': published_file,
                              'error': exc})

            shutil.copyfile(image_file, published_file)
        os.chmod(published_file, 0o777)

        return object_name

    def _unpublish_image(self, object_name, image_share_root):
        """Withdraw the image previously made downloadable.

        Depending on ironic settings, removes previously published file
        from where it has been published - NFS & CIFS.

        :param object_name: name of the published file (optional)
        """
        if image_share_root:
            published_file = os.path.join(image_share_root, object_name)

            ironic_utils.unlink_without_raise(published_file)

    def _cleanup_iso_image(self, task):
        """Deletes the ISO if it was created for the instance.

        :param task: an ironic node object.
        """
        driver_info = task.node.driver_info
        if driver_info.get('remote_image_share_type') == 'nfs':
            image_share_root = driver_info.get('remote_image_share_root')
        else:
            image_share_root = driver_info.get('image_share_root')

        iso_object_name = self._get_iso_image_name(task.node)
        self._unpublish_image(iso_object_name, image_share_root)

    def _prepare_iso_image(self, task, kernel_href, ramdisk_href,
                           bootloader_href=None, configdrive=None,
                           root_uuid=None, params=None):
        """Prepare an ISO to boot the node.

        Build bootable ISO out of `kernel_href` and `ramdisk_href` (and
        `bootloader` if it's UEFI boot), then push built image up to NFS/CIFS
        and return a temporary URL.

        :param task: a TaskManager instance containing the node to act on.
        :param kernel_href: URL or Glance UUID of the kernel to use
        :param ramdisk_href: URL or Glance UUID of the ramdisk to use
        :param bootloader_href: URL or Glance UUID of the EFI bootloader
             image to use when creating UEFI bootbable ISO
        :param configdrive: URL to or a compressed blob of a ISO9660 or
            FAT-formatted OpenStack config drive image. This image will be
            written onto the built ISO image. Optional.
        :param root_uuid: optional uuid of the root partition.
        :param params: a dictionary containing 'parameter name'->'value'
            mapping to be passed to kernel command line.
        :returns: bootable ISO NFS/CIFS URL.
        :raises: MissingParameterValue, if any of the required parameters are
            missing.
        :raises: InvalidParameterValue, if any of the parameters have invalid
            value.
        :raises: ImageCreationFailed, if creating ISO image failed.
        """
        if not kernel_href or not ramdisk_href:
            raise exception.InvalidParameterValue(_(
                "Unable to find kernel or ramdisk for "
                "building ISO for %(node)s") %
                {'node': task.node.uuid})

        i_info = task.node.instance_info
        driver_info = task.node.driver_info
        if driver_info.get('remote_image_share_type') == 'nfs':
            image_share_root = driver_info.get('remote_image_share_root')
        else:
            image_share_root = driver_info.get('image_share_root')
        if deploy_utils.get_boot_option(task.node) == "ramdisk":
            kernel_params = "root=/dev/ram0 text "
            kernel_params += i_info.get("ramdisk_kernel_arguments", "")

        else:
            kernel_params = i_info.get('kernel_append_params', "")

        if params:
            kernel_params = ' '.join(
                (kernel_params, ' '.join(
                    '%s=%s' % kv for kv in params.items())))

        boot_mode = boot_mode_utils.get_boot_mode_for_deploy(task.node)

        LOG.debug("Trying to create %(boot_mode)s ISO image for node %(node)s "
                  "with kernel %(kernel_href)s, ramdisk %(ramdisk_href)s, "
                  "bootloader %(bootloader_href)s and kernel params %(params)s"
                  "", {'node': task.node.uuid,
                       'boot_mode': boot_mode,
                       'kernel_href': kernel_href,
                       'ramdisk_href': ramdisk_href,
                       'bootloader_href': bootloader_href,
                       'params': kernel_params})

        with tempfile.NamedTemporaryFile(
                dir=CONF.tempdir, suffix='.iso') as boot_fileobj:

            with tempfile.NamedTemporaryFile(
                    dir=CONF.tempdir, suffix='.img') as cfgdrv_fileobj:

                configdrive_href = configdrive

                if configdrive:
                    parsed_url = urlparse.urlparse(configdrive)
                    if not parsed_url.scheme:
                        cfgdrv_blob = base64.decode_as_bytes(configdrive)

                        with open(cfgdrv_fileobj.name, 'wb') as f:
                            f.write(cfgdrv_blob)

                        configdrive_href = urlparse.urlunparse(
                            ('file', '', cfgdrv_fileobj.name, '', '', ''))

                    LOG.info("Burning configdrive %(url)s to boot ISO image "
                             "for node %(node)s", {'url': configdrive_href,
                                                   'node': task.node.uuid})
                boot_iso_tmp_file = boot_fileobj.name

                images.create_boot_iso(
                    task.context, boot_iso_tmp_file,
                    kernel_href, ramdisk_href,
                    esp_image_href=bootloader_href,
                    root_uuid=root_uuid,
                    kernel_params=kernel_params,
                    boot_mode=boot_mode)
                iso_object_name = self._get_iso_image_name(task.node)

                image_url = self._publish_image(
                    boot_iso_tmp_file, iso_object_name, image_share_root)

        LOG.debug("Created ISO %(name)s in NFS/CIFS for node %(node)s, "
                  "exposed as temporary URL "
                  "%(url)s", {'node': task.node.uuid,
                              'name': iso_object_name,
                              'url': image_url})

        return image_url

    def _prepare_deploy_iso(self, task, params, mode):
        """Prepare deploy or rescue ISO image

        Build bootable ISO out of
        `[driver_info]/deploy_kernel`/`[driver_info]/deploy_ramdisk` or
        `[driver_info]/rescue_kernel`/`[driver_info]/rescue_ramdisk`
        and `[driver_info]/bootloader`

        :param task: a TaskManager instance containing the node to act on.
        :param params: a dictionary containing 'parameter name'->'value'
            mapping to be passed to kernel command line.
        :param mode: either 'deploy' or 'rescue'.
        :returns: bootable ISO.
        :raises: MissingParameterValue, if any of the required parameters are
            missing.
        :raises: InvalidParameterValue, if any of the parameters have invalid
            value.
        :raises: ImageCreationFailed, if creating ISO image failed.
        """
        node = task.node
        d_info = redfish_boot._parse_driver_info(node)

        kernel_href = d_info.get('%s_kernel' % mode)
        ramdisk_href = d_info.get('%s_ramdisk' % mode)
        bootloader_href = d_info.get('bootloader')

        return self._prepare_iso_image(
            task, kernel_href, ramdisk_href, bootloader_href, params=params)

    def _prepare_boot_iso(self, task, root_uuid=None):
        """Prepare boot ISO image

        Build bootable ISO out of `[instance_info]/kernel`,
        `[instance_info]/ramdisk` and `[driver_info]/bootloader` if present.
        Otherwise, read `kernel_id` and `ramdisk_id` from
        `[instance_info]/image_source` Glance image metadata.

        Push produced ISO image up to Glance and return temporary Swift
        URL to the image.

        :param task: a TaskManager instance containing the node to act on.
        :returns: bootable ISO HTTP URL.
        :raises: MissingParameterValue, if any of the required parameters are
            missing.
        :raises: InvalidParameterValue, if any of the parameters have invalid
            value.
        :raises: ImageCreationFailed, if creating ISO image failed.
        """
        node = task.node
        d_info = redfish_boot._parse_deploy_info(node)

        kernel_href = node.instance_info.get('kernel')
        ramdisk_href = node.instance_info.get('ramdisk')

        if not kernel_href or not ramdisk_href:

            image_href = d_info['image_source']

            image_properties = (
                images.get_image_properties(
                    task.context, image_href, ['kernel_id', 'ramdisk_id']))

            if not kernel_href:
                kernel_href = image_properties.get('kernel_id')

            if not ramdisk_href:
                ramdisk_href = image_properties.get('ramdisk_id')

        if not kernel_href or not ramdisk_href:
            raise exception.InvalidParameterValue(_(
                "Unable to find kernel or ramdisk for "
                "to generate boot ISO for %(node)s") %
                {'node': task.node.uuid})

        bootloader_href = d_info.get('bootloader')

        return self._prepare_iso_image(
            task, kernel_href, ramdisk_href, bootloader_href,
            root_uuid=root_uuid)

    def prepare_ramdisk(self, task, ramdisk_params):
        """Prepares the boot of deploy or rescue ramdisk over virtual media.

        This method prepares the boot of the deploy or rescue ramdisk after
        reading relevant information from the node's driver_info.

        :param task: A task from TaskManager.
        :param ramdisk_params: the parameters to be passed to the ramdisk.
        :returns: None
        :raises: MissingParameterValue, if some information is missing in
            node's driver_info or instance_info.
        :raises: InvalidParameterValue, if some information provided is
            invalid.
        :raises: IronicException, if some power or set boot device
            operation failed on the node.
        """
        node = task.node
        remote_server_data = {}
        remote_image_server = node.driver_info.get('remote_image_server')
        remote_image_share_root = node.driver_info.get(
            'remote_image_share_root')
        remote_server_data['remote_image_share_type'] = (
            node.driver_info.get('remote_image_share_type'))
        remote_server_data['remote_image_user_name'] = (
            node.driver_info.get('remote_image_user_name', None))
        remote_server_data['remote_image_user_password'] = (
            node.driver_info.get('remote_image_user_password', None))

        # NOTE(TheJulia): If this method is being called by something
        # aside from deployment, clean and rescue, such as conductor takeover,
        # we should treat this as a no-op and move on otherwise we would
        # modify the state of the node due to virtual media operations.
        if node.provision_state not in (states.DEPLOYING,
                                        states.CLEANING,
                                        states.RESCUING,
                                        states.INSPECTING):
            return

        # NOTE(TheJulia): Since we're deploying, cleaning, or rescuing,
        # with virtual media boot, we should generate a token!
        manager_utils.add_secret_token(node, pregenerated=True)
        node.save()
        ramdisk_params['ipa-agent-token'] = (
            node.driver_internal_info['agent_secret_token'])

        manager_utils.node_power_action(task, states.POWER_OFF)

        deploy_nic_mac = deploy_utils.get_single_nic_with_vif_port_id(task)
        ramdisk_params['BOOTIF'] = deploy_nic_mac
        if CONF.debug and 'ipa-debug' not in ramdisk_params:
            ramdisk_params['ipa-debug'] = '1'

        mode = deploy_utils.rescue_or_deploy_mode(node)
        iso_ref = self._prepare_deploy_iso(task, ramdisk_params, mode)

        url = (remote_server_data['remote_image_share_type'] + "://" +
               remote_image_server + "/" + remote_image_share_root + "/" +
               iso_ref)

        sdflex_common.eject_vmedia(task,
                                   vmedia_device)
        sdflex_common.insert_vmedia(task, url,
                                    vmedia_device,
                                    remote_server_data)

        boot_mode_utils.sync_boot_mode(task)

        self._set_boot_device(task, boot_devices.CD.value.lower())

        LOG.debug("Node %(node)s is set to one time boot from "
                  "%(device)s", {'node': task.node.uuid,
                                 'device': boot_devices.CD})

    def clean_up_ramdisk(self, task):
        """Cleans up the boot of ironic ramdisk.

        This method cleans up the environment that was setup for booting the
        deploy ramdisk.

        :param task: A task from TaskManager.
        :returns: None
        """
        LOG.debug("Cleaning up deploy boot for "
                  "%(node)s", {'node': task.node.uuid})

        sdflex_common.eject_vmedia(task,
                                   vmedia_device)
        self._cleanup_iso_image(task)

    def prepare_instance(self, task):
        """Prepares the boot of instance over virtual media.

        This method prepares the boot of the instance after reading
        relevant information from the node's instance_info.

        The internal logic is as follows:

        - If `boot_option` requested for this deploy is 'local', then set the
          node to boot from disk.
        - Unless `boot_option` requested for this deploy is 'ramdisk', pass
          root disk/partition ID to virtual media boot image
        - Otherwise build boot image,insert it into virtual media device
          and set node to boot from CD.

        :param task: a task from TaskManager.
        :returns: None
        :raises: InstanceDeployFailure, if its try to boot iSCSI volume in
                 'BIOS' boot mode.
        """
        node = task.node

        boot_option = deploy_utils.get_boot_option(node)

        self.clean_up_instance(task)

        remote_image_server = node.driver_info.get('remote_image_server')
        remote_image_share_root = node.driver_info.get(
            'remote_image_share_root')

        remote_server_data = {}
        remote_server_data['remote_image_share_type'] = (
            node.driver_info.get('remote_image_share_type'))
        remote_server_data['remote_image_user_name'] = (
            node.driver_info.get('remote_image_user_name', None))
        remote_server_data['remote_image_user_password'] = (
            node.driver_info.get('remote_image_user_password', None))

        # Need to enable secure boot, if being requested.
        # update_secure_boot_mode checks and enables secure boot only if the
        # deploy has requested secure boot
        sdflex_common.update_secure_boot_mode(task, True)
        iwdi = node.driver_internal_info.get('is_whole_disk_image')
        if boot_option == "local" or iwdi:
            self._set_boot_device(
                task, boot_devices.DISK, persistent=True)

            LOG.debug("Node %(node)s is set to permanently boot from local "
                      "%(device)s", {'node': task.node.uuid,
                                     'device': boot_devices.DISK})
            return

        params = {}

        if boot_option != 'ramdisk':
            root_uuid = node.driver_internal_info.get('root_uuid_or_disk_id')

            if not root_uuid and task.driver.storage.should_write_image(task):
                LOG.warning(
                    "The UUID of the root partition could not be found for "
                    "node %s. Booting instance from disk anyway.", node.uuid)

                self._set_boot_device(
                    task, boot_devices.DISK, persistent=True)

                return

            params.update(root_uuid=root_uuid)

        iso_ref = self._prepare_boot_iso(task, **params)

        url = (remote_server_data['remote_image_share_type'] + "://" +
               remote_image_server + "/" + remote_image_share_root + "/" +
               iso_ref)

        sdflex_common.eject_vmedia(task,
                                   vmedia_device)
        sdflex_common.insert_vmedia(task, url,
                                    vmedia_device,
                                    remote_server_data)

        boot_mode_utils.sync_boot_mode(task)

        self._set_boot_device(
            task, boot_devices.CD.value.lower(), persistent=True)

        LOG.debug("Node %(node)s is set to permanently boot from "
                  "%(device)s", {'node': task.node.uuid,
                                 'device': boot_devices.CD})

    def clean_up_instance(self, task):
        """Cleans up the boot of instance.

        This method cleans up the environment that was setup for booting
        the instance.

        :param task: A task from TaskManager.
        :returns: None
        """
        LOG.debug("Cleaning up instance boot for "
                  "%(node)s", {'node': task.node.uuid})
        disable_secure_boot_if_supported(task)
        sdflex_common.eject_vmedia(task,
                                   vmedia_device)
        self._cleanup_iso_image(task)

    def validate(self, task):
        """Validate the deployment information for the task's node.

        :param task: a TaskManager instance containing the node to act on.
        :raises: InvalidParameterValue, if some information is invalid.
        :raises: MissingParameterValue if some mandatory information
        is missing on the node
        """
        node = task.node
        sdflex_common.parse_driver_info(node)
        driver_info = task.node.driver_info
        required_params_for_cifs = ['remote_image_user_name',
                                    'remote_image_user_password',
                                    'image_share_root']
        required_params = ['remote_image_share_type', 'remote_image_server',
                           'remote_image_share_root', 'bootloader']
        missing = []
        if (('nfs' not in driver_info.values()) and
                ('cifs' not in driver_info.values())):
            raise ironic_exception.InvalidParameterValue(_(
                "Invalid '%(value)s' as remote_image_share_type in "
                "driver_info. It should be either 'nfs' or 'cifs'") %
                {'value': driver_info['remote_image_share_type']})
        for params in required_params:
            if params not in driver_info:
                missing.append(params)
        if 'cifs' in driver_info.values():
            for params in required_params_for_cifs:
                if params not in driver_info:
                    missing.append(params)
        if missing:
            raise ironic_exception.MissingParameterValue(_(
                "Missing %(missing)s in driver_info") % {'missing': missing})
        super(SdflexRedfishVirtualMediaBoot, self).validate(task)


class SdflexRedfishDhcplessBoot(pxe.PXEBoot):

    @METRICS.timer('SdflexRedfishDhcplessBoot.prepare_ramdisk')
    def prepare_ramdisk(self, task, ramdisk_params):
        """Prepares the boot of Ironic ramdisk.

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
        """
        if task.node.provision_state in (states.DEPLOYING, states.RESCUING,
                                         states.CLEANING, states.INSPECTING):
            node = task.node
            d_info = redfish_boot._parse_driver_info(node)
            # Label indicating a deploy or rescue operation being carried out
            # on the node, 'deploy' or 'rescue'. Unless the node is in a
            # rescue like state, the mode is set to 'deploy', indicating
            # deploy operation is being carried out.

            mode = deploy_utils.rescue_or_deploy_mode(node)

            iso_ref = image_utils.prepare_deploy_iso(task, ramdisk_params,
                                                     mode, d_info)
            node.driver_internal_info.update({'deploy_boot_iso': iso_ref})

            sdflex_common.set_network_setting_dhcpless_boot(node, iso_ref)
            boot_mode_utils.sync_boot_mode(task)
            manager_utils.node_set_boot_device(task, boot_devices.UEFIHTTP,
                                               persistent=False)

    @METRICS.timer('SdflexRedfishDhcplessBoot.prepare_instance')
    def prepare_instance(self, task):
        """Prepares the boot of instance.

        This method prepares the boot of the instance. Only boot option
        local is supported. If secure boot is enabled, it will boot the
        OS in secure boot.

        :param task: a task from TaskManager.
        :returns: None
        :raises: SDFlexOperationError, if some operation on SDFlex failed.
        """

        # Need to enable secure boot, if being requested.
        # update_secure_boot_mode checks and enables secure boot only if the
        # deploy has requested secure boot
        sdflex_common.update_secure_boot_mode(task, True)

        boot_mode_utils.sync_boot_mode(task)
        node = task.node
        boot_device = None

        self.clean_up_instance(task)
        boot_device = boot_devices.DISK

        if boot_device and task.node.provision_state != states.ACTIVE:
            persistent = True
            if node.driver_info.get('force_persistent_boot_device',
                                    'Default') == 'Never':
                persistent = False
            manager_utils.node_set_boot_device(task, boot_device,
                                               persistent=persistent)

    @METRICS.timer('SdflexRedfishDhcplessBoot.clean_up_instance')
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

        sdflex_common.reset_network_setting_dhcpless_boot(node)
        image_utils.cleanup_iso_image(task)

    @METRICS.timer('SdflexRedfishDhcplessBoot.validate')
    def validate(self, task):
        """Validate the deployment information for the task's node.

        :param task: a TaskManager instance containing the node to act on.
        :raises: InvalidParameterValue, if some information is invalid.
        :raises: MissingParameterValue if some mandatory information
        is missing on the node
        """
        node = task.node
        sdflex_common.parse_driver_info(node)
        if not node.network_data.get('networks'):
            raise ironic_exception.MissingParameterValue(_(
                "Missing network data. Please add the network data and retry"))

        network_data = node.network_data.get('networks')[0]
        ipv4_address = network_data.get('ip_address')
        routes = network_data.get('routes')[0]
        ipv4_gateway = routes.get('gateway')
        ipv4_subnet_mask = routes.get('netmask')

        missing_parameter = []
        if not ipv4_address:
            missing_parameter.append('ipv4_address')
        if not ipv4_gateway:
            missing_parameter.append('ipv4_gateway')
        if not ipv4_subnet_mask:
            missing_parameter.append('ipv4_subnet_mask')
        if missing_parameter:
            raise ironic_exception.MissingParameterValue(_(
                "%(missing_parameter)s are Missing Parameter in Network"
                " data") % {'missing_parameter': missing_parameter})
