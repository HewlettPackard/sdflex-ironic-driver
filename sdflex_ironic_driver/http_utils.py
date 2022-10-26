#
# Copyright 2014 Rackspace, Inc
# All Rights Reserved
#
# Copyright 2022 Hewlett Packard Enterprise Development LP
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
# Most of the methods/code snippets in this file are owned by Rackspace, Inc

import os

from ironic_lib import utils as ironic_utils
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import fileutils

from ironic.common import dhcp_factory
from ironic.common import exception
from ironic.common.i18n import _
from ironic.common import image_service as service
from ironic.common import states
from ironic.common import utils
from ironic.conf import CONF
from ironic.drivers.modules import boot_mode_utils
from ironic.drivers.modules import deploy_utils
from ironic.drivers.modules import image_cache

LOG = logging.getLogger(__name__)

PXE_CFG_DIR_NAME = CONF.pxe.pxe_config_subdir

DHCP_CLIENT_ID = '61'  # rfc2132
DHCP_HTTP_SERVER_NAME = '66'  # rfc2132
DHCP_BOOTFILE_NAME = '67'  # rfc2132
DHCPV6_BOOTFILE_NAME = '59'  # rfc5870
# NOTE(TheJulia): adding note for the bootfile parameter
# field as defined by RFC 5870. No practical examples seem
# available. Neither grub2 or ipxe seem to leverage this.
# DHCPV6_BOOTFILE_PARAMS = '60'  # rfc5870
DHCP_HTTP_SERVER_ADDRESS = '150'  # rfc5859
DHCP_HTTP_PATH_PREFIX = '210'  # rfc5071

DEPLOY_KERNEL_RAMDISK_LABELS = ['deploy_kernel', 'deploy_ramdisk']
RESCUE_KERNEL_RAMDISK_LABELS = ['rescue_kernel', 'rescue_ramdisk']
KERNEL_RAMDISK_LABELS = {'deploy': DEPLOY_KERNEL_RAMDISK_LABELS,
                         'rescue': RESCUE_KERNEL_RAMDISK_LABELS}


def get_http_boot_dir():
    return CONF.deploy.http_root


def _ensure_config_dirs_exist(task):
    """Ensure that the node's and HTTP configuration directories exist.

    :param task: A TaskManager instance
    """
    root_dir = get_http_boot_dir()

    node_dir = os.path.join(root_dir, task.node.uuid)
    pxe_dir = os.path.join(root_dir, PXE_CFG_DIR_NAME)
    # NOTE: We should only change the permissions if the folder
    # does not exist. i.e. if defined, an operator could have
    # already created it and placed specific ACLs upon the folder
    # which may not recurse downward.
    for directory in (node_dir, pxe_dir):
        if not os.path.isdir(directory):
            fileutils.ensure_tree(directory)
            if CONF.pxe.dir_permission:
                os.chmod(directory, CONF.pxe.dir_permission)


def _link_mac_http_configs(task):
    """Link each MAC address with the HTTP configuration file.

    :param task: A TaskManager instance.
    """

    def create_link(mac_path):
        ironic_utils.unlink_without_raise(mac_path)
        relative_source_path = os.path.relpath(
            http_config_file_path, os.path.dirname(mac_path))
        utils.create_link_without_raise(relative_source_path, mac_path)
    http_config_file_path = get_http_config_file_path(task.node.uuid)
    for port in task.ports:
        # Grub2 MAC address only
        create_link(_get_http_grub_mac_path(port.address))


def _link_ip_address_http_configs(task):
    """Link each IP address with the HTTP configuration file.

    :param task: A TaskManager instance.
    :raises: FailedToGetIPAddressOnPort
    :raises: InvalidIPv4Address

    """
    http_config_file_path = get_http_config_file_path(task.node.uuid)

    api = dhcp_factory.DHCPFactory().provider
    ip_addrs = api.get_ip_addresses(task)
    if not ip_addrs:

        if ip_addrs == []:
            LOG.warning("No IP addresses assigned for node %(node)s.",
                        {'node': task.node.uuid})
        else:
            LOG.warning(
                "DHCP address management is not available for node "
                "%(node)s. Operators without Neutron can ignore this "
                "warning.",
                {'node': task.node.uuid})
        # Just in case, reset to empty list if we got nothing.
        ip_addrs = []
    for port_ip_address in ip_addrs:
        ip_address_path = _get_http_ip_address_path(port_ip_address)
        ironic_utils.unlink_without_raise(ip_address_path)
        relative_source_path = os.path.relpath(
            http_config_file_path, os.path.dirname(ip_address_path))
        utils.create_link_without_raise(relative_source_path,
                                        ip_address_path)


def _get_http_grub_mac_path(mac):
    return os.path.join(get_http_boot_dir(), mac + ".conf")


def _get_http_mac_path(mac, delimiter='-', client_id=None):
    """Convert a MAC address into a HTTP config file name.

    :param mac: A MAC address string in the format xx:xx:xx:xx:xx:xx.
    :param delimiter: The MAC address delimiter. Defaults to dash ('-').
    :param client_id: client_id indicate InfiniBand port.
                      Defaults is None (Ethernet)
    :returns: the path to the config file.

    """
    mac_file_name = mac.replace(':', delimiter).lower()
    hw_type = '01-'
    if client_id:
        hw_type = '20-'
    mac_file_name = hw_type + mac_file_name
    return os.path.join(get_http_boot_dir(), PXE_CFG_DIR_NAME, mac_file_name)


def _get_http_ip_address_path(ip_address):
    """Convert an ipv4 address into a HTTP config file name.

    :param ip_address: A valid IPv4 address string in the format 'n.n.n.n'.
    :returns: the path to the config file.

    """
    # grub2 bootloader needs ip based config file name.
    root_dir = get_http_boot_dir()
    return os.path.join(root_dir, ip_address + ".conf")


def get_kernel_ramdisk_info(node, driver_info, mode='deploy'):
    """Get href and http path for deploy or rescue kernel and ramdisk.

    :param node_uuid: UUID of the node
    :param driver_info: Node's driver_info dict
    :param mode: A label to indicate whether paths for deploy or rescue
                 ramdisk are being requested. Supported values are 'deploy'
                 'rescue'. Defaults to 'deploy', indicating deploy paths will
                 be returned.
    :returns: a dictionary whose keys are deploy_kernel and deploy_ramdisk or
              rescue_kernel and rescue_ramdisk and whose values are the
              absolute paths to them.

    Note: driver_info should be validated outside of this method.
    """
    root_dir = get_http_boot_dir()
    node_uuid = node.uuid
    image_info = {}
    labels = KERNEL_RAMDISK_LABELS[mode]
    for label in labels:
        image_info[label] = (
            str(driver_info[label]),
            os.path.join(root_dir, node_uuid, label)
        )
    return image_info


def get_http_config_file_path(node_uuid):
    """Generate the path for the node's HTTP configuration file.

    :param node_uuid: the UUID of the node.
    :returns: The path to the node's HTTP configuration file.

    """
    return os.path.join(get_http_boot_dir(), node_uuid, 'config')


def create_http_config(task, http_options, template=None):
    """Generate UEFI HTTP configuration file and MAC address links for it.

    This method will generate the UEFI HTTP configuration file for the task's
    node under a directory named with the UUID of that node. For each
    MAC address or DHCP IP address (port) of that node, a symlink for
    the configuration file will be created under the UEFI HTTP configuration
    directory, so regardless of which port boots first they'll get the
    same UEFI HTTP configuration.
    If grub2 bootloader is in use, then its configuration will be created
    based on DHCP IP address in the form nn.nn.nn.nn.

    :param task: A TaskManager instance.
    :param http_options: A dictionary with the HTTP configuration
        parameters.
    :param template: The HTTP configuration template. If no template is
        given the node specific template will be used.

    """
    LOG.debug("Building UEFI HTTP config for node %s", task.node.uuid)
    if template is None:
        template = deploy_utils.get_pxe_config_template(task.node)

    _ensure_config_dirs_exist(task)

    http_config_file_path = get_http_config_file_path(task.node.uuid)

    # grub bootloader panics with '{}' around any of its tags in its
    # config file. To overcome that 'ROOT' and 'DISK_IDENTIFIER' are enclosed
    # with '(' and ')' in uefi boot mode.
    http_config_root_tag = '(( ROOT ))'
    http_config_disk_ident = '(( DISK_IDENTIFIER ))'

    params = {'http_options': http_options,
              'ROOT': http_config_root_tag,
              'DISK_IDENTIFIER': http_config_disk_ident}
    http_config = utils.render_template(template, params)
    utils.write_to_file(http_config_file_path, http_config)

    # Always write the mac addresses
    _link_mac_http_configs(task)
    try:
        _link_ip_address_http_configs(task)
    # NOTE(TheJulia): The IP address support will fail if the
    # dhcp_provider interface is set to none. This will result
    # in the MAC addresses and DHCP files being written, and
    # we can remove IP address creation for the grub use.
    except exception.FailedToGetIPAddressOnPort as e:
        if CONF.dhcp.dhcp_provider != 'none':
            with excutils.save_and_reraise_exception():
                LOG.error('Unable to create boot config, IP address '
                          'was unable to be retrieved. %(error)s',
                          {'error': e})


def clean_up_http_config(task):
    """Clean up the HTTP environment for the task's node.

    :param task: A TaskManager instance.

    """
    LOG.debug("Cleaning up HTTP config for node %s", task.node.uuid)
    api = dhcp_factory.DHCPFactory().provider
    ip_addrs = api.get_ip_addresses(task)
    for port_ip_address in ip_addrs:
        ironic_utils.unlink_without_raise(
            _get_http_ip_address_path(port_ip_address))

    for port in task.ports:
        # Grub2 MAC address based confiuration
        ironic_utils.unlink_without_raise(
            _get_http_grub_mac_path(port.address))
    utils.rmtree_without_raise(
        os.path.join(get_http_boot_dir(), task.node.uuid))


def clean_up_http_env(task, images_info):
    """Cleanup HTTP environment of all the images in images_info.

    Cleans up the HTTP environment for the mentioned images in
    images_info.

    :param task: a TaskManager object
    :param images_info: A dictionary of images whose keys are the image names
        to be cleaned up (kernel, ramdisk, etc) and values are a tuple of
        identifier and absolute path.
    """
    for label in images_info:
        path = images_info[label][1]
        ironic_utils.unlink_without_raise(path)

    clean_up_http_config(task)
    TFTPImageCache().clean_up()


def get_http_path_prefix():
    """Adds trailing slash (if needed) necessary for path-prefix

    :return: CONF.deploy.http_root ensured to have a trailing slash
    """
    return os.path.join(CONF.deploy.http_root, '')


def get_path_relative_to_http_root(file_path):
    """Return file relative path to CONF.deploy.http_root

    :param file_path: full file path to be made relative path.
    :returns: The path relative to CONF.deploy.http_root
    """
    return os.path.relpath(file_path, get_http_path_prefix())


def parse_driver_info(node, mode='deploy'):
    """Gets the driver specific Node deployment info.

    This method validates whether the 'driver_info' property of the
    supplied node contains the required information for this driver to
    deploy images to, or rescue, the node.

    :param node: a single Node.
    :param mode: Label indicating a deploy or rescue operation being
                 carried out on the node. Supported values are
                 'deploy' and 'rescue'. Defaults to 'deploy', indicating
                 deploy operation is being carried out.
    :returns: A dict with the driver_info values.
    :raises: MissingParameterValue
    """
    info = node.driver_info

    params_to_check = KERNEL_RAMDISK_LABELS[mode]

    d_info = {k: info.get(k) for k in params_to_check}
    if not any(d_info.values()):
        # NOTE(dtantsur): avoid situation when e.g. deploy_kernel comes from
        # driver_info but deploy_ramdisk comes from configuration, since it's
        # a sign of a potential operator's mistake.
        d_info = {k: getattr(CONF.conductor, k) for k in params_to_check}
    error_msg = _("Cannot validate HTTP bootloader. Some parameters were"
                  " missing in node's driver_info and configuration")
    deploy_utils.check_for_missing_params(d_info, error_msg)
    return d_info


def get_instance_image_info(task):
    """Generate the paths for UEFI HTTP files for instance related images.

    This method generates the paths for instance kernel and
    instance ramdisk. This method also updates the node, so caller should
    already have a non-shared lock on the node.

    :param task: A TaskManager instance containing node and context.
    :returns: a dictionary whose keys are the names of the images (kernel,
        ramdisk) and values are the absolute paths of them. If it's a whole
        disk image or node is configured for localboot,
        it returns an empty dictionary.
    """
    ctx = task.context
    node = task.node
    image_info = {}
    # NOTE(pas-ha) do not report image kernel and ramdisk for
    # local boot or whole disk images so that they are not cached
    if (node.driver_internal_info.get('is_whole_disk_image')
            or deploy_utils.get_boot_option(node) == 'local'):
            return image_info
    root_dir = get_http_boot_dir()
    i_info = node.instance_info
    labels = ('kernel', 'ramdisk')
    d_info = deploy_utils.get_image_instance_info(node)
    if not (i_info.get('kernel') and i_info.get('ramdisk')):
        glance_service = service.GlanceImageService(context=ctx)
        iproperties = glance_service.show(d_info['image_source'])['properties']
        for label in labels:
            i_info[label] = str(iproperties[label + '_id'])
        node.instance_info = i_info
        node.save()

    for label in labels:
        image_info[label] = (
            i_info[label],
            os.path.join(root_dir, node.uuid, label)
        )

    return image_info


def get_image_info(node, mode='deploy'):
    """Generate the paths for UEFI HTTP files for deploy or rescue images.

    This method generates the paths for the deploy (or rescue) kernel and
    deploy (or rescue) ramdisk.

    :param node: a node object
    :param mode: Label indicating a deploy or rescue operation being
        carried out on the node. Supported values are 'deploy' and 'rescue'.
        Defaults to 'deploy', indicating deploy operation is being carried out.
    :returns: a dictionary whose keys are the names of the images
        (deploy_kernel, deploy_ramdisk, or rescue_kernel, rescue_ramdisk) and
        values are the absolute paths of them.
    :raises: MissingParameterValue, if deploy_kernel/deploy_ramdisk or
        rescue_kernel/rescue_ramdisk is missing in node's driver_info.
    """
    d_info = parse_driver_info(node, mode=mode)

    return get_kernel_ramdisk_info(node, d_info, mode=mode)


def build_deploy_http_options(task, http_info, mode='deploy'):
    http_opts = {}
    kernel_label = '%s_kernel' % mode
    ramdisk_label = '%s_ramdisk' % mode
    for label, option in ((kernel_label, 'deployment_aki_path'),
                          (ramdisk_label, 'deployment_ari_path')):
        http_opts[option] = get_path_relative_to_http_root(http_info[label][1])
    return http_opts


def build_instance_http_options(task, http_info):
    http_opts = {}
    for label, option in (('kernel', 'aki_path'),
                          ('ramdisk', 'ari_path')):
        if label in http_info:
            http_opts[option] = get_path_relative_to_http_root(
                http_info[label][1])

    http_opts.setdefault('aki_path', 'no_kernel')
    http_opts.setdefault('ari_path', 'no_ramdisk')

    i_info = task.node.instance_info
    try:
        http_opts['ramdisk_opts'] = i_info['ramdisk_kernel_arguments']
    except KeyError:
        pass
    return http_opts


def build_extra_http_options(node):
    # Enable debug in IPA according to CONF.debug if it was not
    # specified yet
    http_append_params = CONF.pxe.kernel_append_params
    if CONF.debug and 'ipa-debug' not in http_append_params:
        http_append_params += ' ipa-debug=1'
    http_server_url = '/'.join([CONF.deploy.http_root, node.uuid])
    return {'kernel_append_params': http_append_params,
            'http_server': http_server_url,
            'ipxe_timeout': CONF.pxe.ipxe_timeout * 1000}


def build_http_config_options(task, http_info, service=False):
    """Build the UEFI HTTP config options for a node

    This method builds the UEFI HTTP boot options for a node,
    given all the required parameters.

    The options should then be passed to http_utils.create_http_config to
    create the actual config files.

    :param task: A TaskManager object
                    http_info[label][1])
    :param http_info: a dict of values to set on the configuration file
    :param service: if True, build "service mode" http config for netboot-ed
        user image and skip adding deployment image kernel and ramdisk info
        to HTTP options.
    :returns: A dictionary of pxe options to be used in the pxe bootfile
        template.
    """
    node = task.node
    mode = deploy_utils.rescue_or_deploy_mode(node)
    if service:
        http_options = {}
    else:
        http_options = build_deploy_http_options(task, http_info, mode=mode)

    # NOTE(pas-ha) we still must always add user image kernel and ramdisk
    # info as later during switching PXE config to service mode the
    # template will not be regenerated anew, but instead edited as-is.
    # This can be changed later if/when switching PXE config will also use
    # proper templating instead of editing existing files on disk.
    http_options.update(build_instance_http_options(task, http_info))

    http_options.update(build_extra_http_options(task.node))

    return http_options


def build_service_http_config(task, instance_image_info, root_uuid_or_disk_id,
                              ramdisk_boot=False):
    node = task.node
    http_config_path = get_http_config_file_path(node.uuid)
    # NOTE(pas-ha) if it is takeover of ACTIVE node or node performing
    # unrescue operation, first ensure that basic PXE configs and links
    # are in place before switching pxe config
    # NOTE(TheJulia): Also consider deploying a valid state to go ahead
    # and check things before continuing, as otherwise deployments can
    # fail if the agent was booted outside the direct actions of the
    # boot interface.
    if (node.provision_state in [states.ACTIVE, states.UNRESCUING,
                                 states.DEPLOYING]
            and not os.path.isfile(http_config_path)):
        http_options = build_http_config_options(task, instance_image_info,
                                                 service=True)
        http_config_template = deploy_utils.get_pxe_config_template(node)
        create_http_config(task, http_options, http_config_template)
    iwdi = node.driver_internal_info.get('is_whole_disk_image')

    deploy_utils.switch_pxe_config(
        http_config_path, root_uuid_or_disk_id,
        boot_mode_utils.get_boot_mode(node),
        iwdi, deploy_utils.is_trusted_boot_requested(node),
        deploy_utils.is_iscsi_boot(task), ramdisk_boot,
        ipxe_enabled=False)


def prepare_instance_http_config(task, image_info, iscsi_boot=False,
                                 ramdisk_boot=False):
    """Prepares the config file for UEFI HTTP boot

    :param task: a task from TaskManager.
    :param image_info: a dict of values of instance image
                       metadata to set on the configuration file.
    :param iscsi_boot: if boot is from an iSCSI volume or not.
    :param ramdisk_boot: if the boot is to a ramdisk configuration.
    :returns: None
    """
    node = task.node
    http_config_path = get_http_config_file_path(node.uuid)
    if not os.path.isfile(http_config_path):
        http_options = build_http_config_options(
            task, image_info, service=ramdisk_boot)
        http_config_template = (
            deploy_utils.get_pxe_config_template(node))
        create_http_config(
            task, http_options, http_config_template)
    deploy_utils.switch_pxe_config(
        http_config_path, None,
        boot_mode_utils.get_boot_mode(node), False,
        iscsi_boot=iscsi_boot, ramdisk_boot=ramdisk_boot,
        ipxe_enabled=False)


@image_cache.cleanup(priority=25)
class TFTPImageCache(image_cache.ImageCache):
    def __init__(self):
        master_path = CONF.pxe.tftp_master_path or None
        super(TFTPImageCache, self).__init__(
            master_path,
            # MiB -> B
            cache_size=CONF.pxe.image_cache_size * 1024 * 1024,
            # min -> sec
            cache_ttl=CONF.pxe.image_cache_ttl * 60)


def cache_ramdisk_kernel(task, http_info):
    """Fetch the necessary kernels and ramdisks for the instance."""
    ctx = task.context
    node = task.node
    path = os.path.join(get_http_boot_dir(), node.uuid)
    fileutils.ensure_tree(path)
    LOG.debug("Fetching necessary kernel and ramdisk for node %s",
              node.uuid)
    deploy_utils.fetch_images(ctx, TFTPImageCache(), list(http_info.values()),
                              CONF.force_raw_images)


def is_http_boot_requested(node):
    """Checks if UEFI HTTP Boot is requested"""
    http_boot_requested = (
        str(node.driver_info.get('enable_uefi_httpboot', 'false')).lower())
    return http_boot_requested == 'true'
