# Copyright 2014 Rackspace, Inc.
# Copyright 2015 Red Hat, Inc.
# All Rights Reserved.
#
# Copyright 2020 Hewlett Packard Enterprise Development LP
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
# Some of the methods/code snippets in this file are owned by Rackspace, Inc
# Some of the methods/code snippets in this file are owned by Red Hat, Inc

from ironic_lib import metrics_utils
from oslo_log import log
from oslo_utils import timeutils
from oslo_utils import strutils
import retrying

from ironic.common.glance_service import service_utils
from ironic.common import images
from ironic.common import raid
from ironic.common import states
from ironic.common import utils
from ironic.conductor import task_manager
from ironic.conductor import utils as manager_utils
from ironic.drivers import base

from ironic.common import boot_devices
from ironic.common import dhcp_factory
from ironic.common import exception 
from ironic.common.i18n import _
from ironic.conf import CONF
from ironic.drivers.modules import agent
from ironic.drivers.modules import agent_base
from ironic.drivers.modules import deploy_utils

from ironic.common import image_service
from ironic.conductor import steps as conductor_steps
from ironic.drivers.modules import agent_client
from ironic.drivers.modules import boot_mode_utils
from ironic.drivers import utils as driver_utils
from ironic import objects


LOG = log.getLogger(__name__)
METRICS = metrics_utils.get_metrics_logger(__name__)


class SDflexHeartbeatMixin(agent_base.HeartbeatMixin):

    def reboot_to_instance_bfpv(self, task):
        task.process_event('resume')
        node = task.node
        self.prepare_instance_to_boot(task, None, None, None)
        if CONF.agent.image_download_source == 'http':
            deploy_utils.remove_http_instance_symlink(task.node.uuid)
        LOG.debug('Rebooting node %s to instance', node.uuid)
        self.reboot_and_finish_deploy(task)
        LOG.info('Deployment to node %s done', task.node.uuid)

    @METRICS.timer('HeartbeatMixin.heartbeat')
    def heartbeat(self, task, callback_url, agent_version,  agent_verify_ca=None):
        """Process a heartbeat.

        Check's if boot from volume is true then it calls
        reboot_to_instance_bfpv if not it will call normal heartbeat
        :param task: task to work with.
        :param callback_url: agent HTTP API URL.
        :param agent_version: The version of the agent that is heartbeating
        """
        node = task.node
        try:
            task.upgrade_lock()
        except exception.NodeLocked:
            LOG.warning('Node %s is currently locked, skipping heartbeat '
                        'processing (will retry on the next heartbeat)',
                        task.node.uuid)
            return
        LOG.debug('Heartbeat from node %s', node.uuid)

        # bfpv is shortcut for  "boot from pre-provisioned volume"

        bfpv = str(task.node.driver_info.get('bfpv', 'false')).lower()
        bfpv_deploy_started = str(task.node.driver_internal_info.get(
            'bfpv_started', 'false')).lower()
        if bfpv == 'true':
            if bfpv_deploy_started == 'false':
                node = task.node
                driver_internal_info = node.driver_internal_info
                driver_internal_info['agent_url'] = callback_url
                driver_internal_info['agent_version'] = agent_version
                driver_internal_info['bfpv_started'] = True
                driver_internal_info['agent_last_heartbeat'] = str(
                    timeutils.utcnow().isoformat())
                node.driver_internal_info = driver_internal_info
                node.save()
                self.reboot_to_instance_bfpv(task)
        else:
            super(SDflexHeartbeatMixin, self).heartbeat(
                task, callback_url, agent_version,
                agent_verify_ca=agent_verify_ca)

    @METRICS.timer('AgentDeployMixin.configure_local_boot')
    def configure_local_boot(self, task, root_uuid=None,
                             efi_system_part_uuid=None,
                             prep_boot_part_uuid=None):
        """Helper method to configure local boot on the node.
        This method triggers bootloader installation on the node.
        On successful installation of bootloader, this method sets the
        node to boot from disk.
        :param task: a TaskManager object containing the node
        :param root_uuid: The UUID of the root partition. This is used
            for identifying the partition which contains the image deployed
            or None in case of whole disk images which we expect to already
            have a bootloader installed.
        :param efi_system_part_uuid: The UUID of the efi system partition.
            This is used only in uefi boot mode.
        :param prep_boot_part_uuid: The UUID of the PReP Boot partition.
            This is used only for booting ppc64* hardware.
        :raises: InstanceDeployFailure if bootloader installation failed or
            on encountering error while setting the boot device on the node.
        """
        node = task.node
        # Almost never taken into account on agent side, just used for softraid
        # Can be useful with whole_disk_images
        target_boot_mode = boot_mode_utils.get_boot_mode(task.node)
        LOG.debug('Configuring local boot for node %s', node.uuid)

        # If the target RAID configuration is set to 'software' for the
        # 'controller', we need to trigger the installation of grub on
        # the holder disks of the desired Software RAID.
        internal_info = node.driver_internal_info
        raid_config = node.target_raid_config
        logical_disks = raid_config.get('logical_disks', [])
        software_raid = False
#         for logical_disk in logical_disks:
#             if logical_disk.get('controller') == 'software':
#                 LOG.debug('Node %s has a Software RAID configuration',
#                           node.uuid)
#                 software_raid = True
#                 break
# 
#         # For software RAID try to get the UUID of the root fs from the
#         # image's metadata (via Glance). Fall back to the driver internal
#         # info in case it is not available (e.g. not set or there's no Glance).
#         if software_raid:
#             image_source = node.instance_info.get('image_source')
#             try:
#                 context = task.context
#                 context.is_admin = True
#                 glance = image_service.GlanceImageService(
#                     context=context)
#                 image_info = glance.show(image_source)
#                 image_properties = image_info.get('properties')
#                 root_uuid = image_properties['rootfs_uuid']
#                 LOG.debug('Got rootfs_uuid from Glance: %s '
#                           '(node %s)', root_uuid, node.uuid)
#             except Exception as e:
#                 LOG.warning('Could not get \'rootfs_uuid\' property for '
#                             'image %(image)s from Glance for node %(node)s. '
#                             '%(cls)s: %(error)s.',
#                             {'image': image_source, 'node': node.uuid,
#                              'cls': e.__class__.__name__, 'error': e})
#                 root_uuid = internal_info.get('root_uuid_or_disk_id')
#                 LOG.debug('Got rootfs_uuid from driver internal info: '
#                           '%s (node %s)', root_uuid, node.uuid)


        LOG.debug('Installing the bootloader for node %(node)s on '
                      'partition %(part)s, EFI system partition %(efi)s',
                      {'node': node.uuid, 'part': root_uuid,
                       'efi': efi_system_part_uuid})
        result = self._client.install_bootloader(
            node, root_uuid=root_uuid,
            efi_system_part_uuid=efi_system_part_uuid,
            prep_boot_part_uuid=prep_boot_part_uuid,
            target_boot_mode=target_boot_mode,
            software_raid=software_raid
        )
        if result['command_status'] == 'FAILED':
            LOG.info('Could not install bootloader for whole disk '
                     'image for node %(node)s, Error: %(error)s"',
                     {'node': node.uuid,
                      'error': result['command_error']})
            log_and_raise_deployment_error(task, msg)
            return

        try:
            persistent = True
            if node.driver_info.get('force_persistent_boot_device',
                                    'Default') == 'Never':
                persistent = False
            deploy_utils.try_set_boot_device(task, boot_devices.DISK,
                                             persistent=persistent)
        except Exception as e:
            msg = (_("Failed to change the boot device to %(boot_dev)s "
                     "when deploying node %(node)s. Error: %(error)s") %
                   {'boot_dev': boot_devices.DISK, 'node': node.uuid,
                    'error': e})
            log_and_raise_deployment_error(task, msg, exc=e)

        LOG.info('Local boot successfully configured for node %s', node.uuid)

    @METRICS.timer('AgentDeployMixin.prepare_instance_to_boot')
    def prepare_instance_to_boot(self, task, root_uuid, efi_sys_uuid,
                                 prep_boot_part_uuid=None):
        """Prepares instance to boot.
        :param task: a TaskManager object containing the node
        :param root_uuid: the UUID for root partition
        :param efi_sys_uuid: the UUID for the efi partition
        :raises: InvalidState if fails to prepare instance
        """
        node = task.node
        if deploy_utils.get_boot_option(node) == "local":
            # Install the boot loader
            self.configure_local_boot(
                task, root_uuid=root_uuid,
                efi_system_part_uuid=efi_sys_uuid,
                prep_boot_part_uuid=prep_boot_part_uuid)
        try:
            task.driver.boot.prepare_instance(task)
        except Exception as e:
            LOG.error('Preparing instance for booting failed for instance '
                      '%(instance)s. %(cls)s: %(error)s',
                      {'instance': node.instance_uuid,
                       'cls': e.__class__.__name__, 'error': e})
            msg = _('Failed to prepare instance for booting')
            log_and_raise_deployment_error(task, msg, exc=e)

    @METRICS.timer('AgentDeployMixin.reboot_and_finish_deploy')
    def reboot_and_finish_deploy(self, task):
        """Helper method to trigger reboot on the node and finish deploy.
        This method initiates a reboot on the node. On success, it
        marks the deploy as complete. On failure, it logs the error
        and marks deploy as failure.
        :param task: a TaskManager object containing the node
        :raises: InstanceDeployFailure, if node reboot failed.
        """
        wait = CONF.agent.post_deploy_get_power_state_retry_interval * 1000
        attempts = CONF.agent.post_deploy_get_power_state_retries + 1

        @retrying.retry(
            stop_max_attempt_number=attempts,
            retry_on_result=lambda state: state != states.POWER_OFF,
            wait_fixed=wait
        )
        def _wait_until_powered_off(task):
            return task.driver.power.get_power_state(task)

        node = task.node

        if CONF.agent.deploy_logs_collect == 'always':
            driver_utils.collect_ramdisk_logs(node)

        # Whether ironic should power off the node via out-of-band or
        # in-band methods
        oob_power_off = strutils.bool_from_string(
            node.driver_info.get('deploy_forces_oob_reboot', False))

        try:
            if not oob_power_off:
                try:
                    self._client.power_off(node)
                except Exception as e:
                    LOG.warning('Failed to soft power off node %(node_uuid)s. '
                                '%(cls)s: %(error)s',
                                {'node_uuid': node.uuid,
                                 'cls': e.__class__.__name__, 'error': e},
                                exc_info=not isinstance(
                                    e, exception.IronicException))

                # NOTE(dtantsur): in rare cases it may happen that the power
                # off request comes through but we never receive the response.
                # Check the power state before trying to force off.
                try:
                    _wait_until_powered_off(task)
                except Exception:
                    LOG.warning('Failed to soft power off node %(node_uuid)s '
                                'in at least %(timeout)d seconds. Forcing '
                                'hard power off and proceeding.',
                                {'node_uuid': node.uuid,
                                 'timeout': (wait * (attempts - 1)) / 1000})
                    manager_utils.node_power_action(task, states.POWER_OFF)
            else:
                # Flush the file system prior to hard rebooting the node
                result = self._client.sync(node)
                error = result.get('faultstring')
                if error:
                    if 'Unknown command' in error:
                        error = _('The version of the IPA ramdisk used in '
                                  'the deployment do not support the '
                                  'command "sync"')
                    LOG.warning(
                        'Failed to flush the file system prior to hard '
                        'rebooting the node %(node)s. Error: %(error)s',
                        {'node': node.uuid, 'error': error})

                manager_utils.node_power_action(task, states.POWER_OFF)
        except Exception as e:
            msg = (_('Error rebooting node %(node)s after deploy. '
                     '%(cls)s: %(error)s') %
                   {'node': node.uuid, 'cls': e.__class__.__name__,
                    'error': e})
            log_and_raise_deployment_error(task, msg, exc=e)

        try:
            with manager_utils.power_state_for_network_configuration(task):
                task.driver.network.remove_provisioning_network(task)
                task.driver.network.configure_tenant_networks(task)
            manager_utils.node_power_action(task, states.POWER_ON)
        except Exception as e:
            msg = (_('Error rebooting node %(node)s after deploy. '
                     '%(cls)s: %(error)s') %
                   {'node': node.uuid, 'cls': e.__class__.__name__,
                    'error': e})
            # NOTE(mgoddard): Don't collect logs since the node has been
            # powered off.
            log_and_raise_deployment_error(task, msg, collect_logs=False,
                                           exc=e)

        task.process_event('done')

class SDFlexAgentDeploy(SDflexHeartbeatMixin, agent.AgentDeploy):

    def __init__(self):
        """Initialize the sdflex-redfish deploy Interface.

        :raises: DriverLoadError if the driver can't be loaded due to missing
                 dependencies
        """

        super(SDFlexAgentDeploy, self).__init__()

    def validate(self, task):
        """Validate the driver-specific Node deployment info.

        This method validates whether the properties of the supplied node
        contain the required information for this driver to deploy images to
        the node.

        :param task: a TaskManager instance
        :raises: InvalidParameterValue, if any of the parameters have invalid
            value.
        """
        driver_info = task.node.driver_info
        if 'bfpv' in driver_info:
            bfpv_value = str(driver_info['bfpv']).lower()
            if bfpv_value not in ('true', 'false'):
                raise exception.InvalidParameterValue(_(
                    "For Boot from Pre-Provisioned Volume the 'bfpv' value "
                    "should be a Boolean value. '%(bfpv_inputed)s'"
                    " is not a valid value for 'bfpv'.")
                    % {'bfpv_inputed': driver_info['bfpv']})

    def prepare(self, task):
        def _update_instance_info():
            node.instance_info = (
                deploy_utils.build_instance_info_for_deploy(task))
            node.save()

        node = task.node
        deploy_utils.populate_storage_driver_internal_info(task)
        if node.provision_state == states.DEPLOYING:
            # Validate network interface to ensure that it supports boot
            # options configured on the node.
            try:
                task.driver.network.validate(task)
            except exception.InvalidParameterValue:
                # For 'neutron' network interface validation will fail
                # if node is using 'netboot' boot option while provisioning
                # a whole disk image. Updating 'boot_option' in node's
                # 'instance_info' to 'local for backward compatibility.
                # TODO(stendulker): Fail here once the default boot
                # option is local.
                # NOTE(TheJulia): Fixing the default boot mode only
                # masks the failure as the lack of a user definition
                # can be perceived as both an invalid configuration and
                # reliance upon the default configuration. The reality
                # being that in most scenarios, users do not want network
                # booting, so the changed default should be valid.
                with excutils.save_and_reraise_exception(reraise=False) as ctx:
                    instance_info = node.instance_info
                    capabilities = utils.parse_instance_info_capabilities(node)
                    if 'boot_option' not in capabilities:
                        capabilities['boot_option'] = 'local'
                        instance_info['capabilities'] = capabilities
                        node.instance_info = instance_info
                        node.save()
                        # Re-validate the network interface
                        task.driver.network.validate(task)
                    else:
                        ctx.reraise = True
            # Determine if this is a fast track sequence
            fast_track_deploy = manager_utils.is_fast_track(task)
            if fast_track_deploy:
                # The agent has already recently checked in and we are
                # configured to take that as an indicator that we can
                # skip ahead.
                LOG.debug('The agent for node %(node)s has recently checked '
                          'in, and the node power will remain unmodified.',
                          {'node': task.node.uuid})
            else:
                # Powering off node to setup networking for port and
                # ensure that the state is reset if it is inadvertently
                # on for any unknown reason.
                manager_utils.node_power_action(task, states.POWER_OFF)
            if task.driver.storage.should_write_image(task):
                # NOTE(vdrok): in case of rebuild, we have tenant network
                # already configured, unbind tenant ports if present
                if not fast_track_deploy:
                    power_state_to_restore = (
                        manager_utils.power_on_node_if_needed(task))

                task.driver.network.unconfigure_tenant_networks(task)
                task.driver.network.add_provisioning_network(task)
                if not fast_track_deploy:
                    manager_utils.restore_power_state_if_needed(
                        task, power_state_to_restore)
            # Signal to storage driver to attach volumes
            task.driver.storage.attach_volumes(task)
            if (not task.driver.storage.should_write_image(task)
                or fast_track_deploy):
                # We have nothing else to do as this is handled in the
                # backend storage system, and we can return to the caller
                # as we do not need to boot the agent to deploy.
                # Alternatively, we could be in a fast track deployment
                # and again, we should have nothing to do here.
                return
        if node.provision_state in (states.ACTIVE, states.UNRESCUING):
            # Call is due to conductor takeover
            task.driver.boot.prepare_instance(task)
        elif node.provision_state != states.ADOPTING:

            if CONF.agent.manage_agent_boot:
                deploy_opts = deploy_utils.build_agent_options(node)
                task.driver.boot.prepare_ramdisk(task, deploy_opts)