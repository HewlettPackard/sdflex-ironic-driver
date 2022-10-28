# Copyright 2014 Rackspace, Inc.
# Copyright 2015 Red Hat, Inc.
# All Rights Reserved.
#
# Copyright 2020-2022 Hewlett Packard Enterprise Development LP
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
from oslo_utils import excutils
from oslo_utils import timeutils

from ironic.common import states
from ironic.common import utils
from ironic.conductor import utils as manager_utils

from ironic.common import boot_devices
from ironic.common import exception
from ironic.common.i18n import _
from ironic.conf import CONF
from ironic.drivers.modules import agent
from ironic.drivers.modules import agent_base
from ironic.drivers.modules import agent_client
from ironic.drivers.modules import deploy_utils

from ironic.drivers.modules import boot_mode_utils


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
        self.tear_down_agent(task)
        task.process_event('done')
        LOG.info('Deployment to node %s done', task.node.uuid)

    @METRICS.timer('HeartbeatMixin.heartbeat')
    def heartbeat(self, task, callback_url, agent_version,
                  agent_verify_ca=None, agent_status=None,
                  agent_status_message=None):
        """Process a heartbeat.

        Check's if boot from volume is true then it calls
        reboot_to_instance_bfpv if not it will call normal heartbeat
        :param task: task to work with.
        :param callback_url: agent HTTP API URL.
        :param agent_version: The version of the agent that is heartbeating
        :param agent_verify_ca: TLS certificate for the agent.
        :param agent_status: Status of the heartbeating agent
        :param agent_status_message: Status message that describes the
                                     agent_status
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
                if agent_verify_ca:
                    driver_internal_info['agent_verify_ca'] = agent_verify_ca
                if agent_status:
                    driver_internal_info['agent_status'] = agent_status
                if agent_status_message:
                    driver_internal_info['agent_status_message'] = \
                        agent_status_message
                node.driver_internal_info = driver_internal_info
                node.save()
                self.reboot_to_instance_bfpv(task)
        else:
            super(SDflexHeartbeatMixin, self).heartbeat(
                task, callback_url, agent_version,
                agent_verify_ca=agent_verify_ca, agent_status=agent_status,
                agent_status_message=agent_status_message)

    @METRICS.timer('AgentDeployMixin.configure_local_boot')
    def configure_local_boot(self, task, root_uuid=None,
                             efi_system_part_uuid=None,
                             prep_boot_part_uuid=None):

        """Helper method to configure local boot on the node.

        This method triggers bootloader installation on the node.
        This method creates a boot entry and sets the node to boot from
        FC volume.

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
        LOG.debug('Creating the boot entry for node %(node)s',
                  {'node': node.uuid})
        client = agent_client.get_client(task)
        result = client.install_bootloader(
            node, root_uuid=root_uuid,
            efi_system_part_uuid=efi_system_part_uuid,
            prep_boot_part_uuid=prep_boot_part_uuid,
            target_boot_mode=target_boot_mode)
        if result['command_status'] == 'FAILED':
            msg = (_("Failed to create the boot entry when deploying node "
                     "%(node)s from pre-provisioned volume.Error: %(error)s") %
                   {'node': node.uuid, 'error': result['command_error']})
            agent_base.log_and_raise_deployment_error(task, msg)
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
            agent_base.log_and_raise_deployment_error(task, msg, exc=e)

        LOG.info('Boot entry is create and node will boot from '
                 'pre-provisioned volume for node %s', node.uuid)


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
        """Prepare the deployment environment for this node.

        We have copied this method from upstream. Actual upstream function
        as _update_instance_info which actually which builds instance_info
        necessary for deploying to a node based on the image_source which
        we include in the instance_info. As we don't want to give image_source
        we have removed that function and occurance of "_update_instance_info"
        """
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

            # Powering off node to setup networking for port and
            # ensure that the state is reset if it is inadvertently
            # on for any unknown reason.
            manager_utils.node_power_action(task, states.POWER_OFF)

            power_state_to_restore = (
                manager_utils.power_on_node_if_needed(task))

            task.driver.network.unconfigure_tenant_networks(task)
            task.driver.network.add_provisioning_network(task)
            manager_utils.restore_power_state_if_needed(
                task, power_state_to_restore)

            # Signal to storage driver to attach volumes
            # Leaving the below line as a place holder for Cinder attach volume
            # We are using NOOP storage interface for this BFPV. It is
            # automatically returns False in this case.
            task.driver.storage.attach_volumes(task)
        if CONF.agent.manage_agent_boot:
            deploy_opts = deploy_utils.build_agent_options(node)
            task.driver.boot.prepare_ramdisk(task, deploy_opts)
