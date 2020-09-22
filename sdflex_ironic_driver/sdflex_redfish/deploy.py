# Copyright 2014 Rackspace, Inc.
# Copyright 2015 Red Hat, Inc.
# All Rights Reserved.
#
# Copyright 2020 Hewlett Packard Enterprise Development LP
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
# Some of the methods/code snippets in this file are owned by Rackspace, Inc
# Some of the methods/code snippets in this file are owned by Red Hat, Inc

from ironic_lib import metrics_utils
from oslo_log import log
from oslo_utils import strutils
from oslo_utils import timeutils
import retrying

from ironic.common import exception
from ironic.common.i18n import _
from ironic.common import states
from ironic.conductor import utils as manager_utils
from ironic.conf import CONF
from ironic.drivers.modules import agent
from ironic.drivers.modules import agent_base
from ironic.drivers.modules import deploy_utils
from ironic.drivers import utils as driver_utils

LOG = log.getLogger(__name__)
METRICS = metrics_utils.get_metrics_logger(__name__)


class SDflexHeartbeatMixin(agent_base.HeartbeatMixin):

    @METRICS.timer('log_and_raise_deployment_error')
    def log_and_raise_deployment_error(self, task, msg, collect_logs=True,
                                       exc=None):
        """Helper method to log the error and raise exception.

        :param task: a TaskManager instance containing the node to act on.
        :param msg: the message to set in last_error of the node.
        :param collect_logs: Boolean indicating whether to attempt to collect
                             logs from IPA-based ramdisk. Defaults to True.
         Actual log collection is also affected by
         CONF.agent.deploy_logs_collect config option.
        :param exc: Exception that caused the failure.
        """
        log_traceback = (exc is not None
                         and not isinstance(exc, exception.IronicException))
        LOG.error(msg, exc_info=log_traceback)
        deploy_utils.set_failed_state(task, msg, collect_logs=collect_logs)
        raise exception.InstanceDeployFailure(msg)

    def reboot_and_finish_deploy(self, task):
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
                    _wait_until_powered_off(task)
                except Exception as e:
                    LOG.warning('Failed to soft power off node %(node_uuid)s '
                                'in at least %(timeout)d seconds. '
                                '%(cls)s: %(error)s',
                                {'node_uuid': node.uuid,
                                 'timeout': (wait * (attempts - 1)) / 1000,
                                 'cls': e.__class__.__name__, 'error': e},
                                exc_info=not isinstance(
                                    e, exception.IronicException))
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
            self.log_and_raise_deployment_error(task, msg, exc=e)
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
            self.log_and_raise_deployment_error(task, msg, collect_logs=False,
                                                exc=e)
        task.process_event('done')
        LOG.info('Deployment to node %s done', task.node.uuid)

    def reboot_to_instance_bfv(self, task):
        task.process_event('resume')
        node = task.node
        self.prepare_instance_to_boot(task, None, None, None)
        if CONF.agent.image_download_source == 'http':
            deploy_utils.remove_http_instance_symlink(task.node.uuid)
        LOG.debug('Rebooting node %s to instance', node.uuid)
        self.reboot_and_finish_deploy(task)

    @METRICS.timer('HeartbeatMixin.heartbeat')
    def heartbeat(self, task, callback_url, agent_version):
        """Process a heartbeat.

        Check's if boot from volume is true then it calls
        reboot_to_instance_bfv if not it will call normal heartbeat
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

        bfv = str(task.node.driver_info.get('bfv', 'false')).lower()
        bfv_deploy_started = str(
            task.node.driver_internal_info.get('bfv_started', 'false')).lower()
        if bfv == 'true':
            if bfv_deploy_started == 'false':
                node = task.node
                driver_internal_info = node.driver_internal_info
                driver_internal_info['agent_url'] = callback_url
                driver_internal_info['agent_version'] = agent_version
                driver_internal_info['bfv_started'] = True
                driver_internal_info['agent_last_heartbeat'] = str(
                    timeutils.utcnow().isoformat())
                node.driver_internal_info = driver_internal_info
                node.save()
                self.reboot_to_instance_bfv(task)
        else:
            super(SDflexHeartbeatMixin, self).heartbeat(task, callback_url,
                                                        agent_version)


class SDFlexAgentDeploy(SDflexHeartbeatMixin, agent.AgentDeploy):

    def __init__(self):
        """Initialize the Sdflex Redfish Deploy Interface.

        :raises: DriverLoadError if the driver can't be loaded due to missing
                 dependencies
        """

        super(SDFlexAgentDeploy, self).__init__()
