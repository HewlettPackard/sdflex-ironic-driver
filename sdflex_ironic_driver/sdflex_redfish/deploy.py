from oslo_log import log
from ironic_lib import metrics_utils
from oslo_utils import strutils
from oslo_utils import timeutils
import retrying

from ironic.common import exception
from ironic.common import states
from ironic.conductor import task_manager
from ironic.conf import CONF
from ironic.drivers import utils as driver_utils
from ironic.conductor import utils as manager_utils
from ironic.drivers.modules import deploy_utils
from ironic.drivers.modules import agent
from ironic.drivers.modules import agent_base

LOG = log.getLogger(__name__)
METRICS = metrics_utils.get_metrics_logger(__name__)


class SDflexHeartbeatMixin(agent_base.HeartbeatMixin):

    @METRICS.timer('log_and_raise_deployment_error')
    def log_and_raise_deployment_error(task, msg, collect_logs=True, exc=None):
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
        LOG.info('Deployment to node %s done', task.node.uuid)
 
    def reboot_to_instance_bfv(self, task):
        task.process_event('resume')
        node = task.node
        iwdi = task.node.driver_internal_info.get('is_whole_disk_image')
        cpu_arch = task.node.properties.get('cpu_arch')
        self.prepare_instance_to_boot(task, None, None, None)
        if CONF.agent.image_download_source == 'http':
            deploy_utils.remove_http_instance_symlink(task.node.uuid)
        LOG.debug('Rebooting node %s to instance', node.uuid)
        self.reboot_and_finish_deploy(task)


    @METRICS.timer('HeartbeatMixin.heartbeat')
    def heartbeat(self, task, callback_url, agent_version):
        """Process a heartbeat.

        :param task: task to work with.
        :param callback_url: agent HTTP API URL.
        :param agent_version: The version of the agent that is heartbeating
        """
        try:
            task.upgrade_lock()
        except exception.NodeLocked:
            LOG.warning('Node %s is currently locked, skipping heartbeat '
                        'processing (will retry on the next heartbeat)',
                        task.node.uuid)
            return
        # NOTE(pas-ha) immediately skip the rest if nothing to do
        bfv = str(task.node.driver_info.get('bfv', 'false')).lower()
        bfpv_deploy_started = str(task.node.driver_internal_info.get('bfpv_started', 'false')).lower()
        if bfv == 'true':
            if bfpv_deploy_started == 'false':
                node = task.node
                #LOG.debug('Heartbeat from node %s', node.uuid)
                driver_internal_info = node.driver_internal_info
                driver_internal_info['agent_url'] = callback_url
                driver_internal_info['agent_version'] = agent_version
                driver_internal_info['bfpv_started'] = True
                # Record the last heartbeat event time in UTC, so we can make
                # decisions about it later. Can be decoded to datetime object with:
                # datetime.datetime.strptime(var, "%Y-%m-%d %H:%M:%S.%f")
                driver_internal_info['agent_last_heartbeat'] = str(
                    timeutils.utcnow().isoformat())
                node.driver_internal_info = driver_internal_info
                node.save()
                self.reboot_to_instance_bfv(task)
        else:
            super(SDflexHeartbeatMixin, self).heartbeat(task, callback_url, agent_version)
        """
        if (task.node.provision_state not in self.heartbeat_allowed_states
                and not manager_utils.fast_track_able(task)):
            LOG.error('Heartbeat from node %(node)s in unsupported '
                      'provision state %(state)s, not taking any action.',
                      {'node': task.node.uuid,
                       'state': task.node.provision_state})
            return

        try:
            task.upgrade_lock()
        except exception.NodeLocked:
            LOG.warning('Node %s is currently locked, skipping heartbeat '
                        'processing (will retry on the next heartbeat)',
                        task.node.uuid)
            return

        node = task.node
        LOG.debug('Heartbeat from node %s', node.uuid)
        driver_internal_info = node.driver_internal_info
        driver_internal_info['agent_url'] = callback_url
        driver_internal_info['agent_version'] = agent_version
        # Record the last heartbeat event time in UTC, so we can make
        # decisions about it later. Can be decoded to datetime object with:
        # datetime.datetime.strptime(var, "%Y-%m-%d %H:%M:%S.%f")
        driver_internal_info['agent_last_heartbeat'] = str(
            timeutils.utcnow().isoformat())
        node.driver_internal_info = driver_internal_info
        node.save()

        if node.provision_state in _HEARTBEAT_RECORD_ONLY:
            # We shouldn't take any additional action. The agent will
            # silently continue to heartbeat to ironic until user initiated
            # state change occurs causing it to match a state below.
            LOG.debug('Heartbeat from %(node)s recorded to identify the '
                      'node as on-line.', {'node': task.node.uuid})
            return
        bfv = str(node.driver_info.get('bfv', 'false')).lower()
        if bfv == 'true':
            self.reboot_to_instance(task)
        else:
            super(SDflexHeartbeatMixin, this).heartbeat()
        """

class SDFlexAgentDeployMixin(SDflexHeartbeatMixin, agent.AgentDeploy):

    @METRICS.timer('SDFlexAgentDeployMixin.reboot_to_instance')
    def reboot_to_instance(self, task):
        super(SDFlexAgentDeployMixin, self).reboot_to_instance(task)


#class SDFlexAgentDeploy(SDFlexAgentDeployMixin):

class SDFlexAgentDeploy(SDflexHeartbeatMixin, agent.AgentDeploy):

    def __init__(self):
        """Initialize the Redfish power interface.
        :raises: DriverLoadError if the driver can't be loaded due to missing
                 dependencies
        """

        super(SDFlexAgentDeploy, self).__init__()
