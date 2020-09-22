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

from ironic.common import exception
from ironic.common.i18n import _
from ironic.conf import CONF
from ironic.drivers.modules import agent
from ironic.drivers.modules import agent_base
from ironic.drivers.modules import deploy_utils

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
        task.process_event('done')
        LOG.info('Deployment to node %s done', task.node.uuid)

    @METRICS.timer('HeartbeatMixin.heartbeat')
    def heartbeat(self, task, callback_url, agent_version):
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
            super(SDflexHeartbeatMixin, self).heartbeat(task, callback_url,
                                                        agent_version)


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
        super(SDFlexAgentDeploy, self).validate(task)
