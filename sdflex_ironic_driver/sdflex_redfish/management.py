# Copyright 2017 Red Hat, Inc.
# All Rights Reserved.
# Copyright 2019-2020 Hewlett Packard Enterprise Development LP
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

from ironic_lib import metrics_utils

from oslo_log import log as logging
from oslo_utils import importutils

from ironic.common import exception as ironic_exception
from ironic.conf import CONF
from ironic.drivers import base
from ironic.drivers.modules import agent_base
from ironic.drivers.modules.redfish import management as redfish_management
from ironic.drivers import utils as driver_utils

from sdflex_ironic_driver.sdflex_redfish import firmware_processor

LOG = logging.getLogger(__name__)

METRICS = metrics_utils.get_metrics_logger(__name__)

_FIRMWARE_UPDATE_SUM_ARGSINFO = {
    'url': {
        'description': (
            "The image location for Custom ISO (SPP for SDFlex)."
        ),
        'required': True
    },
    'checksum': {
        'description': (
            "The sha256 checksum of the SPP image file."
        ),
        'required': True
    }
}

sushy = importutils.try_import('sushy')


if sushy:
    redfish_management.BOOT_DEVICE_MAP.update(
        {sushy.BOOT_SOURCE_TARGET_UEFI_HTTP: 'uefi http',
         sushy.BOOT_SOURCE_TARGET_CD: 'cd'})

    redfish_management.BOOT_DEVICE_MAP_REV = {
        v: k for k, v in redfish_management.BOOT_DEVICE_MAP.items()}


def _should_collect_logs(command):
    """Returns boolean to check whether logs need to collected or not."""
    return ((CONF.agent.deploy_logs_collect == 'on_failure'
             and command['command_status'] == 'FAILED')
            or CONF.agent.deploy_logs_collect == 'always')


class SdflexRedfishManagement(redfish_management.RedfishManagement):

    def __init__(self):
        """Initialize the Redfish management interface.

        :raises: DriverLoadError if the driver can't be loaded due to
            missing dependencies
        """
        super(SdflexRedfishManagement, self).__init__()
        if not sushy:
            raise ironic_exception.DriverLoadError(
                driver='sdfelx-redfish',
                reason=_('Unable to import the sushy library'))

    @METRICS.timer('SdflexRedfishManagement.update_firmware_sum')
    @base.clean_step(priority=0, abortable=False,
                     argsinfo=_FIRMWARE_UPDATE_SUM_ARGSINFO)
    def update_firmware_sum(self, task, **kwargs):
        """Updates the firmware using Smart Update Manager (SUM).

        :param task: a TaskManager object.
        :raises: NodeCleaningFailure, on failure to execute of clean step.
        """
        node = task.node
        # The arguments are validated and sent to the SDFlexHardwareManager
        # to perform SUM based firmware update clean step.
        firmware_processor.validate_firmware_image_info(kwargs)

        url = kwargs['url']
        node.clean_step['args']['url'] = url

        step = node.clean_step
        return agent_base.execute_clean_step(task, step)

    @staticmethod
    @agent_base.post_clean_step_hook(
        interface='management', step='update_firmware_sum')
    def _update_firmware_sum_final(task, command):
        """Clean step hook after SUM based firmware update operation.

        This method is invoked as a post clean step hook by the Ironic
        conductor once firmware update operaion is completed. The clean logs
        are collected and stored according to the configured storage backend
        when the node is configured to collect the logs.

        :param task: a TaskManager instance.
        :param command: A command result structure of the SUM based firmware
            update operation returned from agent ramdisk on query of the
            status of command(s).
        """
        if not _should_collect_logs(command):
            return

        node = task.node
        try:
            driver_utils.store_ramdisk_logs(
                node,
                command['command_result']['clean_result']['Log Data'],
                label='update_firmware_sum')
        except EnvironmentError as e:
            LOG.exception('Failed to store the logs from the node %(node)s '
                          'for "update_firmware_sum" clean step due to a '
                          'file-system related error. Error: %(error)s',
                          {'node': node.uuid, 'error': e})
        except Exception as e:
            LOG.exception('Unknown error when storing logs from the node '
                          '%(node)s for "update_firmware_sum" clean step. '
                          'Error: %(error)s',
                          {'node': node.uuid, 'error': e})
