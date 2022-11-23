# Copyright 2022 Hewlett Packard Enterprise Development LP
# Copyright 2015 Hewlett-Packard Development Company, L.P.
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
"""
Vendor Interface for sdflex-edfish driver and its supporting methods.
"""

from ironic_lib import metrics_utils
from oslo_log import log
from oslo_utils import importutils

from ironic.common import exception
from ironic.common.i18n import _
from ironic.drivers import base
from ironic.drivers.modules.redfish import utils as redfish_utils
from ironic.drivers.modules.redfish import vendor as redfish_vendor

from sdflex_ironic_driver.sdflex_redfish import common as sdflex_common

sushy = importutils.try_import('sushy')

LOG = log.getLogger(__name__)
METRICS = metrics_utils.get_metrics_logger(__name__)
SUBSCRIPTION_COMMON_FIELDS = {
    'Id', 'Context', 'Protocol', 'Destination', 'EventTypes'
}


class SdflexRedfishVendorPassthru(redfish_vendor.RedfishVendorPassthru):
    """Sdflex Redfish interface for vendor_passthru."""

    def _filter_subscription_fields(self, subscription_json):
        filter_subscription = {k: v for k, v in subscription_json.items()
                               if k in SUBSCRIPTION_COMMON_FIELDS}
        return filter_subscription

    @METRICS.timer('RedfishVendorPassthru.create_subscription')
    @base.passthru(['POST'], async_call=False,
                   description=_("Creates a subscription on a node. "
                                 "Required argument: a dictionary of "
                                 "{'Destination': 'destination_url'}"))
    def create_subscription(self, task, **kwargs):
        """Creates a subscription.

        :param task: A TaskManager object.
        :param kwargs: The arguments sent with vendor passthru.
        :raises: RedfishError, if any problem occurs when trying to create
            a subscription.
        """
        node = task.node
        sdflex_object = sdflex_common.get_sdflex_object(node)
        product_name = sdflex_object.get_product_name()
        if product_name != 'Superdome Flex':
            payload = {
                'Destination': kwargs.get('Destination'),
                'Protocol': kwargs.get('Protocol', "Redfish"),
                'Context': kwargs.get('Context', ""),
            }
        else:
            payload = {
                'Destination': kwargs.get('Destination'),
                'Protocol': kwargs.get('Protocol', "Redfish"),
                'Context': kwargs.get('Context', ""),
                'EventTypes': kwargs.get('EventTypes', ["Alert"])
            }

        http_headers = kwargs.get('HttpHeaders', [])
        if http_headers:
            payload['HttpHeaders'] = http_headers

        try:
            event_service = redfish_utils.get_event_service(task.node)
            subscription = event_service.subscriptions.create(payload)
            return self._filter_subscription_fields(subscription.json)
        except sushy.exceptions.SushyError as e:
            error_msg = (_('Failed to create subscription on node %(node)s. '
                           'Subscription payload: %(payload)s. '
                           'Error: %(error)s') % {'node': task.node.uuid,
                                                  'payload': str(payload),
                                                  'error': e})
            LOG.error(error_msg)
            raise exception.RedfishError(error=error_msg)
