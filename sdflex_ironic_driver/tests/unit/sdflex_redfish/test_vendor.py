# Copyright 2022 Hewlett Packard Enterprise Development LP
# Copyright 2018 DMTF. All rights reserved.
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


from unittest import mock

from oslo_utils import importutils

from ironic.common import exception
from ironic.conductor import task_manager
from ironic.drivers.modules.redfish import utils as redfish_utils
from ironic.tests.unit.db import utils as db_utils

from sdflex_ironic_driver.sdflex_redfish import common as sdflex_common
from sdflex_ironic_driver.tests.unit.sdflex_redfish import test_common

sushy = importutils.try_import('sushy')

INFO_DICT = db_utils.get_test_redfish_info()


class SdflexRedfishVendorPassthruTestCase(test_common.BaseSdflexTest):

    @mock.patch.object(redfish_utils, 'get_event_service', autospec=True)
    def test_validate_invalid_create_subscription(self,
                                                  mock_get_event_service):

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            kwargs = {'Destination': 10000}
            self.assertRaises(
                exception.InvalidParameterValue,
                task.driver.vendor.validate, task, 'create_subscription',
                **kwargs)

            kwargs = {'Destination': 'https://someulr', 'Context': 10}
            self.assertRaises(
                exception.InvalidParameterValue,
                task.driver.vendor.validate, task, 'create_subscription',
                **kwargs)

            kwargs = {'Destination': 'https://someulr', 'Protocol': 10}
            self.assertRaises(
                exception.InvalidParameterValue,
                task.driver.vendor.validate, task, 'create_subscription',
                **kwargs)

            mock_evt_serv = mock_get_event_service.return_value
            mock_evt_serv.get_event_types_for_subscription.return_value = \
                ['Alert']
            kwargs = {'Destination': 'https://someulr',
                      'EventTypes': ['Other']}
            self.assertRaises(
                exception.InvalidParameterValue,
                task.driver.vendor.validate, task, 'create_subscription',
                **kwargs)

            kwargs = {'Destination': 'https://someulr',
                      'HttpHeaders': {'Content-Type': 'application/json'}}
            self.assertRaises(
                exception.InvalidParameterValue,
                task.driver.vendor.validate, task, 'create_subscription',
                **kwargs
            )

    @mock.patch.object(sdflex_common, 'get_sdflex_object',
                       spec_set=True, autospec=True)
    @mock.patch.object(redfish_utils, 'get_event_service', autospec=True)
    def test_create_subscription(self, mock_get_event_service,
                                 mock_get_sdflex_object):
        mock_get_sdflex_object.return_value.get_product_name.return_value = (
            "Superdome Flex")
        subscription_json = {
            "@odata.context": "",
            "@odata.etag": "",
            "@odata.id": "/redfish/v1/EventService/Subscriptions/100",
            "@odata.type": "#EventDestination.v1_0_0.EventDestination",
            "Id": "100",
            "Context": "Ironic",
            "Description": "Sdflex Event Subscription",
            "Destination": "https://someurl",
            "EventTypes": [
                "Alert"
            ],
            "HttpHeaders": [],
            "Name": "Event Subscription",
            "Oem": {
            },
            "Protocol": "Redfish"
        }
        mock_subscription = mock.MagicMock()
        mock_subscription.json = subscription_json
        mock_event_service = mock_get_event_service.return_value
        mock_event_service.subscriptions.create.return_value = (
            mock_subscription)
        kwargs = {
            'Destination': 'https://someurl',
            'HttpHeaders': [{"Content-Type": "application/json"}]
        }
        expected = {'Id': '100', 'Context': 'Ironic',
                    'Destination': 'https://someurl',
                    'EventTypes': ['Alert'],
                    'Protocol': 'Redfish'}
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            actual = task.driver.vendor.create_subscription(task, **kwargs)
            self.assertEqual(expected, actual)

    @mock.patch.object(sdflex_common, 'get_sdflex_object',
                       spec_set=True, autospec=True)
    @mock.patch.object(redfish_utils, 'get_event_service', autospec=True)
    def test_create_subscription_sdflex280(self, mock_get_event_service,
                                           mock_get_sdflex_object):
        mock_get_sdflex_object.return_value.get_product_name.return_value = (
            "Superdome Flex 280")
        subscription_json = {
            "@odata.context": "",
            "@odata.etag": "",
            "@odata.id": "/redfish/v1/EventService/Subscriptions/100",
            "@odata.type": "#EventDestination.v1_0_0.EventDestination",
            "Id": "100",
            "Context": "Ironic",
            "Description": "Sdflex Event Subscription",
            "Destination": "https://someurl",
            "HttpHeaders": [],
            "Name": "Event Subscription",
            "Oem": {
            },
            "Protocol": "Redfish"
        }
        mock_subscription = mock.MagicMock()
        mock_subscription.json = subscription_json
        mock_event_service = mock_get_event_service.return_value
        mock_event_service.subscriptions.create.return_value = (
            mock_subscription)
        kwargs = {
            'Destination': 'https://someurl',
            'HttpHeaders': [{"Content-Type": "application/json"}]
        }
        expected = {'Id': '100', 'Context': 'Ironic',
                    'Destination': 'https://someurl',
                    'Protocol': 'Redfish'}
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            actual = task.driver.vendor.create_subscription(task, **kwargs)
            self.assertEqual(expected, actual)

    @mock.patch.object(sdflex_common, 'get_sdflex_object',
                       spec_set=True, autospec=True)
    @mock.patch.object(redfish_utils, 'get_event_service', autospec=True)
    def test_create_subscription_invalid(self, mock_get_event_service,
                                         mock_get_sdflex_object):
        mock_get_sdflex_object.return_value.get_product_name.return_value = (
            "Superdome Flex 280")
        subscription_json = {
            "@odata.context": "",
            "@odata.etag": "",
            "@odata.id": "/redfish/v1/EventService/Subscriptions/100",
            "@odata.type": "#EventDestination.v1_0_0.EventDestination",
            "Id": "100",
            "Context": "Ironic",
            "Description": "Sdflex Event Subscription",
            "Destination": "https://someurl",
            "EventTypes": [
                "Alert"
            ],
            "HttpHeaders": [],
            "Name": "Event Subscription",
            "Oem": {
            },
            "Protocol": "Redfish"
        }
        mock_subscription = mock.MagicMock()
        mock_subscription.json = subscription_json
        mock_event_service = mock_get_event_service.return_value
        mock_event_service.subscriptions.create.side_effect = (
            sushy.exceptions.SushyError)
        kwargs = {
            'Destination': 'https://someurl',
            'HttpHeaders': [{"Content-Type": "application/json"}]
        }
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            self.assertRaises(exception.RedfishError,
                              task.driver.vendor.create_subscription,
                              task, **kwargs)
