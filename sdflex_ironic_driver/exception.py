# Copyright 2019 Hewlett Packard Enterprise Development LP
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

from ironic.common import exception as ironic_exception
from ironic.common.i18n import _

"""Exception Classes for sdflex-refish driver module."""


class SDFlexOperationNotSupported(ironic_exception.DriverOperationError):
    _msg_fmt = _("%(operation)s not supported. error: %(error)s")


class SDFlexOperationError(ironic_exception.DriverOperationError):
    _msg_fmt = _("%(operation)s failed, error: %(error)s")
