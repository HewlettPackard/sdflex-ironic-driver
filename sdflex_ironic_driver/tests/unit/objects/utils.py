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


import six

from ironic.common import exception
from ironic.common.i18n import _
from ironic import objects
from sdflex_redfish_ironic.tests.unit.db import utils as db_utils


def check_keyword_arguments(func):
    @six.wraps(func)
    def wrapper(**kw):
        obj_type = kw.pop('object_type')
        result = func(**kw)

        extra_args = set(kw) - set(result)
        if extra_args:
            raise exception.InvalidParameterValue(
                _("Unknown keyword arguments (%(extra)s) were passed "
                  "while creating a test %(object_type)s object.") %
                {"extra": ", ".join(extra_args),
                 "object_type": obj_type})

        return result

    return wrapper


def get_test_node(ctxt, **kw):
    """Return a Node object with appropriate attributes.

    NOTE: The object leaves the attributes marked as changed, such
    that a create() could be used to commit it to the DB.
    """
    kw['object_type'] = 'node'
    get_db_node_checked = check_keyword_arguments(db_utils.get_test_node)
    db_node = get_db_node_checked(**kw)

    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del db_node['id']
    node = objects.Node(ctxt)
    for key in db_node:
        if key == 'traits':
            # convert list of strings to object
            raw_traits = db_node['traits']
            trait_list = []
            for raw_trait in raw_traits:
                trait = objects.Trait(ctxt, trait=raw_trait)
                trait_list.append(trait)
            node.traits = objects.TraitList(ctxt, objects=trait_list)
            node.traits.obj_reset_changes()
        else:
            setattr(node, key, db_node[key])
    return node


def create_test_node(ctxt, **kw):
    """Create and return a test node object.

    Create a node in the DB and return a Node object with appropriate
    attributes.
    """
    node = get_test_node(ctxt, **kw)
    node.create()
    return node
