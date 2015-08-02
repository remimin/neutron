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

import random
import string

import mock
from oslo_versionedobjects import base as obj_base
from oslo_versionedobjects import fields as obj_fields

from neutron.common import exceptions as n_exc
from neutron import context
from neutron.db import api as db_api
from neutron.objects import base
from neutron.tests import base as test_base


class FakeModel(object):
    def __init__(self, *args, **kwargs):
        pass


@obj_base.VersionedObjectRegistry.register
class FakeNeutronObject(base.NeutronDbObject):

    db_model = FakeModel

    fields = {
        'id': obj_fields.UUIDField(),
        'field1': obj_fields.StringField(),
        'field2': obj_fields.StringField()
    }

    fields_no_update = ['id']


def _random_string(n=10):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(n))


def _random_boolean():
    return bool(random.getrandbits(1))


def _random_integer():
    return random.randint(0, 1000)


FIELD_TYPE_VALUE_GENERATOR_MAP = {
    obj_fields.BooleanField: _random_boolean,
    obj_fields.IntegerField: _random_integer,
    obj_fields.StringField: _random_string,
    obj_fields.UUIDField: _random_string,
    obj_fields.ListOfObjectsField: lambda: []
}


def get_obj_db_fields(obj):
    return {field: getattr(obj, field) for field in obj.fields
            if field not in obj.synthetic_fields}


class _BaseObjectTestCase(object):

    _test_class = FakeNeutronObject

    def setUp(self):
        super(_BaseObjectTestCase, self).setUp()
        self.context = context.get_admin_context()
        self.db_objs = list(self.get_random_fields() for _ in range(3))
        self.db_obj = self.db_objs[0]

    @classmethod
    def get_random_fields(cls, obj_cls=None):
        obj_cls = obj_cls or cls._test_class
        fields = {}
        for field, field_obj in obj_cls.fields.items():
            if field not in obj_cls.synthetic_fields:
                generator = FIELD_TYPE_VALUE_GENERATOR_MAP[type(field_obj)]
                fields[field] = generator()
        return fields

    def get_updatable_fields(self, fields):
        return base.get_updatable_fields(self._test_class, fields)

    @classmethod
    def _is_test_class(cls, obj):
        return isinstance(obj, cls._test_class)


class BaseObjectIfaceTestCase(_BaseObjectTestCase, test_base.BaseTestCase):

    def test_get_by_id(self):
        with mock.patch.object(db_api, 'get_object',
                               return_value=self.db_obj) as get_object_mock:
            obj = self._test_class.get_by_id(self.context, id='fake_id')
            self.assertTrue(self._is_test_class(obj))
            self.assertEqual(self.db_obj, get_obj_db_fields(obj))
            get_object_mock.assert_called_once_with(
                self.context, self._test_class.db_model, id='fake_id')

    def test_get_by_id_missing_object(self):
        with mock.patch.object(db_api, 'get_object', return_value=None):
            obj = self._test_class.get_by_id(self.context, id='fake_id')
            self.assertIsNone(obj)

    def test_get_objects(self):
        with mock.patch.object(db_api, 'get_objects',
                               return_value=self.db_objs) as get_objects_mock:
            objs = self._test_class.get_objects(self.context)
            self._validate_objects(self.db_objs, objs)
        get_objects_mock.assert_called_once_with(
            self.context, self._test_class.db_model)

    def _validate_objects(self, expected, observed):
        self.assertFalse(
            filter(lambda obj: not self._is_test_class(obj), observed))
        self.assertEqual(
            sorted(expected),
            sorted(get_obj_db_fields(obj) for obj in observed))

    def _check_equal(self, obj, db_obj):
        self.assertEqual(
            sorted(db_obj),
            sorted(get_obj_db_fields(obj)))

    def test_create(self):
        with mock.patch.object(db_api, 'create_object',
                               return_value=self.db_obj) as create_mock:
            obj = self._test_class(self.context, **self.db_obj)
            self._check_equal(obj, self.db_obj)
            obj.create()
            self._check_equal(obj, self.db_obj)
            create_mock.assert_called_once_with(
                self.context, self._test_class.db_model, self.db_obj)

    def test_create_updates_from_db_object(self):
        with mock.patch.object(db_api, 'create_object',
                               return_value=self.db_obj):
            obj = self._test_class(self.context, **self.db_objs[1])
            self._check_equal(obj, self.db_objs[1])
            obj.create()
            self._check_equal(obj, self.db_obj)

    @mock.patch.object(db_api, 'update_object')
    def test_update_no_changes(self, update_mock):
        with mock.patch.object(base.NeutronDbObject,
                               '_get_changed_persistent_fields',
                               return_value={}):
            obj = self._test_class(self.context)
            obj.update()
            self.assertFalse(update_mock.called)

    @mock.patch.object(db_api, 'update_object')
    def test_update_changes(self, update_mock):
        fields_to_update = self.get_updatable_fields(self.db_obj)
        with mock.patch.object(base.NeutronDbObject,
                               '_get_changed_persistent_fields',
                               return_value=fields_to_update):
            obj = self._test_class(self.context, **self.db_obj)
            obj.update()
            update_mock.assert_called_once_with(
                self.context, self._test_class.db_model,
                self.db_obj['id'], fields_to_update)

    @mock.patch.object(base.NeutronDbObject,
                       '_get_changed_persistent_fields',
                       return_value={'a': 'a', 'b': 'b', 'c': 'c'})
    def test_update_changes_forbidden(self, *mocks):
        with mock.patch.object(
            self._test_class,
            'fields_no_update',
            new_callable=mock.PropertyMock(return_value=['a', 'c']),
            create=True):
            obj = self._test_class(self.context, **self.db_obj)
            self.assertRaises(base.NeutronObjectUpdateForbidden, obj.update)

    def test_update_updates_from_db_object(self):
        with mock.patch.object(db_api, 'update_object',
                               return_value=self.db_obj):
            obj = self._test_class(self.context, **self.db_objs[1])
            fields_to_update = self.get_updatable_fields(self.db_objs[1])
            with mock.patch.object(base.NeutronDbObject,
                                   '_get_changed_persistent_fields',
                                   return_value=fields_to_update):
                obj.update()
            self._check_equal(obj, self.db_obj)

    @mock.patch.object(db_api, 'delete_object')
    def test_delete(self, delete_mock):
        obj = self._test_class(self.context, **self.db_obj)
        self._check_equal(obj, self.db_obj)
        obj.delete()
        self._check_equal(obj, self.db_obj)
        delete_mock.assert_called_once_with(
            self.context, self._test_class.db_model, self.db_obj['id'])


class BaseDbObjectTestCase(_BaseObjectTestCase):

    def test_get_by_id_create_update_delete(self):
        obj = self._test_class(self.context, **self.db_obj)
        obj.create()

        new = self._test_class.get_by_id(self.context, id=obj.id)
        self.assertEqual(obj, new)

        obj = new

        for key, val in self.get_updatable_fields(self.db_objs[1]).items():
            setattr(obj, key, val)
        obj.update()

        new = self._test_class.get_by_id(self.context, id=obj.id)
        self.assertEqual(obj, new)

        obj = new
        new.delete()

        new = self._test_class.get_by_id(self.context, id=obj.id)
        self.assertIsNone(new)

    def test_update_non_existent_object_raises_not_found(self):
        obj = self._test_class(self.context, **self.db_obj)
        obj.obj_reset_changes()

        for key, val in self.get_updatable_fields(self.db_obj).items():
            setattr(obj, key, val)

        self.assertRaises(n_exc.ObjectNotFound, obj.update)

    def test_delete_non_existent_object_raises_not_found(self):
        obj = self._test_class(self.context, **self.db_obj)
        self.assertRaises(n_exc.ObjectNotFound, obj.delete)
