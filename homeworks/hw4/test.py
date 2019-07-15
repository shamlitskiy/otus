import datetime
import unittest
import hashlib
import functools

import api
from store import Store


def set_monkey_store():
    st = Store()
    monkeypatch = MonkeyPatch()
    monkeypatch.setattr(st, 'get', MonkStore.get)
    monkeypatch.setattr(st, 'cache_get', MonkStore.cache_get)
    monkeypatch.setattr(st, 'cache_set', MonkStore.cache_set)


def cases(cases):
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args):
            set_monkey_store()
            for c in cases:
                new_args = args + (c if isinstance(c, tuple) else (c,))
                f(*new_args)
        return wrapper
    return decorator


class MonkeypatchPlugin(object):
    """ setattr-monkeypatching with automatical reversal after test. """
    def pytest_pyfuncarg_monkeypatch(self, pyfuncitem):
        monkeypatch = MonkeyPatch()
        pyfuncitem.addfinalizer(monkeypatch.finalize)
        return monkeypatch


notset = object()


class MonkeyPatch(object):
    def __init__(self):
        self._setattr = []
        self._setitem = []

    def setattr(self, obj, name, value):
        self._setattr.insert(0, (obj, name, getattr(obj, name, notset)))
        setattr(obj, name, value)

    def setitem(self, dictionary, name, value):
        self._setitem.insert(0, (dictionary, name, dictionary.get(name, notset)))
        dictionary[name] = value

    def finalize(self):
        for obj, name, value in self._setattr:
            if value is not notset:
                setattr(obj, name, value)
            else:
                delattr(obj, name)
        for dictionary, name, value in self._setitem:
            if value is notset:
                del dictionary[name]
            else:
                dictionary[name] = value


class MonkStore(object):
    @staticmethod
    def get(key):
        return 1

    @staticmethod
    def cache_get(key):
        return 1.5

    @staticmethod
    def cache_set(key):
        pass


class TestSuite(unittest.TestCase):
    def setUp(self):
        self.context = {}
        self.headers = {}
        self.store = Store()

    def get_response(self, request):
        return api.method_handler({"body": request, "headers": self.headers}, self.context, self.store)

    def set_valid_auth(self, request):
        if request.get("login") == api.ADMIN_LOGIN:
            request["token"] = hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + api.ADMIN_SALT).hexdigest()
        else:
            msg = str(request.get("account", "")) + str(request.get("login", "")) + api.SALT
            request["token"] = hashlib.sha512(msg).hexdigest()

    def test_empty_request(self):
        _, code = self.get_response({})
        self.assertEqual(api.INVALID_REQUEST, code)

    @cases([
        {"req": {"account": "sdf", "token": "", "method": "online_score", "arguments": {}},
         "resp": 'Invalid Request. Field login is required'},

        {"req": {"account": "sdf", "login": "qw", "method": "online_score", "arguments": {}},
         "resp": 'Invalid Request. Field token is required'},

        {"req": {"account": "sdf", "login": "qw", "token": "", "arguments": {}},
         "resp": 'Invalid Request. Field method is required; Field method is not nullable'},

        {"req": {"account": "sdf", "login": "qw", "token": "", "method": "online_score"},
         "resp": 'Invalid Request. Field arguments is required'},
    ])
    def test_check_required_header_fields(self, request):
        resp, code = self.get_response(request['req'])
        self.assertEqual(request['resp'], resp)

    @cases([
        {"account": 1, "login": "qw", "method": "online_score", "arguments": {}},
        {"account": "acc", "login": 2, "method": "online_score", "arguments": {}},
        {"account": "acc", "login": "qw", "method": 3, "arguments": {}},
        {"account": "sdf", "login": "qw", "method": "online_score", "arguments": 4},
    ])
    def test_wrong_headers(self, request):
        self.set_valid_auth(request)

        _, code = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, code)

    @cases([
        {'arguments': {"phone": "69251637831"}},
        {'arguments': {"phone": "1234567891011"}},
    ])
    def test_check_wrong_phone(self, request):
        request.update({"account": "acc", "login": "qw", "method": "online_score"})
        request['arguments'].update({
            "email": "some@mail.ru", "gender": 1, "birthday": "01.01.2010", "first_name": "some", "last_name": "name",
        })

        self.set_valid_auth(request)

        _, code = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, code)

    @cases([
        {'arguments': {"phone": "69251637831"}},
        {'arguments': {"phone": "1234567891011"}},
    ])
    def test_check_wrong_phone(self, request):
        request.update({"account": "acc", "login": "qw", "method": "online_score"})
        request['arguments'].update({
            "email": "some@mail.ru", "gender": 1, "birthday": "01.01.2010", "first_name": "some", "last_name": "name",
        })

        self.set_valid_auth(request)

        _, code = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, code)


if __name__ == "__main__":
    unittest.main()
