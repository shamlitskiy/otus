import datetime
import unittest
import hashlib
import functools
import mock

import api
from store import Store


def cases(cases):
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args):
            for c in cases:
                new_args = args + (c if isinstance(c, tuple) else (c,))
                f(*new_args)
        return wrapper
    return decorator


class TestSuite(unittest.TestCase):
    def setUp(self):
        sq = Store
        sq.get = mock.MagicMock(return_value=1)
        sq.cache_get = mock.MagicMock(return_value=1.5)
        sq.cache_set = mock.MagicMock(return_value=1)

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
        {'arguments': {"phone": 9341414}},
        {'arguments': {"phone": 74954348374.9}},
        {'arguments': {"phone": 7495434837.9}},
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
        {'arguments': {"email": "somemail.ru"}},
        {'arguments': {"email": 341}},
        {'arguments': {"email": [4, 3]}},
    ])
    def test_check_wrong_email(self, request):
        request.update({"account": "acc", "login": "qw", "method": "online_score"})
        request['arguments'].update({
            "phone": "74993432145", "gender": 1, "birthday": "01.01.2010", "first_name": "some", "last_name": "name",
        })

        self.set_valid_auth(request)

        _, code = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, code)

    @cases([
        {'arguments': {"gender": 10}},
        {'arguments': {"gender": -1}},
        {'arguments': {"gender": [13, 4]}},
        {'arguments': {"gender": "1"}},
    ])
    def test_check_wrong_gender(self, request):
        request.update({"account": "acc", "login": "qw", "method": "online_score"})
        request['arguments'].update({
            "phone": "74993432145", "email": "some@mail.ru", "birthday": "01.01.2010", "first_name": "some", "last_name": "name",
        })

        self.set_valid_auth(request)

        _, code = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, code)

    @cases([
        {'arguments': {"phone": "74993432145", "email": "some@mail.ru"}},
        {'arguments': {"gender": 1, "birthday": "01.01.2010"}},
        {'arguments': {"first_name": "some", "last_name": "name"}},
    ])
    def test_check_required_pairs(self, request):
        request.update({"account": "acc", "login": "qw", "method": "online_score"})

        self.set_valid_auth(request)

        _, code = self.get_response(request)
        self.assertEqual(api.OK, code)

    @cases([
        {'arguments': {"client_ids": '1, 2, 4'}},
        {'arguments': {"client_ids": 14}},
        {'arguments': {"client_ids": 0.1}},
        {'arguments': {"client_ids": (1, 6)}},
    ])
    def test_check_wrong_client_ids(self, request):
        request.update({"account": "acc", "login": "qw", "method": "clients_interests"})
        request['arguments'].update({
            "date": "01.02.2011",
        })

        self.set_valid_auth(request)

        _, code = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, code)

    @cases([
        {'arguments': {"date": 3}},
        {'arguments': {"date": 'abcs'}},
        {'arguments': {"date": 3.0}},
        {'arguments': {"date": [3.0]}},
    ])
    def test_check_wrong_date(self, request):
        request.update({"account": "acc", "login": "qw", "method": "clients_interests"})
        request['arguments'].update({
            "client_ids": [1, 2, 4],
        })

        self.set_valid_auth(request)

        _, code = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, code)


if __name__ == "__main__":
    unittest.main()
