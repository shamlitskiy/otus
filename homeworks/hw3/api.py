#!/usr/bin/env python
# -*- coding: utf-8 -*-

from abc import ABCMeta
import json
import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

from scoring import get_score, get_interests


SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class Field(object):
    def __init__(self, value=None, required=False, nullable=False):
        self.label = None
        self.value = value
        self.required = required
        self.nullable = nullable

    def __set__(self, obj, val):
        self.errors = []
        errors = self.check_values(val)
        if not errors:
            self.value = val
        else:
            self.value = None
            self.errors.extend(errors)

    def __get__(self, obj, owner):
        return self.value

    def check_values(self, val):
        errors = []
        errors.extend(self._check_nullable(val))
        return errors

    def _check_nullable(self, val):
        if not val and not self.nullable:
            return [
                'Field {label} is not nullable'.format(label=self.label)
            ]
        else:
            return []


class CharField(Field):
    def check_values(self, val):
        errors = super(CharField, self).check_values(val)
        errors.extend(self._check_type(val))
        return errors

    def _check_type(self, val):
        if val and not isinstance(val, str):
            return [
                'Field {label} should be string'.format(label=self.label)
            ]
        else:
            return []


class ArgumentsField(Field):
    def check_values(self, val):
        errors = super(ArgumentsField, self).check_values(val)
        errors.extend(self._check_type(val))
        return errors

    def _check_type(self, val):
        if val and not isinstance(val, dict):
            return [
                'Field {label} should be dict'.format(label=self.label)
            ]
        else:
            return []


class EmailField(CharField):
    def check_values(self, val):
        errors = super(EmailField, self).check_values(val)
        errors.extend(self._check_email(val))
        return errors

    def _check_email(self, val):
        if val and '@' not in val:
            return [
                'Field {label} should contain `@` symbol'.format(label=self.label)
            ]
        else:
            return []


class PhoneField(Field):
    def check_values(self, val):
        errors = super(PhoneField, self).check_values(val)
        errors.extend(self._check_type(val))
        errors.extend(self._check_length(val))
        errors.extend(self._check_first_char(val))
        return errors

    def _check_type(self, val):
        if val and not isinstance(val, (int, str)):
            return [
                'Field {label}. Expected string or number'.format(label=self.label)
            ]
        else:
            return []

    def _check_length(self, val):
        if val and len(val) != 11:
            return [
                'Field {label} should be 11 chars length'.format(label=self.label)
            ]
        else:
            return []

    def _check_first_char(self, val):
        if val and not str(val).startswith('7'):
            return [
                'Field {label} should starts with `7`'.format(label=self.label)
            ]
        else:
            return []


class DateField(Field):
    def check_values(self, val):
        errors = super(DateField, self).check_values(val)
        errors.extend(self._check_date_format(val))
        return errors

    def _check_date_format(self, val):
        try:
            if val:
                datetime.datetime.strptime(val, '%d.%m.%Y')
            return []
        except ValueError:
            return [
                'Field {label}: Expected format: DD.MM.YYYY'.format(label=self.label)
            ]


class BirthDayField(DateField):
    def check_values(self, val):
        errors = super(BirthDayField, self).check_values(val)
        errors.extend(self._check_date_range(val))
        return errors

    def _check_date_range(self, val):
        if val and not str(val).startswith('7'):
            return [
                'Field {label}. Age should be lower than 70 years'.format(label=self.label)
            ]
        else:
            return []


class GenderField(Field):
    pass


class ClientIDsField(Field):
    def check_values(self, val):
        errors = super(ClientIDsField, self).check_values(val)
        errors.extend(self._check_type(val))
        return errors

    def _check_type(self, val):
        if val and not isinstance(val, list):
            return [
                'Field {label}. Expected `list` type.'.format(label=self.label)
            ]
        else:
            return []


class RequestMeta(type):
    def __new__(mcs, name, bases, attrs):
        for n, v in attrs.items():
            if isinstance(v, Field):
                v.label = n
        return super(RequestMeta, mcs).__new__(mcs, name, bases, attrs)

    def __init__(cls, name, bases, attrs):
        cls.fields = []
        cls.required_fields = []

        for n, v in attrs.items():
            if isinstance(v, Field):
                if v.required:
                    cls.required_fields.append(n)
                cls.fields.append(v)

        super(RequestMeta, cls).__init__(name, bases, attrs)


class ClientsInterestsRequest(object):
    __metaclass__ = RequestMeta

    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def __init__(self, arguments):
        self.errors = []
        self._check_required_fields(arguments)

        self.client_ids = arguments.get('client_ids')
        self.date = arguments.get('date')

        self._check_fields_errors()

    def _check_required_fields(self, request):
        for required_field in self.required_fields:
            if required_field not in request:
                self.errors.extend(['Field {} is required'.format(required_field)])

    def _check_fields_errors(self):
        for field in self.fields:
            self.errors.extend(field.errors)

    def response(self, ctx, store):
        interests = {}
        for cid in self.client_ids:
            interests.update({cid: get_interests(
                store=store,
                cid=self.client_ids)
            })
        return interests


class OnlineScoreRequest(object):
    __metaclass__ = RequestMeta

    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(self, arguments):
        self.errors = []
        self._check_required_fields(arguments)

        self.first_name = arguments.get('first_name')
        self.last_name = arguments.get('last_name')
        self.email = arguments.get('email')
        self.phone = arguments.get('phone')
        self.birthday = arguments.get('birthday')
        self.gender = arguments.get('gender')

        self._check_fields_errors()

    def _check_required_fields(self, request):
        for required_field in self.required_fields:
            if required_field not in request:
                self.errors.extend(['Field {} is required'.format(required_field)])

    def _check_fields_errors(self):
        for field in self.fields:
            self.errors.extend(field.errors)

    def response(self, ctx, store):
        score = get_score(
            store=store, phone=self.phone, email=self.email,
            first_name=self.first_name, last_name=self.last_name,
            birthday=self.birthday, gender=self.gender,
        )
        return score


class MethodRequest(object):
    __metaclass__ = RequestMeta

    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    def __init__(self, request):
        self.errors = []
        self._check_required_fields(request)

        self.account = request.get('account')
        self.login = request.get('login')
        self.token = request.get('token')
        self.arguments = request.get('arguments')
        self.method = request.get('method')
        self._check_fields_errors()

        self.response_method = self._set_response_method()
        self._check_method_errors()

    def _check_required_fields(self, request):
        for required_field in self.required_fields:
            if required_field not in request:
                self.errors.extend(['Field {} is required'.format(required_field)])

    def _check_fields_errors(self):
        for field in self.fields:
            self.errors.extend(field.errors)

    def _check_method_errors(self):
        if self.response_method and self.response_method.errors:
            self.errors.extend(self.response_method.errors)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN

    def _set_response_method(self):
        response_method = None
        if not self.errors:
            if self.method == 'clients_interests':
                response_method = ClientsInterestsRequest(self.arguments)
            elif self.method == 'online_score':
                response_method = OnlineScoreRequest(self.arguments)
            else:
                self.errors.extend(['Method "{}" not found'.format(self.method)])
        return response_method

    def get_response(self, ctx, store):
        return self.response_method.response(ctx, store)


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).hexdigest()
    else:
        digest = hashlib.sha512(request.account + request.login + SALT).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    method_req = MethodRequest(request)
    if method_req.errors:
        msg = '{error}. {msg}'.format(
            error=ERRORS[INVALID_REQUEST],
            msg='; '.join(method_req.errors)
        )
        code, response = INVALID_REQUEST, msg
    elif not check_auth(method_req):
        code, response = FORBIDDEN, ERRORS[FORBIDDEN]
    else:
        code, response = OK, method_req.get_response(ctx=ctx, store=store)
    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception, e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r))
        return


if __name__ == "__main__":
    # op = OptionParser()
    # op.add_option("-p", "--port", action="store", type=int, default=8080)
    # op.add_option("-l", "--log", action="store", default=None)
    # (opts, args) = op.parse_args()
    # logging.basicConfig(filename=opts.log, level=logging.INFO,
    #                     format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    # server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    # logging.info("Starting server at %s" % opts.port)
    # try:
    #     server.serve_forever()
    # except KeyboardInterrupt:
    #     pass
    # server.server_close()

    # req = {"account": "horns&hoofs", "method": "online_score", "token": "", "arguments": {}}
    # a = MethodRequest(req)
    # res = method_handler(req, 1, 1)

    valid_token = hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).hexdigest()

    req_list = [
        {
            "account": "horns&hoofs",
            "login": "admin",
            "method": "clients_interests",
            "token":
            "d3573aff1555cd67dccf21b95fe8c4dc8732f33fd4e32461b7fe6a71d83c947688515e36774c00fb630b039fe2223c991f045f13f",
            "arguments": {
                "client_ids": [1, 2, 3, 4],
                "date": "20.07.2017"
            }
        },
        {
            "account": "horns&hoofs",
            "login": "admin",
            "method": "clients_interests",
            "token": valid_token,
            "arguments": {
                "client_ids": [1, 2, 3, 4],
                "date": "20.07.2017"
            }
        },
        {
            # "account": "horns&hoofs",
            "login": "admin",
            "method": "clients_interests",
            "token": valid_token,
            "arguments": {
                "client_ids": [4, 5, 7, 3],
                "date": "20.07.2017"
            }
        },
        {
            "account": "",
            "login": "admin",
            "method": "clients_interests",
            "token": valid_token,
            "arguments": {
                "client_ids": [411, 254, 23, 64],
                "date": "20.07.2017"
            }
        },
        {
            "account": "horns&hoofs",
            # "login": "admin",
            "method": "clients_interests",
            "token": valid_token,
            "arguments": {
                "client_ids": [1, 2, 3, 4],
                "date": "20.07.2017"
            }
        },
        {
            "account": "horns&hoofs",
            "login": "",
            "method": "clients_interests",
            "token": valid_token,
            "arguments": {
                "client_ids": [1, 2, 3, 4],
                "date": "20.07.2017"
            }
        },
        {
            "account": "horns&hoofs",
            "login": "admin",
            # "method": "clients_interests",
            "token": valid_token,
            "arguments": {
                "client_ids": [1, 2, 3, 4],
                "date": "20.07.2017"
            }
        },
        {
            "account": "horns&hoofs",
            "login": "admin",
            "method": "",
            "token": valid_token,
            "arguments": {
                "client_ids": [1, 2, 3, 4],
                "date": "20.07.2017"
            }
        },
        {
            "account": "horns&hoofs",
            "login": "admin",
            "method": "asdf",
            "token": valid_token,
            "arguments": {
                "client_ids": [1, 2, 3, 4],
                "date": "20.07.2017"
            }
        },
        {
            "account": "horns&hoofs",
            "login": "admin",
            "method": "clients_interests",
            # "token": valid_token,
            "arguments": {
                "client_ids": [1, 2, 3, 4],
                "date": "20.07.2017"
            }
        },
        {
            "account": "horns&hoofs",
            "login": "admin",
            "method": "clients_interests",
            "token": valid_token,
            # "arguments": {
            #     "client_ids": [1, 2, 3, 4],
            #     "date": "20.07.2017"
            # }
        },
        {
            "account": "horns&hoofs",
            "login": "admin",
            "method": "clients_interests",
            "token": valid_token,
            "arguments": {}
        },
        {
            "account": "horns&hoofs",
            "login": "admin",
            "method": "clients_interests",
            "token": valid_token,
            "arguments": {
                # "client_ids": [1, 2, 3, 4],
                "date": "20.07.2017"
            }
        },
        {
            "account": "horns&hoofs",
            "login": "admin",
            "method": "clients_interests",
            "token": valid_token,
            "arguments": {
                "client_ids": [1, 2, 3, 4],
                "date": ""
            }
        },
        {
            "account": "horns&hoofs",
            "login": "admin",
            "method": "clients_interests",
            "token": valid_token,
            "arguments": {
                "client_ids": [1, 2, 3, 4],
                # "date": "20.07.2017"
            }
        },
        {
            "account": "horns&hoofs",
            "login": "admin",
            "method": "clients_interests",
            "token": valid_token,
            "arguments": {
                "client_ids": [1, 2, 3, 4],
                "date": "20314.07.2017"
            }
        },
        {
            "account": "horns&hoofs",
            "login": "admin",
            "method": "clients_interests",
            "token": valid_token,
            "arguments": {
                "client_ids": [1, 2, 3, 4],
                "date": "2007.2017"
            }
        },
        {
            "account": "horns&hoofs",
            "login": "admin",
            "method": "clients_interests",
            "token": valid_token,
            "arguments": {
                "client_ids": [1, 2, 3, 4],
                "date": "sdaf901.41"
            }
        },
        {},
    ]

    for req in req_list:
        print(req)
        res = method_handler(req, 1, 1)
        print res
        print('\n')

    print('Done!')
