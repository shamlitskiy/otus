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
    """Base class for all field types"""
    def __init__(self, value=None, required=False, nullable=False):
        self.label = None
        self.value = value
        self.required = required
        self.nullable = nullable

    def __set__(self, obj, val):
        # Check errors before set the value
        self.errors = []
        self.check_values(val)
        if not self.errors:
            self.value = val
        else:
            self.value = None

    def __get__(self, obj, owner):
        return self.value

    def check_values(self, val):
        # Check value for some properties and restrictions
        # and extend the errors list:
        # self.errors.extend(%some_method_to_check_the_value%)
        self.errors.extend(self._check_nullable(val))

    def _check_nullable(self, val):
        if not val and not self.nullable:
            return [
                'Field {label} is not nullable'.format(label=self.label)
            ]
        else:
            return []


class CharField(Field):
    """Char field's base class"""
    def __set__(self, obj, val):
        if self.nullable and val is None:
            val = ''  # Default value for CharField is empty string
        super(CharField, self).__set__(obj, val)

    def check_values(self, val):
        super(CharField, self).check_values(val)
        self.errors.extend(self._check_type(val))

    def _check_type(self, val):
        if val and not isinstance(val, str):
            return [
                'Field {label} should be string'.format(label=self.label)
            ]
        else:
            return []


class ArgumentsField(Field):
    """`словарь (объект в терминах json), обязательно, может быть пустым`"""
    def __set__(self, obj, val):
        if self.nullable and not val:
            val = {}  # Default value for ArgumentsField is empty dict
        super(ArgumentsField, self).__set__(obj, val)

    def check_values(self, val):
        super(ArgumentsField, self).check_values(val)
        self.errors.extend(self._check_type(val))

    def _check_type(self, val):
        if val and not isinstance(val, dict):
            return [
                'Field {label} should be dict'.format(label=self.label)
            ]
        else:
            return []


class EmailField(CharField):
    """"`строка, в которой есть @, опционально, может быть пустым`"""
    def check_values(self, val):
        super(EmailField, self).check_values(val)
        self.errors.extend(self._check_email(val))

    def _check_email(self, val):
        if not self.errors and val and '@' not in val:
            return [
                'Field {label} should contain `@` symbol'.format(label=self.label)
            ]
        else:
            return []


class PhoneField(Field):
    """"`строка или число, длиной 11, начинается с 7, опционально, может быть пустым`"""
    def check_values(self, val):
        super(PhoneField, self).check_values(val)
        self.errors.extend(self._check_type(val))
        self.errors.extend(self._check_length(val))
        self.errors.extend(self._check_first_char(val))

    def _check_type(self, val):
        if val and not isinstance(val, (str, int)):
            return [
                'Field {label}. Expected string or integer'.format(label=self.label)
            ]
        else:
            return []

    def _check_length(self, val):
        if not self.errors and val and len(str(val)) != 11:
            return [
                'Field {label} should be 11 chars length'.format(label=self.label)
            ]
        else:
            return []

    def _check_first_char(self, val):
        if not self.errors and val and not str(val).startswith('7'):
            return [
                'Field {label} should starts with `7`'.format(label=self.label)
            ]
        else:
            return []


class DateField(Field):
    """`дата в формате DD.MM.YYYY, опционально, может быть пустым`"""
    def __set__(self, obj, val):
        super(DateField, self).__set__(obj, val)
        if self.value:
            self.value = datetime.datetime.strptime(val, '%d.%m.%Y')

    def check_values(self, val):
        super(DateField, self).check_values(val)
        self.errors.extend(self._check_date_format(val))

    def _check_date_format(self, val):
        try:
            if not self.errors and val:
                datetime.datetime.strptime(val, '%d.%m.%Y')
            return []
        except ValueError:
            return [
                'Field {label}: Expected format: DD.MM.YYYY'.format(label=self.label)
            ]


class BirthDayField(DateField):
    """`дата в формате DD.MM.YYYY, с которой прошло не более 70 лет, опционально, может быть пустым`"""
    def check_values(self, val):
        super(BirthDayField, self).check_values(val)
        self.errors.extend(self._check_date_range(val))

    def _check_date_range(self, val):
        if not self.errors and val:
            dt = datetime.datetime.strptime(val, '%d.%m.%Y')
            curr_date = datetime.datetime.now()
            if abs((curr_date - dt).days) / 365 > 70:
                return [
                    'Field {label}. Age should be lower than 70 years'.format(label=self.label)
                ]
        return []


class GenderField(Field):
    """`число 0, 1 или 2, опционально, может быть пустым`"""
    def check_values(self, val):
        super(GenderField, self).check_values(val)
        self.errors.extend(self._check_gender_range(val))

    def _check_type(self, val):
        if val and not isinstance(val, int):
            return [
                'Field {label}. Value should be type of integer'.format(label=self.label)
            ]
        else:
            return []

    def _check_gender_range(self, val):
        if not self.errors and val and val not in [0, 1, 2]:
            return [
                'Field {label}. Gender value should be 0, 1 or 2'.format(label=self.label)
            ]
        else:
            return []


class ClientIDsField(Field):
    """`массив чисел, обязательное, не пустое`"""
    def __set__(self, obj, val):
        if self.nullable and not val:
            val = []  # Default value for ClientIDsField is empty list
        super(ClientIDsField, self).__set__(obj, val)

    def check_values(self, val):
        super(ClientIDsField, self).check_values(val)
        self.errors.extend(self._check_type(val))
        self.errors.extend(self._check_element_type(val))

    def _check_type(self, val):
        if val and not isinstance(val, list):
            return [
                'Field {label}. Expected `list` type.'.format(label=self.label)
            ]
        else:
            return []

    def _check_element_type(self, val):
        if not self.errors:
            for elem in val:
                if not isinstance(elem, int):
                    return [
                        'Field {label}. Should contain only integers.'.format(label=self.label)
                    ]
        return []


class RequestMeta(type):
    def __new__(mcs, name, bases, attrs):
        # Set labels for attributes of type `Field`
        for n, v in attrs.items():
            if isinstance(v, Field):
                v.label = n
        return super(RequestMeta, mcs).__new__(mcs, name, bases, attrs)

    def __init__(cls, name, bases, attrs):
        # Init the lists with objects with type of `Field`
        cls.fields = []  # all objects
        cls.required_fields = []  # required objects

        for n, v in attrs.items():
            if isinstance(v, Field):
                if v.required:
                    cls.required_fields.append(n)
                cls.fields.append(v)

        super(RequestMeta, cls).__init__(name, bases, attrs)


class RequestBaseClass(object):
    __metaclass__ = RequestMeta

    def __init__(self, request):
        self.errors = []
        self._check_required_fields(request)
        self._check_fields_errors()

    def _check_required_fields(self, request):
        # Check if all required fields is in request
        for required_field in self.required_fields:
            if required_field not in request:
                self.errors.extend(['Field {} is required'.format(required_field)])

    def _check_fields_errors(self):
        # iterate through field objects and get its errors
        for field in self.fields:
            self.errors.extend(field.errors)

    def response(self, ctx, score, is_admin=False):
        return {}


class ClientsInterestsRequest(RequestBaseClass):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def __init__(self, arguments):
        self.client_ids = arguments.get('client_ids')
        self.date = arguments.get('date')
        super(ClientsInterestsRequest, self).__init__(arguments)

    def response(self, ctx, store, is_admin=False):
        interests = {}
        for cid in self.client_ids:
            interests.update({cid: get_interests(
                store=store,
                cid=self.client_ids)
            })
        ctx.update({'nclients': len(self.client_ids)})
        return interests


class OnlineScoreRequest(RequestBaseClass):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(self, arguments):
        self.first_name = arguments.get('first_name')
        self.last_name = arguments.get('last_name')
        self.email = arguments.get('email')
        self.phone = arguments.get('phone')
        self.birthday = arguments.get('birthday')
        self.gender = arguments.get('gender')
        super(OnlineScoreRequest, self).__init__(arguments)

        self._check_required_pairs_of_fields()
        self.context = self._prepare_context(arguments)

    def _check_required_pairs_of_fields(self):
        if not self.errors and not any([
            (self.phone and self.email),
            (self.first_name and self.last_name),
            (self.gender is not None and self.birthday)
        ]):
            self.errors.extend([
                'Required one of the next pairs: phone-email, first_name-last_name, gender-birthday'.format()
            ])

    def _prepare_context(self, arguments):
        context = []
        for field in self.fields:
            ctx_field = arguments.get(field.label)
            if ctx_field is not None:
                context.append(field.label)
        return context

    def response(self, ctx, store, is_admin=False):
        if is_admin:
            score = 42
        else:
            score = get_score(
                store=store, phone=self.phone, email=self.email,
                first_name=self.first_name, last_name=self.last_name,
                birthday=self.birthday, gender=self.gender,
            )
        ctx.update({
            'has': self.context
        })
        return {'score': score}


class MethodRequest(RequestBaseClass):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    def __init__(self, request):
        request_body = request.get('body', {})
        self.account = request_body.get('account')
        self.login = request_body.get('login')
        self.token = request_body.get('token')
        self.arguments = request_body.get('arguments')
        self.method = request_body.get('method')
        super(MethodRequest, self).__init__(request_body)

        self.response_method = self._set_response_method()
        self._check_method_errors()

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN

    def _set_response_method(self):
        if not self.errors and self.arguments:
            if self.method == 'clients_interests':
                return ClientsInterestsRequest(self.arguments)
            elif self.method == 'online_score':
                return OnlineScoreRequest(self.arguments)
            else:
                self.errors.extend(['Method "{}" not found'.format(self.method)])
                return None
        else:
            return None

    def _check_method_errors(self):
        if self.response_method and self.response_method.errors:
            self.errors.extend(self.response_method.errors)

    def get_response(self, ctx, store):
        if self.response_method:
            return self.response_method.response(ctx, store, self.is_admin)
        else:
            return None


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
    elif method_req.arguments:
        code, response = OK, method_req.get_response(ctx=ctx, store=store)
    else:
        code, response = INVALID_REQUEST, ERRORS[INVALID_REQUEST]
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
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
