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


class FieldMeta(type):
    def __new__(cls, name, bases, attrs):
        for n, v in attrs.items():
            if isinstance(v, Field):
                v.label = n
        return super(FieldMeta, cls).__new__(cls, name, bases, attrs)


class Field(object):
    def __init__(self, value=None, required=False, nullable=True):
        self.label = None
        self.value = value
        self.required = required
        self.nullable = nullable

    def __set__(self, obj, val):
        if self.required and val is None:
            raise ValueError(
                'Field {label} is required'.format(label=self.label)
            )
        else:
            obj.__dict__[self.label] = val

    def __get__(self, obj, owner):
        return obj.__dict__.get(self.value, None)


class CharField(Field):
    def __set__(self, obj, val):
        super(CharField, self).__set__(obj, val)
        if not self.nullable and val == '':
            raise ValueError(
                'Field {label} is not nullable'.format(label=self.label)
            )


class ArgumentsField(Field):
    def __set__(self, *args, **kwargs):
        super(ArgumentsField, self).__set__(*args, **kwargs)


class EmailField(CharField):
    def __set__(self, *args, **kwargs):
        super(EmailField, self).__set__(*args, **kwargs)


class PhoneField(Field):
    def __set__(self, *args, **kwargs):
        super(PhoneField, self).__set__(*args, **kwargs)


class DateField(Field):
    def __set__(self, *args, **kwargs):
        super(DateField, self).__set__(*args, **kwargs)


class BirthDayField(Field):
    def __set__(self, *args, **kwargs):
        super(BirthDayField, self).__set__(*args, **kwargs)


class GenderField(Field):
    def __set__(self, *args, **kwargs):
        super(GenderField, self).__set__(*args, **kwargs)


class ClientIDsField(Field):
    def __set__(self, *args, **kwargs):
        super(ClientIDsField, self).__set__(*args, **kwargs)


class ClientsInterestsRequest(object):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(object):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)


class MethodRequest(object):
    __metaclass__ = FieldMeta

    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    def __init__(self, request):
        self.error = None
        try:
            self.account = request.get('account')
            self.login = request.get('login')
            self.token = request.get('token')
            self.arguments = request.get('arguments')
            self.method = request.get('method')
        except ValueError as e:
            self.error = e.message

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).hexdigest()
    else:
        digest = hashlib.sha512(request.account + request.login + SALT).hexdigest()
    if digest == request.token:
        return True
    return False


def online_score(store, phone, email, first_name, last_name, birthday, gender):
    score = get_score(
        store=store, phone=phone, email=email,
        first_name=first_name, last_name=last_name,
        birthday=birthday, gender=gender,
    )
    return score


def clients_interests(store, cid):
    interests = get_interests(
        store=store, cid=cid
    )
    return interests


def method_handler(request, ctx, store):
    code, response = None, None
    methods_dict = {
        'online_score': online_score,
        'clients_interests': clients_interests,
    }
    method_req = MethodRequest(request)
    if method_req.error:
        msg = '{error}. {msg}'.format(
            error=ERRORS[BAD_REQUEST],
            msg=method_req.error
        )
        code, response = BAD_REQUEST, msg
    elif not check_auth(method_req):
        code, response = FORBIDDEN, ERRORS[FORBIDDEN]
    else:
        method_to_call = methods_dict[method_req.method]
        method_args = method_req.arguments
        code, response = method_to_call(store, **method_args)
        # code, response = '200', 'Vse norm'
    return code, response


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
    # req = {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "token": "", "arguments": {}}
    req = {"account": "horns&hoofs", "method": "online_score", "token": "", "arguments": {}}
    a = MethodRequest(req)
    res = method_handler(req, 1, 1)
    print(a.__dict__)
