#!/usr/bin/env python
# -*- coding: utf-8 -*-

# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

from datetime import datetime as dt
import os
import sys
import argparse
import json
import fnmatch
import gzip
import re
import collections


config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
}

DATE_FORMAT = "%Y%m%d"
REPORT_TEMPLATE = "report.html"
FILE_PATTERN = "nginx-access-ui.log-*"


def init_config(config_path, default):
    result_config = {}
    if config_path:
        _config = _get_config_from_file(config_path)
        for cfg_key in default:
            result_config[cfg_key] = _config.get(cfg_key, default[cfg_key])
    else:
        result_config = default
    return result_config


def _get_config_from_file(config_path):
    try:
        with open(config_path, 'r') as cfg:
            config_dict = json.load(cfg)
        return config_dict
    except IOError as e:
        print ('{}: {}'.format(e.strerror, e.filename))
    except ValueError:
        print ('Wrong JSON')
    sys.exit()


def find_file(file_dir):
    for path, dirs, files in os.walk(file_dir):
        for name in fnmatch.filter(files, FILE_PATTERN):
            yield os.path.join(path, name)


def _file_dates(filenames):
    data_pattern = re.compile(r'.*-(?P<log_date>\d{8}).*')
    for name in filenames:
        found = data_pattern.match(name)
        if found:
            log_date = dt.strptime(found.group('log_date'), DATE_FORMAT)
            yield {'name': name, 'log_date': log_date}


def get_latest_log(file_names):
    list_files = list(_file_dates(file_names))
    return max(list_files, key=lambda x: x['log_date'])


def file_open(filename):
    if filename.endswith(".gz"):
        yield gzip.open(filename)
    else:
        yield open(filename)


def get_data(file_name):
    for s in file_name:
        for item in s:
            yield item


def process_line(log_line):
    # $remote_addr          $remote_user            $http_x_real_ip     [$time_local] 
    # "$request"            $status                 $body_bytes_sent    "$http_referer"
    # "$http_user_agent" "  $http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER"
    # $request_time;
    log_pattern = (r'(?P<remote_addr>.+) (?P<remote_user>.+) (?P<http_x_real_ip>.+) [[](?P<time_local>.+)[]] '
                   r'".* (?P<request>.+) .*" (?P<status>\d+) (?P<body_bytes_sent>\d+) "(?P<http_referer>.+)" '
                   r'"(?P<http_user_agent>.+)" "(?P<http_x_forwarded_for>.+)" "(?P<http_X_REQUEST_ID>.+)" '
                   r'"(?P<http_X_RB_USER>.+)" (?P<request_time>.+)')
    parse_line = re.compile(log_pattern)
    groups = (parse_line.match(line) for line in log_line)
    log = (g.groupdict() for g in groups if g)
    log = field_map(log, "request_time", lambda s: float(s) if s != '-' else 0)
    return log


def field_map(dictseq, name, func):
    for d in dictseq:
        d[name] = func(d[name])
        yield d


def broadcast(source, consumers):
    for item in source:
        for c in consumers:
            c.send(item)
    for c in consumers:
        try:
            c.send(None)
        except StopIteration:
            pass


def consumer(func):
    def start(*args, **kwargs):
        c = func(*args, **kwargs)
        c.next()
        return c
    return start


@consumer
def url_count(urls):
    counter = collections.defaultdict(int)
    while True:
        r = (yield)
        if r is None:
            break
        counter[r['request']] += 1
    for s, c in counter.iteritems():
        urls[s].update({'count': c})


@consumer
def url_request_time(urls):
    summer = collections.defaultdict(int)
    while True:
        r = (yield)
        if r is None:
            break
        summer[r['request']] += r['request_time']
    for s, c in summer.iteritems():
        urls[s].update({'time_sum': c})


def percent(count, total):
        return count * 100.0 / total


def avg(summ, total):
    return summ / total


@consumer
def urls_total_count(urls):
    total = 0
    while True:
        r = (yield)
        if r is None:
            break
        total += 1
    for url, val in urls.iteritems():
        urls[url].update({
            'count_perc': percent(val['count'], total)
        })


@consumer
def total_request_time(urls):
    total = 0
    while True:
        r = (yield)
        if r is None:
            break
        total += r['request_time']
    for url, val in urls.iteritems():
        time_summ = val['time_sum']
        urls[url].update({
            'time_perc': percent(time_summ, total),
            'time_avg': avg(time_summ, total)
        })


@consumer
def calculate_time_max(urls):
    max_time = collections.defaultdict(int)
    while True:
        r = (yield)
        if r is None:
            break
        max_time[r['request']] = max([max_time.get(r['request'], 0), r['request_time']])
    for s, c in max_time.iteritems():
        urls[s].update({'time_max': c})


def calculate_time_med():
    pass


def create_report():
    pass


def save_report_file():
    pass


def main(_config):
    file_names = find_file(
        _config['LOG_DIR']
    )
    last_log = get_latest_log(file_names)
    opened_file = file_open(last_log['name'])
    data = get_data(opened_file)
    line_dict = process_line(data)
    urls = collections.defaultdict(dict)
    func_list = [
        url_count(urls),
        url_request_time(urls),
        total_request_time(urls),
        calculate_time_max(urls),
    ]
    broadcast(line_dict, func_list)

    report_file = os.path.join(_config['REPORT_DIR'], 'report_file_1')

    for k, v in urls.iteritems():
        print('{}: {}'.format(k, v))
    print('!')


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--config',
                        help='path to config file')
    args = parser.parse_args()
    cfg = init_config(config_path=args.config,
                      default=config)
    main(_config=cfg)
