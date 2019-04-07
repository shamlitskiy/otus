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
from string import Template


config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
}

DATE_FORMAT = "%Y%m%d"
REPORT_TEMPLATE = "./static/report.html"
FILE_PATTERN = "nginx-access-ui.log-*"

CURRENT_DATE = dt.now().strftime(DATE_FORMAT)
REPORT_FILE = '{}-report.html'.format(CURRENT_DATE)


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


def _report_file_exists(report_dir):
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)
        return False
    report_file_dir = os.path.join(report_dir, REPORT_FILE)
    return os.path.exists(report_file_dir)


def _get_template(report_template):
    with open(report_template, 'r') as rprt:
        _template = rprt.read()
    return _template


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
    list_files = tuple(_file_dates(file_names))
    latest_log = max(list_files, key=lambda x: x['log_date'])
    return latest_log['name']


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


def percent(count, total):
        return count * 100.0 / total


def avg(summ, total):
    return summ / total


def median(values_list):
        n = len(values_list)
        if n < 1:
            return None
        if n % 2 == 1:
            central_value = n // 2
            return sorted(values_list)[central_value]
        else:
            left_central_val = n // 2 - 1
            right_central_val = n // 2 + 1
            return sum(sorted(values_list)[left_central_val:right_central_val]) / 2.0


@consumer
def count_url(urls):
    counter = collections.defaultdict(int)
    while True:
        r = (yield)
        if r is None:
            break
        counter[r['request']] += 1
    for s, c in counter.iteritems():
        urls[s].update({'count': c})


@consumer
def count_request_time(urls):
    summer = collections.defaultdict(int)
    while True:
        r = (yield)
        if r is None:
            break
        summer[r['request']] += r['request_time']
    for s, c in summer.iteritems():
        urls[s].update({'time_sum': c})


@consumer
def perc_urls(urls):
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
def perc_request_time(urls):
    total = 0
    while True:
        r = (yield)
        if r is None:
            break
        total += r['request_time']
    for url, val in urls.iteritems():
        time_summ = val.get('time_sum', 0)
        urls[url].update({
            'time_perc': percent(time_summ, total),
        })


@consumer
def avg_request_time(urls):
    total = 0
    while True:
        r = (yield)
        if r is None:
            break
        total += r['request_time']
    for url, val in urls.iteritems():
        time_summ = val.get('time_sum', 0)
        urls[url].update({
            'time_avg': avg(time_summ, total)
        })


@consumer
def calculate_time_max(urls):
    time_max = collections.defaultdict(int)
    while True:
        r = (yield)
        if r is None:
            break
        time_max[r['request']] = max([time_max.get(r['request'], 0), r['request_time']])
    for url, t in time_max.iteritems():
        urls[url].update({'time_max': t})


@consumer
def calculate_time_med(urls):
    time_med = collections.defaultdict(list)
    while True:
        r = (yield)
        if r is None:
            break
        time_med[r['request']].append(r['request_time'])
    for url, t in time_med.iteritems():
        urls[url].update({
            'time_med': median(t)
        })


def _float_to_str(fl_val):
    return '{:.3f}'.format(fl_val)


def prepare_data(data, data_size):
    result_data = []
    for c, v in data.iteritems():
        for k in v:
            v[k] = _float_to_str(v[k])

        result_data.append({
            'url': c,
            'count': v['count'],
            'count_perc': v['count_perc'],
            'time_sum': v['time_sum'],
            'time_perc': v['time_perc'],
            'time_max': v['time_max'],
            'time_avg': v['time_avg'],
            'time_med': v['time_med'],
        })
    result_data = sorted(result_data, key=lambda x: x['time_sum'], reverse=True)
    result_data = result_data[:data_size]
    result_data = json.dumps(result_data)
    return result_data


def save_to_file(report_data, report_dir):
    report = os.path.join(report_dir, REPORT_FILE)

    with open(report, 'w') as rprt:
        rprt.write(report_data)


def create_report(report_data, report_template):
    s = Template(_get_template(report_template))
    data_to_load = s.safe_substitute(table_json=report_data)
    return data_to_load


def main(_config):
    log_dir = _config['LOG_DIR']
    report_size = _config['REPORT_SIZE']
    report_dir = _config['REPORT_DIR']

    if _report_file_exists(report_dir):
        pass

    file_names = find_file(log_dir)
    last_log = get_latest_log(file_names)
    opened_file = file_open(last_log)
    data = get_data(opened_file)
    log_line_dict = process_line(data)

    urls_stats = collections.defaultdict(dict)
    funcs_list = [
        count_url(urls_stats),
        count_request_time(urls_stats),
        perc_urls(urls_stats),
        perc_request_time(urls_stats),
        avg_request_time(urls_stats),
        calculate_time_max(urls_stats),
        calculate_time_med(urls_stats),
    ]
    broadcast(log_line_dict, funcs_list)

    data_to_load = prepare_data(urls_stats, report_size)
    report = create_report(data_to_load, REPORT_TEMPLATE)
    save_to_file(report, report_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--config',
                        help='path to config file')
    args = parser.parse_args()
    cfg = init_config(config_path=args.config,
                      default=config)
    main(_config=cfg)
