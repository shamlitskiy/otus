#!/usr/bin/env python
# -*- coding: utf-8 -*-

# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

from datetime import datetime as dt
import os
import sys
import traceback
import argparse
import json
import gzip
import re
import collections
import logging
from string import Template


config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "/Users/alex/PycharmProjects/otus/playground/homework_1/log",
    "LOGGING_FILE": "./log_analyzer.log",
}

DATE_FORMAT = "%Y%m%d"
REPORT_TEMPLATE = "./static/report.html"
FILE_PATTERN = "nginx-access-ui.log-*"

CURRENT_DATE = dt.now().strftime('%Y.%m.%d')
REPORT_FILE = 'report-{}.html'.format(CURRENT_DATE)
LOGGING_FORMAT = '[%(asctime)s] %(levelname).1s %(message)s'
LOGGING_DATE_FORMAT = '%Y.%m.%d %H:%M:%S'


def handle_exception(exc_type, exc_value, exc_traceback):
    traceback_msg = ''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    logging.exception('Uncaught exception.\n{}'.format(traceback_msg))


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
    except Exception as e:
        msg = ('Config file error: {}'.format(e.message))
        raise IOError(msg)


def report_file_exists(report_dir):
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)
        return False
    report_file_dir = os.path.join(report_dir, REPORT_FILE)
    return os.path.exists(report_file_dir)


def _get_template(report_template):
    with open(report_template, 'r') as rprt:
        _template = rprt.read()
    return _template


def log_dir_exists(log_dir):
    return os.path.exists(log_dir)


def find_file(file_dir):
    file_pattern = re.compile(r'nginx-access-ui[.]log-[0-9]+($|[.]gz$)')
    for path, dirs, files in os.walk(file_dir):
        for name in files:
            if file_pattern.match(name):
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
    if list_files:
        latest_log = max(list_files, key=lambda x: x['log_date'])
        return latest_log['name']
    else:
        return None


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


def average(summ, count):
    return summ / count


def median(values_seq):
        n = len(values_seq)
        if n < 1:
            return None
        if n % 2 == 1:
            central_value = n // 2
            return sorted(values_seq)[central_value]
        else:
            left_central_val = n // 2 - 1
            right_central_val = n // 2 + 1
            return sum(sorted(values_seq)[left_central_val:right_central_val]) / 2.0


@consumer
def get_urls_counts(urls_count):
    while True:
        r = (yield)
        if r is None:
            break
        urls_count[r['request']] += 1


@consumer
def get_total_values(total_values):
    while True:
        r = (yield)
        if r is None:
            break
        total_values['urls_count'] += 1
        total_values['time_total'] += r['request_time']


@consumer
def get_urls_times_list(urls_times_list):
    while True:
        r = (yield)
        if r is None:
            break
        urls_times_list[r['request']].append(r['request_time'])


def calculate_urls_stats(log_line_dict):
    urls_stats = []
    urls_count = collections.defaultdict(int)
    total_values = collections.defaultdict(int)
    urls_times_list = collections.defaultdict(list)

    funcs_list = [
        get_urls_counts(urls_count),
        get_total_values(total_values),
        get_urls_times_list(urls_times_list),
    ]
    broadcast(log_line_dict, funcs_list)

    urls_total = total_values['urls_count']
    time_total = total_values['time_total']
    for url, count in urls_count.iteritems():
        urls_percent = percent(count, urls_total)
        time_summ = sum(urls_times_list[url])
        time_perc = percent(time_summ, time_total)
        time_max = max(urls_times_list[url])
        time_avg = average(time_summ, count)
        time_med = median(urls_times_list[url])

        urls_stats.append({
            'url': url,
            'count': count,
            'count_perc': urls_percent,
            'time_sum': time_summ,
            'time_perc': time_perc,
            'time_max': time_max,
            'time_avg': time_avg,
            'time_med': time_med,
        })

    return urls_stats


def _float_to_str(fl_val):
    return '{:.3f}'.format(fl_val)


def prepare_data(data, data_size):
    for url in data:
        for k, v in url.iteritems():
            url[k] = _float_to_str(url[k]) if isinstance(url[k], float) else url[k]
    result_data = sorted(data, key=lambda x: x['time_sum'], reverse=True)
    result_data = result_data[:data_size]
    result_data = json.dumps(result_data)
    return result_data


def create_report(report_data, report_template):
    s = Template(_get_template(report_template))
    data_to_load = s.safe_substitute(table_json=report_data)
    return data_to_load


def save_to_file(report_data, report_dir):
    report = os.path.join(report_dir, REPORT_FILE)
    with open(report, 'w') as rprt:
        rprt.write(report_data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config',
                        help='path to config file')
    args = parser.parse_args()

    cfg = init_config(config_path=args.config, default=config)

    logging.basicConfig(
        filename=cfg['LOGGING_FILE'] if cfg['LOGGING_FILE'] else None,
        format=LOGGING_FORMAT,
        datefmt=LOGGING_DATE_FORMAT,
        level=logging.INFO
    )
    sys.excepthook = handle_exception

    log_dir = cfg['LOG_DIR']
    if not log_dir_exists(log_dir):
        logging.info("Log dir don't exist.")
        return

    report_size = cfg['REPORT_SIZE']
    report_dir = cfg['REPORT_DIR']
    if report_file_exists(report_dir):
        logging.info('Report file already exists.')
        return

    file_names = find_file(log_dir)
    if not file_names:
        logging.info('Log dir are empty.')
        return

    last_log = get_latest_log(file_names)
    opened_file = file_open(last_log)
    data = get_data(opened_file)
    log_line_dict = process_line(data)

    urls_stats = calculate_urls_stats(log_line_dict)

    data_to_load = prepare_data(urls_stats, report_size)
    report = create_report(data_to_load, REPORT_TEMPLATE)
    save_to_file(report, report_dir)


if __name__ == "__main__":
    main()
