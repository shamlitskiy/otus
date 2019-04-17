import unittest
import log_analyzer as lg


class MyTestCase(unittest.TestCase):
    def test_process_line(self):
        test_line = '1.169.137.128 -  - [29/Jun/2017:03:50:23 +0300]' \
                    ' "GET /api/v2/group/1823183/banners HTTP/1.1" 200 1002' \
                    ' "-" "Configovod" "-" "1498697423-2118016444-4708-9752777"' \
                    ' "712e90144abee9" 0.680'
        test_generator = (line for line in (test_line,))
        result_line = lg.process_line(test_generator)
        true_result_line = {
            'status': '200',
            'body_bytes_sent': '1002',
            'remote_user': '- ',
            'request_time': 0.68,
            'http_referer': '-',
            'remote_addr': '1.169.137.128',
            'http_x_forwarded_for': '-',
            'http_X_REQUEST_ID': '1498697423-2118016444-4708-9752777',
            'request': '/api/v2/group/1823183/banners',
            'http_user_agent': 'Configovod',
            'time_local': '29/Jun/2017:03:50:23 +0300',
            'http_X_RB_USER': '712e90144abee9',
            'http_x_real_ip': '-'
        }
        self.assertEqual(true_result_line, result_line.next())

    def test_avg(self):
        result = lg.average(1256, 56)
        self.assertEqual(22, result)

    def test_percent(self):
        result = lg.percent(count=100, total=500)
        self.assertEqual(20.0, result)

    def test_median(self):
        result = lg.median([1256, 3, 43, 76, 56])
        self.assertEqual(56, result)


if __name__ == '__main__':
    unittest.main()
