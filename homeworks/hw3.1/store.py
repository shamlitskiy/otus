import redis

HOST = ''
PORT = ''
PASSWORD = ''


class Store(object):
    def __init__(self):
        self.r = self._connection(HOST, PORT, PASSWORD)

    def _connection(self, host, port, password):
        return redis.Redis(
            host=host,
            port=port,
            password=password,
            socket_timeout=10000,
            socket_connect_timeout=3600,
            retry_on_timeout=False
        )

    def get(self, key):
        return self.r.get(key)

    def cache_get(self, key):
        return self.r.get(key)

    def cache_set(self, key, value, cache_expire):
        self.r.set(key, value)
        self.r.expire(key, cache_expire)