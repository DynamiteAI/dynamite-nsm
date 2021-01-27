import json

from typing import Dict, List, TypeVar, Optional

TargetClass = TypeVar('TargetClass')


class InvalidTargetString(TypeError):
    """
    Thrown when target is invalid
    """

    def __init__(self, target_string):
        """
        :param target_string: The full target string
        """
        msg = f'Filebeat Target is invalid expected: (http|https)//(url|ip):port) got: {target_string}'
        super(InvalidTargetString, self).__init__(msg)


class BaseTargets:

    def __init__(self, target_strings: List[str], ssl_certificate_authorities: Optional[str] = None,
                 ssl_certificate: Optional[str] = None,
                 ssl_key: Optional[str] = None, ssl_verification_mode: Optional[str] = 'certificate',
                 enabled: Optional[bool] = False):
        self.target_strings = target_strings
        self.ssl_certificate_authorities = ssl_certificate_authorities
        self.ssl_certificate = ssl_certificate
        self.ssl_key = ssl_key
        self.ssl_verification_mode = ssl_verification_mode
        self.enabled = enabled

    def __str__(self) -> str:
        return json.dumps(
            dict(
                obj_name=str(self.__class__),
                target_strings=self.target_strings,
                ssl_certificate_authorities=self.ssl_certificate_authorities,
                ssl_certificate=self.ssl_certificate,
                ssl_verification_mode=self.ssl_verification_mode
            )
        )

    def get_raw(self) -> Dict:
        ssl = dict(
            certificate_authorities=self.ssl_certificate_authorities,
            certificate=self.ssl_certificate,
            key=self.ssl_key,
            verification_mode=self.ssl_verification_mode
        )
        ssl = {k: v for k, v in ssl.items() if v is not None}
        return dict(
            hosts=self.target_strings,
            enabled=self.enabled,
            ssl=ssl

        )


class ElasticsearchTargets(BaseTargets):

    def __init__(self, target_strings: List[str], index: Optional[str] = 'filebeat-%{[agent.version]}-%{+yyyy.MM.dd}',
                 username: Optional[str] = None, password: Optional[str] = None,
                 ssl_certificate_authorities: Optional[str] = None,
                 ssl_certificate: Optional[str] = None, ssl_key: Optional[str] = None,
                 ssl_verification_mode: Optional[str] = 'certificate', enabled: Optional[bool] = False):
        """
        Define ElasticSearch endpoints where events should be sent

        :param target_strings: The list of Elasticsearch nodes to connect to.
                             The events are distributed to these nodes in round robin order.
        :param index: The index name to write events to.
        :param username: The basic authentication username for connecting to Elasticsearch.
        :param password: The basic authentication password for connecting to Elasticsearch.
        :param ssl_certificate_authorities: The list of root certificates for server verifications.
               If certificate_authorities is empty or not set, the trusted certificate authorities of the host
               system are used. (E.G ["/etc/pki/root/ca.pem"])
        :param ssl_certificate: The path to the certificate for SSL client authentication.
               If the certificate is not specified, client authentication is not available.
               The connection might fail if the server requests client authentication.
        :param ssl_key: The client certificate key used for client authentication. This option is required if
               ssl_certificate is specified.
        :param ssl_verification_mode: This option controls whether the client verifies server certificates and host
               names.
        """
        super().__init__(target_strings, ssl_certificate_authorities, ssl_certificate, ssl_key, ssl_verification_mode,
                         enabled=enabled)
        self.index = index
        self.username = username
        self.password = password

    def get_raw(self) -> Dict:
        orig_raw = super().get_raw()
        orig_raw.update(
            dict(
                index=self.index,
                username=self.username,
                password=self.password
            )
        )
        orig_raw = {k: v for k, v in orig_raw.items() if v is not None and v != ''}
        return orig_raw


class KafkaTargets(BaseTargets):

    def __init__(self, target_strings: List[str], topic: Optional[str] = None, username: Optional[str] = None,
                 password: Optional[str] = None, ssl_certificate_authorities: Optional[str] = None,
                 ssl_certificate: Optional[str] = None, ssl_key: Optional[str] = None,
                 ssl_verification_mode: Optional[str] = None, enabled: Optional[bool] = False):
        """
        Define Kafka endpoints where events should be sent

        :param target_strings: A list of Kafka brokers, and their service port (E.G ["192.168.0.9:5044"])
        :param topic: A Kafka topic
        :param username: The username used to authenticate to Kafka broker
        :param password: The password used to authenticate to Kafka broker,
        :param ssl_certificate_authorities: The list of root certificates for server verifications.
               If certificate_authorities is empty or not set, the trusted certificate authorities of the host
               system are used. (E.G ["/etc/pki/root/ca.pem"])
        :param ssl_certificate: The path to the certificate for SSL client authentication.
               If the certificate is not specified, client authentication is not available.
               The connection might fail if the server requests client authentication.
        :param ssl_key: The client certificate key used for client authentication. This option is required if
               ssl_certificate is specified.
        :param ssl_verification_mode: This option controls whether the client verifies server certificates and host
               names.
        """
        super().__init__(target_strings, ssl_certificate_authorities, ssl_certificate, ssl_key, ssl_verification_mode,
                         enabled)
        self.topic = topic
        self.username = username
        self.password = password

    def __str__(self) -> str:
        orig_raw = self.get_raw()
        orig_raw.update(dict(obj_name=str(self.__class__)))
        return json.dumps(orig_raw)

    def get_raw(self) -> Dict:
        orig_raw = super().get_raw()
        orig_raw.update(
            dict(
                topic=self.topic,
                username=self.username,
                password=self.password
            )
        )
        orig_raw = {k: v for k, v in orig_raw.items() if v is not None and v != ''}
        return orig_raw


class LogstashTargets(BaseTargets):

    def __init__(self, target_strings: List[str], index: Optional[str] = 'filebeat-%{[agent.version]}-%{+yyyy.MM.dd}',
                 load_balance: Optional[bool] = True,
                 socks_5_proxy_url: Optional[str] = None,
                 pipelines: Optional[int] = 2, max_batch_size: Optional[int] = 2048,
                 ssl_certificate_authorities: Optional[str] = None,
                 ssl_certificate: Optional[str] = None, ssl_key: Optional[str] = None,
                 ssl_verification_mode: Optional[str] = 'certificate', enabled: Optional[bool] = False):
        """
        Define LogStash endpoints where events should be sent

        :param target_strings: A list of Logstash hosts, and their service port (E.G ["192.168.0.9:5044"])
        :param load_balance: If set to true and multiple Logstash hosts are configured, the output plugin load balances
               published events onto all Logstash hosts.
        :param index: The name of the index to include in the %{[@metadata][beat]} field
        :param socks_5_proxy_url: The full url to the SOCKS5 proxy used for encapsulating the beat protocol
        :param pipelines: Configures the number of batches to be sent asynchronously to Logstash
        :param max_batch_size: The maximum number of events to bulk in a single Logstash request.
        :param ssl_certificate_authorities: The list of root certificates for server verifications.
               If certificate_authorities is empty or not set, the trusted certificate authorities of the host
               system are used. (E.G ["/etc/pki/root/ca.pem"])
        :param ssl_certificate: The path to the certificate for SSL client authentication.
               If the certificate is not specified, client authentication is not available.
               The connection might fail if the server requests client authentication.
        :param ssl_key: The client certificate key used for client authentication. This option is required if
               ssl_certificate is specified.
        :param ssl_verification_mode: This option controls whether the client verifies server certificates and host
               names.
                - full, which verifies that the provided certificate is signed by a trusted authority (CA)
                  and also verifies that the server’s hostname (or IP address) matches the names identified within the
                  certificate.
                - certificate, which verifies that the provided certificate is signed by a trusted authority (CA),
                  but does not perform any hostname verification.
                - none, which performs no verification of the server’s certificate.
                  This mode disables many of the security benefits of SSL/TLS and should only be used
                  after very careful consideration.
                  It is primarily intended as a temporary diagnostic mechanism when attempting to resolve TLS errors;
                  its use in production environments is strongly discouraged.
        """
        self.index = index
        self.load_balance = load_balance
        self.socks_5_proxy_url = socks_5_proxy_url
        self.pipelines = pipelines
        self.max_batch_size = max_batch_size
        super().__init__(target_strings, ssl_certificate_authorities, ssl_certificate, ssl_key, ssl_verification_mode,
                         enabled)

    def __str__(self) -> str:
        orig_raw = self.get_raw()
        orig_raw.update(dict(obj_name=str(self.__class__)))
        return json.dumps(orig_raw)

    def get_raw(self) -> Dict:
        orig_raw = super().get_raw()
        orig_raw.update(
            dict(
                index=self.index,
                loadbalance=self.load_balance,
                proxy_url=self.socks_5_proxy_url,
                pipelining=self.pipelines,
                bulk_max_size=self.max_batch_size
            )
        )
        orig_raw = {k: v for k, v in orig_raw.items() if v is not None and v != ''}
        return orig_raw


class RedisTargets(BaseTargets):

    def __init__(self, target_strings: List[str], index: Optional[str] = 'filebeat-%{[agent.version]}-%{+yyyy.MM.dd}',
                 load_balance: Optional[bool] = True, socks_5_proxy_url: Optional[str] = None,
                 workers: Optional[int] = 1, max_batch_size: Optional[int] = 2048, db: Optional[int] = 0,
                 password: Optional[str] = None, ssl_certificate_authorities: Optional[str] = None,
                 ssl_certificate: Optional[str] = None, ssl_key: Optional[str] = None,
                 ssl_verification_mode: Optional[str] = 'certificate', enabled: Optional[bool] = False):
        """
        :param target_strings: A list of Redis hosts, and their service port (E.G ["192.168.0.9:6379"]
        :param index: The key format string to use. If this string contains field references,
               such as %{[fields.name]}, the fields must exist, or the rule fails.
        :param load_balance: If set to true and multiple hosts or workers are configured, the output plugin load
               balances published events onto all Redis hosts. If set to false, the output plugin sends all events to
               only one host (determined at random) and will switch to another host if the currently selected one
               becomes unreachable. The default value is true.
        :param socks_5_proxy_url: The full url to the SOCKS5 proxy used for encapsulating the beat protocol
        :param workers: The number of workers to use for each host configured to publish events to Redis.
               Use this setting along with the load_balance option.
               For example, if you have 2 hosts and 3 workers,
               in total 6 workers are started (3 for each host).
        :param max_batch_size: The maximum number of events to bulk in a single Redis request or pipeline.
               The default is 2048.
        :param password: The password to authenticate with. The default is no authentication.
        :param db: The Redis database number where the events are published. The default is 0.
        :param ssl_certificate_authorities: The list of root certificates for server verifications.
               If certificate_authorities is empty or not set, the trusted certificate authorities of the host
               system are used. (E.G ["/etc/pki/root/ca.pem"])
        :param ssl_certificate: The path to the certificate for SSL client authentication.
               If the certificate is not specified, client authentication is not available.
               The connection might fail if the server requests client authentication.
        :param ssl_key: The client certificate key used for client authentication. This option is required if
               ssl_certificate is specified.
        :param ssl_verification_mode: This option controls whether the client verifies server certificates and host
               names.
        """
        super().__init__(target_strings, ssl_certificate_authorities, ssl_certificate, ssl_key, ssl_verification_mode,
                         enabled)
        self.index = index
        self.socks_5_proxy_url = socks_5_proxy_url
        self.workers = workers
        self.max_batch_size = max_batch_size
        self.db = db
        self.load_balance = load_balance
        self.password = password

    def __str__(self) -> str:
        orig_raw = self.get_raw()
        orig_raw.update(dict(obj_name=str(self.__class__)))
        return json.dumps(orig_raw)

    def get_raw(self) -> Dict:
        orig_raw = super().get_raw()
        orig_raw.update(
            dict(
                index=self.index,
                proxy_url=self.socks_5_proxy_url,
                loadbalance=self.load_balance,
                worker=self.workers,
                bulk_max_size=self.max_batch_size,
                db=self.db,
                password=self.password
            )
        )
        orig_raw = {k: v for k, v in orig_raw.items() if v is not None and v != ''}
        return orig_raw
