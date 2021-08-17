import json

from typing import Dict, List, TypeVar, Optional

TargetClass = TypeVar('TargetClass')


class InvalidTargetString(TypeError):

    def __init__(self, target_string):
        """Invalid Filebeat Target
        Args:
            target_string: The full target string
        """
        msg = f'Filebeat Target is invalid expected: (http|https)//(url|ip):port) got: {target_string}'
        super(InvalidTargetString, self).__init__(msg)


class BaseTargets:

    def __init__(self, target_strings: List[str], ssl_certificate_authorities: Optional[str] = None,
                 ssl_certificate: Optional[str] = None,
                 ssl_key: Optional[str] = None, ssl_verification_mode: Optional[str] = 'certificate',
                 enabled: Optional[bool] = False, ssl_enabled: Optional[bool] = False):
        """An abstract object from which all Filebeat targets are derived
        Args:
            target_strings: The list of downstream servers to connect to
            ssl_certificate_authorities: The list of root certificates for server verifications.
                If certificate_authorities is empty or not set, the trusted certificate authorities of the host
                system are used. (E.G ["/etc/pki/root/ca.pem"])
            ssl_certificate: The path to the certificate for SSL client authentication.
            If the certificate is not specified, client authentication is not available.
            The connection might fail if the server requests client authentication.
            ssl_key: The client certificate key used for client authentication.
                This option is required if ssl_certificate is specified.
            ssl_verification_mode: This option controls whether the client verifies server certificates and host names.
            enabled: If True, Filebeat will attempt to send events to this target
            ssl_enabled: If True, The SSL transport settings will be used
            ssl_certificate_authorities: The list of root certificates for server verifications.
                If certificate_authorities is empty or not set, the trusted certificate authorities of the host
                system are used. (E.G ["/etc/pki/root/ca.pem"])
            ssl_certificate: The path to the certificate for SSL client authentication.
            If the certificate is not specified, client authentication is not available.
            The connection might fail if the server requests client authentication.
            ssl_key: The client certificate key used for client authentication.
                This option is required if ssl_certificate is specified.
            ssl_verification_mode: This option controls whether the client verifies server certificates and host names.
        """
        self.target_strings = target_strings
        self.ssl_certificate_authorities = ssl_certificate_authorities if not None else []
        self.ssl_certificate = ssl_certificate
        self.ssl_key = ssl_key
        self.ssl_verification_mode = ssl_verification_mode
        self.enabled = enabled
        self.ssl_enabled = ssl_enabled

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
        """Get the raw representation of this config object.
        Returns:
            A configuration dictionary representing a downstream connector where to send logs
        """
        ssl = dict(
            certificate_authorities=self.ssl_certificate_authorities,
            certificate=self.ssl_certificate,
            key=self.ssl_key,
            verification_mode=self.ssl_verification_mode
        )
        ssl = {k: v for k, v in ssl.items() if v is not None}
        raw = dict(
            hosts=self.target_strings,
            enabled=self.enabled,
        )
        if self.ssl_enabled:
            raw.update(ssl=ssl)
        return raw


class ElasticsearchTargets(BaseTargets):

    def __init__(self, target_strings: List[str], index: Optional[str] = 'filebeat-%{[agent.version]}-%{+yyyy.MM.dd}',
                 username: Optional[str] = None, password: Optional[str] = None,
                 ssl_certificate_authorities: Optional[str] = None,
                 ssl_certificate: Optional[str] = None, ssl_key: Optional[str] = None,
                 ssl_verification_mode: Optional[str] = 'certificate', enabled: Optional[bool] = False,
                 ssl_enabled: Optional[bool] = False):
        """Elasticsearch endpoint configuration where events should be sent
        Args:
            target_strings: The list of Elasticsearch nodes to connect to.
            index: The index name to write events to.
            username: The basic authentication username for connecting to Elasticsearch.
            password: The basic authentication password for connecting to Elasticsearch.
            enabled: If True, Filebeat will attempt to send events to this target
            ssl_enabled: If True, The SSL transport settings will be used
            ssl_certificate_authorities: The list of root certificates for server verifications.
            ssl_certificate: The path to the certificate for SSL client authentication.
            ssl_key: The client certificate key used for client authentication.
            ssl_verification_mode: This option controls whether the client verifies server certificates and host names.
        """
        super().__init__(target_strings, ssl_certificate_authorities, ssl_certificate, ssl_key, ssl_verification_mode,
                         enabled=enabled, ssl_enabled=ssl_enabled)
        self.index = index
        self.username = username
        self.password = password

    def get_raw(self) -> Dict:
        """Get the raw representation of this config object.
        Returns:
            A configuration dictionary representing a elasticsearch connector where to send logs
        """
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
                 ssl_verification_mode: Optional[str] = None, enabled: Optional[bool] = False,
                 ssl_enabled: Optional[bool] = False):
        """Kafka endpoint configuration where events should be sent
        Args:
            target_strings: A list of Kafka brokers, and their service port (E.G ["192.168.0.9 5044"])
            topic: A Kafka topic
            username: The username used to authenticate to Kafka broker
            password: The password used to authenticate to Kafka broker
            enabled: If True, Filebeat will attempt to send events to this target
            ssl_enabled: If True, The SSL transport settings will be used
            ssl_certificate_authorities: The list of root certificates for server verifications.
            ssl_certificate: The path to the certificate for SSL client authentication.
            ssl_key: The client certificate key used for client authentication.
            ssl_verification_mode: This option controls whether the client verifies server certificates and host names.
        """
        super().__init__(target_strings, ssl_certificate_authorities, ssl_certificate, ssl_key, ssl_verification_mode,
                         enabled, ssl_enabled=ssl_enabled)
        self.topic = topic
        self.username = username
        self.password = password

    def __str__(self) -> str:
        orig_raw = self.get_raw()
        orig_raw.update(dict(obj_name=str(self.__class__)))
        return json.dumps(orig_raw)

    def get_raw(self) -> Dict:
        """Get the raw representation of this config object.

        Returns:
            A configuration dictionary representing a kafka connector where to send logs
        """
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
                 ssl_verification_mode: Optional[str] = 'certificate', enabled: Optional[bool] = False,
                 ssl_enabled: Optional[bool] = False):
        """Logstash endpoint configuration where events should be sent
        Args:
            target_strings: A list of Logstash hosts, and their service port (E.G ["192.168.0.9 5044"])
            load_balance: If included and multiple Logstash hosts are configured load-balance between them
            index: The name of the index to include in the @metadata.beat field
            socks_5_proxy_url: The full url to the SOCKS5 proxy used for encapsulating the beat protocol
            pipelines: Configures the number of batches to be sent asynchronously to Logstash
            max_batch_size: The maximum number of events to bulk in a single Logstash request.
            enabled: If True, Filebeat will attempt to send events to this target
            ssl_enabled: If True, The SSL transport settings will be used
            ssl_certificate_authorities: The list of root certificates for server verifications.
            ssl_certificate: The path to the certificate for SSL client authentication.
            ssl_key: The client certificate key used for client authentication.
            ssl_verification_mode: This option controls whether the client verifies server certificates and host names.
        """

        self.index = index
        self.load_balance = load_balance
        self.socks_5_proxy_url = socks_5_proxy_url
        self.pipelines = pipelines
        self.max_batch_size = max_batch_size
        super().__init__(target_strings, ssl_certificate_authorities, ssl_certificate, ssl_key, ssl_verification_mode,
                         enabled, ssl_enabled=ssl_enabled)

    def __str__(self) -> str:
        orig_raw = self.get_raw()
        orig_raw.update(dict(obj_name=str(self.__class__)))
        return json.dumps(orig_raw)

    def get_raw(self) -> Dict:
        """Get the raw representation of this config object.
        Returns:
            A configuration dictionary representing a logstash connector where to send logs
        """
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
                 ssl_verification_mode: Optional[str] = 'certificate', enabled: Optional[bool] = False,
                 ssl_enabled: Optional[bool] = False):
        """Redis endpoint configuration where events should be sent
        Args:
            target_strings: A list of Redis hosts, and their service port (E.G ["192.168.0.9 6379"]
            index: The key format string to use.
            load_balance: If included and multiple Redis hosts are configured load-balance between them
            socks_5_proxy_url: The full url to the SOCKS5 proxy used for encapsulating the beat protocol
            workers: The number of workers to use for each host configured to publish events to Redis.
            max_batch_size: The maximum number of events to bulk in a single Redis request or pipeline.
            password: The password to authenticate with. The default is no authentication.
            db: The Redis database number where the events are published. The default is 0.
            enabled: If True, Filebeat will attempt to send events to this target
            ssl_enabled: If True, The SSL transport settings will be used
            ssl_certificate_authorities: The list of root certificates for server verifications.
            ssl_certificate: The path to the certificate for SSL client authentication.
            ssl_key: The client certificate key used for client authentication.
            ssl_verification_mode: This option controls whether the client verifies server certificates and host names.
        """
        super().__init__(target_strings, ssl_certificate_authorities, ssl_certificate, ssl_key, ssl_verification_mode,
                         enabled, ssl_enabled=ssl_enabled)
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
        """Get the raw representation of this config object.
        Returns:
            A configuration dictionary representing a redis connector where to send logs
        """
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
