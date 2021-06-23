import json
from typing import Dict, List, Optional


class InputLogs:

    def __init__(self, monitor_log_paths: List[str]):
        """A set of logs to monitor on the filesystem
        Args:
            monitor_log_paths: A list of logs to monitor
        """
        self.enabled = False
        self.monitor_log_paths = monitor_log_paths

    def __str__(self):
        return json.dumps(
            dict(
                obj_name=str(self.__class__),
                monitor_log_paths=self.monitor_log_paths
            )
        )

    def get_raw(self) -> List:
        """Get the raw representation of this config object.
        Returns:
            A list of input log paths
        """
        return [dict(
            enabled=self.enabled,
            paths=self.monitor_log_paths,
            type='log'
        )]


class IndexTemplateSettings:

    def __init__(self, index_name: str, index_pattern: Optional[str] = None, enabled: Optional[bool] = True,
                 overwrite: Optional[bool] = True):
        """Settings for index name and pattern for downstream Elasticsearch
        Args:
            index_name: The name of the index where to send logs (E.G dynamite-events-%{+yyyy.MM.dd})
            index_pattern: The corresponding index pattern (E.G dynamite-events-*)
        """
        self.enabled = enabled
        self.overwrite = overwrite
        self.index_name = index_name
        if index_pattern:
            self.index_pattern = index_pattern
        else:
            if index_name:
                self.index_pattern = f'{index_name}-*'
            else:
                self.index_pattern = f'filebeat-*'

    def __str__(self) -> str:
        return json.dumps(dict(
            obj_name=str(self.__class__),
            index_name=self.index_name,
            index_pattern=self.index_pattern,
            enabled=self.enabled,
            overwrite=self.overwrite,
        ))

    def get_raw(self) -> Dict:
        """Get the raw representation of this config object.
        Returns:
            A dictionary of index template settings
        """
        return dict(
            enabled=self.enabled,
            overwrite=self.overwrite,
            name=self.index_name,
            pattern=self.index_pattern
        )


class KibanaSettings:
    def __init__(self, kibana_target_str: str, kibana_protocol: str, enabled: Optional[bool] = False):
        """Settings for configuring an upstream Kibana instance
        Args:
            kibana_target_str: The URL to the Kibana instance w/o the protocol prefix (E.G 192.168.0.5:5601)
            kibana_protocol: http or https
        """
        self.enabled = enabled
        self.kibana_target_str = kibana_target_str
        self.kibana_protocol = kibana_protocol

    def __str__(self) -> str:
        return json.dumps(dict(
            obj_name=str(self.__class__),
            target=self.kibana_target_str,
            protocol=self.kibana_protocol,
            enabled=self.enabled
        ))

    def get_raw(self) -> Dict:
        """Get the raw representation of this config object.
        Returns:
            A dictionary of Kibana endpoint settings
        """
        return dict(
            enabled=self.enabled,
            host=self.kibana_target_str,
            protocol=self.kibana_protocol
        )


class FieldProcessors:

    def __init__(self, originating_agent_tag: str):
        """Add/remove/manipulate fields parsed by Filebeat
        Args:
            originating_agent_tag: The name for the Dynamite Agent which will be **added** to all events sent downstream
        """
        self.originating_agent_tag = originating_agent_tag

    def __str__(self) -> str:
        return json.dumps(
            dict(
                originating_agent_tag=self.originating_agent_tag
            )
        )

    def get_raw(self) -> List[Dict]:
        """Get the raw representation of this config object.
        Returns:
            A dictionary of Filebeat field processors
        """
        return [dict(
            add_fields=dict(
                fields=dict(
                    originating_agent_tag=self.originating_agent_tag
                )
            )
        )]

    @staticmethod
    def validate_agent_tag(agent_tag: str) -> bool:
        """Validate that the agent tag given is valid
        Args:
            agent_tag: The name of the agent

        Returns:
            True, if valid
        """
        import re
        agent_tag = str(agent_tag)
        tag_length_ok = 30 > len(agent_tag) > 5
        tag_match_pattern = bool(re.findall(r"^[a-zA-Z0-9_]*$", agent_tag))
        return tag_length_ok and tag_match_pattern
