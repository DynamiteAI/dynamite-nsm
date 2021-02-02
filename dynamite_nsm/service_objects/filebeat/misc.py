import json
from typing import Dict, List, Optional


class InputLogs:

    def __init__(self, monitor_log_paths: List[str]):
        """
        A set of logs to monitor on the filesystem

        :param monitor_log_paths: A list of logs to monitor
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
        return [dict(
            enabled=self.enabled,
            paths=self.monitor_log_paths,
            type='log'
        )]


class IndexTemplateSettings:

    def __init__(self, index_name: str, index_pattern: Optional[str] = None):
        """

        :param index_name:
        :param index_pattern:
        """
        self.enabled = False
        self.index_name = index_name
        if index_pattern:
            self.index_pattern = index_pattern
        else:
            self.index_pattern = f'{index_name}-*'

    def __str__(self) -> str:
        return json.dumps(dict(
            obj_name=str(self.__class__),
            index_name=self.index_name,
            index_pattern=self.index_pattern,
            enabled=self.enabled
        ))

    def get_raw(self) -> Dict:
        return dict(
            enabled=self.enabled,
            name=self.index_name,
            pattern=self.index_pattern
        )


class FieldProcessors:

    def __init__(self, originating_agent_tag: str):
        self.originating_agent_tag = originating_agent_tag

    def __str__(self) -> str:
        return json.dumps(
            dict(
                originating_agent_tag=self.originating_agent_tag
            )
        )

    def get_raw(self) -> List:
        return [dict(
            add_fields=dict(
                fields=dict(
                    originating_agent_tag=self.originating_agent_tag
                )
            )
        )]

    @staticmethod
    def validate_agent_tag(agent_tag):
        import re
        agent_tag = str(agent_tag)
        tag_length_ok = 30 > len(agent_tag) > 5
        tag_match_pattern = bool(re.findall(r"^[a-zA-Z0-9_]*$", agent_tag))
        return tag_length_ok and tag_match_pattern
