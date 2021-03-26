import argparse

from typing import Optional


class BaseInterface:

    def __init__(self, interface_name: Optional[str] = None, interface_description: Optional[str] = None):
        self.interface_name = interface_name
        self.interface_description = interface_description

    def get_parser(self):
        raise NotImplementedError()

    def execute(self, args: argparse.Namespace):
        raise NotImplementedError()
