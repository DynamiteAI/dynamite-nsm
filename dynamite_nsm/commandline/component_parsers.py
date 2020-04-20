import argparse

base_parser = argparse.ArgumentParser(add_help=False)

base_parser.add_argument(
    "--silent", dest="no_stdout", default=False, action="store_true", help="Disable terminal output.")

base_parser.add_argument(
    "--verbose", dest="verbose", default=False, action="store_true", help="Show verbose output.")

main_parser = argparse.ArgumentParser(description="Discover your network.")

component_subparsers = main_parser.add_subparsers()

# === Setup Components === #
agent_deps_component_parser = component_subparsers.add_parser(
    "agent-dependencies",
    help="Install Linux kernel development headers required for agent installation.")
agent_deps_component_parser.set_defaults(component_name="agent-dependencies")

elasticsearch_component_parser = component_subparsers.add_parser(
    "elasticsearch",
    help="Install, configure, manage ElasticSearch.")
elasticsearch_component_parser.set_defaults(component_name="elasticsearch")

logstash_component_parser = component_subparsers.add_parser(
    "logstash",
    help="Install, configure, manage LogStash.")
logstash_component_parser.set_defaults(component_name="logstash")

kibana_component_parser = component_subparsers.add_parser(
    "kibana",
    help="Install, configure, manage Kibana with pre-built "
         "Dynamite Analytic Views.")
kibana_component_parser.set_defaults(component_name="kibana")

monitor_component_parser = component_subparsers.add_parser(
    "monitor",
    help="Install, configure, manage standalone ELK "
         "[ElasticSearch + Logstash + Kibana] instance.")
monitor_component_parser.set_defaults(component_name="monitor")

agent_component_parser = component_subparsers.add_parser(
    "agent",
    help="Install, configure, manage the Dynamite Agent.")
agent_component_parser.set_defaults(component_name="agent")