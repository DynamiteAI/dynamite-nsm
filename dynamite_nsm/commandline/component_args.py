from dynamite_nsm.utilities import get_default_agent_tag


def register_agent_dependency_component_args(agt_deps_component_parser, parent_parsers):
    agt_deps_component_parser = agt_deps_component_parser.add_subparsers()
    # === Setup Agent Dependency Component Install Arguments === #
    agt_deps_install_parser = agt_deps_component_parser.add_parser(
        "install",
        help="Install Agent Dependencies (Requires Reboot).", parents=parent_parsers)

    agt_deps_install_parser.set_defaults(action_name="install")


def register_agent_component_args(agt_component_parser, parent_parsers):
    agent_component_args_subparsers = agt_component_parser.add_subparsers()

    # === Setup Agent Component Install Arguments === #
    agt_install_parser = agent_component_args_subparsers.add_parser(
        "install", help="Install Agent.",
        parents=parent_parsers)
    agt_install_parser.set_defaults(action_name="install")
    agt_install_parser.add_argument("--capture-interfaces", dest="agent_capture_interfaces", type=str, nargs='+',
                                    required=True, help="A list of network interfaces. (E.G mon0 mon1 mon2)"
                                    )
    agt_install_parser.add_argument("--ls-targets", dest="logstash_targets", type=str, nargs='+', required=True,
                                    help="A list of LogStash targets. (E.G 192.168.0.1:5044 192.168.0.100:5044)"
                                    )
    agt_install_parser.add_argument("--analyzers", dest="agent_analyzers", type=str, default=['zeek', 'suricata'],
                                    help="A list of analyzers to enable on this agent instance (E.G zeek suricata)"
                                    )
    agt_install_parser.add_argument("--tag", dest="agent_tag", type=str, default=None,
                                    help="A friendly identifier for this agent. Defaults to {}.".format(
                                        get_default_agent_tag())
                                    )

    # === Setup Agent Component Uninstall Arguments === #
    agt_uninstall_parser = agent_component_args_subparsers.add_parser(
        "uninstall",
        help="Uninstall Agent.",
        parents=parent_parsers)
    agt_uninstall_parser.add_argument(
        '--skip-uninstall-prompt', dest="skip_agent_uninstall_prompt", default=False,
        action="store_true", help="Skip prompting uninstall prompt.")
    agt_uninstall_parser.set_defaults(action_name="uninstall")

    # === Setup Agent Component Start Arguments === #
    agt_start_parser = agent_component_args_subparsers.add_parser(
        "start", help="Start Agent.",
        parents=parent_parsers)
    agt_start_parser.set_defaults(action_name="start")

    # === Setup Agent Component Stop Arguments === #
    agt_stop_parser = agent_component_args_subparsers.add_parser(
        "stop", help="Stop Agent.",
        parents=parent_parsers)
    agt_stop_parser.set_defaults(action_name="stop")

    # === Setup Agent Component Restart Arguments === #
    agt_restart_parser = agent_component_args_subparsers.add_parser(
        "restart", help="Restart Agent.",
        parents=parent_parsers)
    agt_restart_parser.set_defaults(action_name="restart")

    # === Setup Agent Component Status Arguments === #
    ls_status_parser = agent_component_args_subparsers.add_parser(
        "status", help="Status Agent.",
        parents=parent_parsers)
    ls_status_parser.set_defaults(action_name="status")


def register_monitor_component_args(mon_component_parser, parent_parsers):
    monitor_component_args_subparsers = mon_component_parser.add_subparsers()
    # === Setup Monitor Component Install Arguments === #
    mon_install_parser = monitor_component_args_subparsers.add_parser(
        "install", help="Install Monitor.",
        parents=parent_parsers)
    mon_install_parser.set_defaults(action_name="install")

    mon_install_parser.add_argument("--ls-listen-addr", dest="ls_addr", type=str, default='0.0.0.0',
                                    help="The address upon which Monitor input plugins listen."
                                    )
    mon_install_parser.add_argument("--kb-listen-addr", dest="kb_addr", type=str, default='0.0.0.0',
                                    help="The address upon which Kibana web interface listens."
                                    )
    mon_install_parser.add_argument("--kb-listen-port", dest="kb_port", type=str, default=5601,
                                    help="The port upon which Kibana web interface listens."
                                    )
    mon_install_parser.add_argument("--es-heap-size", dest="elastic_heap_size", type=int, default=4,
                                    help="The amount of memory to designate to ElasticSearch's Java Heap [Gi]"
                                    )
    mon_install_parser.add_argument("--es-host", dest="es_host", type=str, default='localhost',
                                    help="The host where ElasticSearch lives."
                                    )
    mon_install_parser.add_argument("--es-port", dest="es_port", type=int, default=9200,
                                    help="The port that ElasticSearch is listening on."
                                    )
    mon_install_parser.add_argument("--ls-heap-size", dest="ls_heap_size", type=int, default=4,
                                    help="The amount of memory to designate to Monitor's Java Heap [Gi]"
                                    )
    mon_install_parser.add_argument("--es-password", dest="elastic_password", type=str,
                                    help="The password used for logging into ElasticSearch."
                                    )
    mon_install_parser.add_argument("--skip-install-jdk", dest="skip_monitor_install_jdk", default=False,
                                    action="store_true",
                                    help="Skip the installation of Java 11 Development Environment."
                                    )

    # === Setup Monitor Component Uninstall Arguments === #
    mon_uninstall_parser = monitor_component_args_subparsers.add_parser(
        "uninstall",
        help="Uninstall Monitor.",
        parents=parent_parsers)
    mon_uninstall_parser.add_argument(
        '--skip-uninstall-prompt', dest="skip_monitor_uninstall_prompt", default=False,
        action="store_true", help="Skip prompting uninstall prompt.")
    mon_uninstall_parser.set_defaults(action_name="uninstall")

    # === Setup Monitor Component Start Arguments === #
    mon_start_parser = monitor_component_args_subparsers.add_parser(
        "start", help="Start Monitor.",
        parents=parent_parsers)
    mon_start_parser.set_defaults(action_name="start")

    # === Setup Monitor Component Stop Arguments === #
    mon_stop_parser = monitor_component_args_subparsers.add_parser(
        "stop", help="Stop Monitor.",
        parents=parent_parsers)
    mon_stop_parser.set_defaults(action_name="stop")

    # === Setup Monitor Component Restart Arguments === #
    mon_restart_parser = monitor_component_args_subparsers.add_parser(
        "restart", help="Restart Monitor.",
        parents=parent_parsers)
    mon_restart_parser.set_defaults(action_name="restart")

    # === Setup Monitor Component Status Arguments === #
    ls_status_parser = monitor_component_args_subparsers.add_parser(
        "status", help="Status Monitor.",
        parents=parent_parsers)
    ls_status_parser.set_defaults(action_name="status")


def register_elasticsearch_component_args(es_component_parser, parent_parsers):
    elasticsearch_component_args_subparsers = es_component_parser.add_subparsers()
    # === Setup ElasticSearch Component Install Arguments === #
    es_install_parser = elasticsearch_component_args_subparsers.add_parser(
        "install", help="Install ElasticSearch.",
        parents=parent_parsers)

    es_install_parser.set_defaults(action_name="install")
    es_install_parser.add_argument("--es-heap-size", dest="elastic_heap_size", type=int, default=4,
                                   help="The amount of memory to designate to ElasticSearch's Java Heap [Gi]"
                                   )
    es_install_parser.add_argument("--es-password", dest="elastic_password", type=str,
                                   help="The password used for logging into ElasticSearch."
                                   )
    es_install_parser.add_argument("--skip-install-jdk", dest="skip_elastic_install_jdk", default=False,
                                   action="store_true", help="Skip the installation of Java 11 Development Environment."
                                   )

    # === Setup ElasticSearch Component Uninstall Arguments === #
    es_uninstall_parser = elasticsearch_component_args_subparsers.add_parser(
        "uninstall",
        help="Uninstall ElasticSearch.",
        parents=parent_parsers)
    es_uninstall_parser.add_argument('--skip-uninstall-prompt', dest="skip_elastic_uninstall_prompt", default=False,
                                     action="store_true", help="Skip prompting uninstall prompt.")
    es_uninstall_parser.set_defaults(action_name="uninstall")

    # === Setup ElasticSearch Component Start Arguments === #
    es_start_parser = elasticsearch_component_args_subparsers.add_parser(
        "start", help="Start ElasticSearch.", parents=parent_parsers)
    es_start_parser.set_defaults(action_name="start")

    # === Setup ElasticSearch Component Stop Arguments === #
    es_stop_parser = elasticsearch_component_args_subparsers.add_parser(
        "stop", help="Stop ElasticSearch.", parents=parent_parsers)
    es_stop_parser.set_defaults(action_name="stop")

    # === Setup ElasticSearch Component Restart Arguments === #
    es_restart_parser = elasticsearch_component_args_subparsers.add_parser(
        "restart", help="Restart ElasticSearch.", parents=parent_parsers)
    es_restart_parser.set_defaults(action_name="restart")

    # === Setup ElasticSearch Component Status Arguments === #
    es_status_parser = elasticsearch_component_args_subparsers.add_parser(
        "status", help="Status ElasticSearch.", parents=parent_parsers)
    es_status_parser.set_defaults(action_name="status")


def register_logstash_component_args(ls_component_parser, parent_parsers):
    logstash_component_args_subparsers = ls_component_parser.add_subparsers()
    # === Setup LogStash Component Install Arguments === #
    ls_install_parser = logstash_component_args_subparsers.add_parser(
        "install", help="Install LogStash.", parents=parent_parsers)

    ls_install_parser.set_defaults(action_name="install")
    ls_install_parser.add_argument("--ls-listen-addr", dest="ls_addr", type=str, default='0.0.0.0',
                                   help="The address upon which LogStash input plugins listen."
                                   )
    ls_install_parser.add_argument("--es-host", dest="es_host", type=str, default='localhost',
                                   help="The host where ElasticSearch lives."
                                   )
    ls_install_parser.add_argument("--es-port", dest="es_port", type=int, default=9200,
                                   help="The port that ElasticSearch is listening on."
                                   )
    ls_install_parser.add_argument("--ls-heap-size", dest="logstash_heap_size", type=int, default=4,
                                   help="The amount of memory to designate to LogStash's Java Heap [Gi]"
                                   )
    ls_install_parser.add_argument("--es-password", dest="elastic_password", type=str,
                                   help="The password used for logging into ElasticSearch."
                                   )
    ls_install_parser.add_argument("--skip-es-check", dest="skip_check_elasticsearch_connection", default=False,
                                   action="store_true", help="Skip check to see if ElasticSearch is up and running."
                                   )
    ls_install_parser.add_argument("--skip-install-jdk", dest="skip_logstash_install_jdk", default=False,
                                   action="store_true", help="Skip the installation of Java 11 Development Environment."
                                   )

    # === Setup LogStash Component Uninstall Arguments === #
    ls_uninstall_parser = logstash_component_args_subparsers.add_parser(
        "uninstall",
        help="Uninstall LogStash.",
        parents=parent_parsers)
    ls_uninstall_parser.add_argument('--skip-uninstall-prompt', dest="skip_logstash_uninstall_prompt", default=False,
                                     action="store_true", help="Skip prompting uninstall prompt.")
    ls_uninstall_parser.set_defaults(action_name="uninstall")

    # === Setup LogStash Component Start Arguments === #
    ls_start_parser = logstash_component_args_subparsers.add_parser(
        "start", help="Start LogStash.", parents=parent_parsers)
    ls_start_parser.set_defaults(action_name="start")

    # === Setup LogStash Component Stop Arguments === #
    ls_stop_parser = logstash_component_args_subparsers.add_parser(
        "stop", help="Stop LogStash.", parents=parent_parsers)
    ls_stop_parser.set_defaults(action_name="stop")

    # === Setup LogStash Component Restart Arguments === #
    ls_restart_parser = logstash_component_args_subparsers.add_parser(
        "restart", help="Restart LogStash.", parents=parent_parsers)
    ls_restart_parser.set_defaults(action_name="restart")

    # === Setup ElasticSearch Component Status Arguments === #
    ls_status_parser = logstash_component_args_subparsers.add_parser(
        "status", help="Status LogStash.", parents=parent_parsers)
    ls_status_parser.set_defaults(action_name="status")


def register_kibana_component_args(kb_component_parser, parent_parsers):
    kibana_component_args_subparsers = kb_component_parser.add_subparsers()
    # === Setup Kibana Component Install Arguments === #
    kb_install_parser = kibana_component_args_subparsers.add_parser(
        "install", help="Install Kibana.", parents=parent_parsers)

    kb_install_parser.set_defaults(action_name="install")
    kb_install_parser.add_argument("--kb-listen-addr", dest="kb_addr", type=str, default='0.0.0.0',
                                   help="The address upon which Kibana web interface listens."
                                   )
    kb_install_parser.add_argument("--kb-listen-port", dest="kb_port", type=str, default=5601,
                                   help="The port upon which Kibana web interface listens."
                                   )
    kb_install_parser.add_argument("--es-host", dest="es_host", type=str, default='localhost',
                                   help="The host where ElasticSearch lives."
                                   )
    kb_install_parser.add_argument("--es-port", dest="es_port", type=int, default=9200,
                                   help="The port that ElasticSearch is listening on."
                                   )
    kb_install_parser.add_argument("--ls-heap-size", dest="kibana_heap_size", type=int, default=4,
                                   help="The amount of memory to designate to LogStash's Java Heap [Gi]"
                                   )
    kb_install_parser.add_argument("--es-password", dest="elastic_password", type=str,
                                   help="The password used for logging into ElasticSearch."
                                   )
    kb_install_parser.add_argument("--skip-es-check", dest="skip_check_elasticsearch_connection", default=False,
                                   action="store_true", help="Skip check to see if ElasticSearch is up and running."
                                   )

    # === Setup Kibana Component Uninstall Arguments === #
    kb_uninstall_parser = kibana_component_args_subparsers.add_parser(
        "uninstall",
        help="Uninstall Kibana.",
        parents=parent_parsers)
    kb_uninstall_parser.add_argument('--skip-uninstall-prompt', dest="skip_kibana_uninstall_prompt", default=False,
                                     action="store_true", help="Skip prompting uninstall prompt.")
    kb_uninstall_parser.set_defaults(action_name="uninstall")

    # === Setup Kibana Component Start Arguments === #
    kb_start_parser = kibana_component_args_subparsers.add_parser(
        "start", help="Start Kibana.",
        parents=parent_parsers)
    kb_start_parser.set_defaults(action_name="start")

    # === Setup Kibana Component Stop Arguments === #
    kb_stop_parser = kibana_component_args_subparsers.add_parser(
        "stop", help="Stop Kibana.",
        parents=parent_parsers)
    kb_stop_parser.set_defaults(action_name="stop")

    # === Setup Kibana Component Restart Arguments === #
    kb_restart_parser = kibana_component_args_subparsers.add_parser(
        "restart", help="Restart Kibana.",
        parents=parent_parsers)
    kb_restart_parser.set_defaults(action_name="restart")

    # === Setup ElasticSearch Component Status Arguments === #
    kb_status_parser = kibana_component_args_subparsers.add_parser(
        "status", help="Status Kibana.",
        parents=parent_parsers)
    kb_status_parser.set_defaults(action_name="status")