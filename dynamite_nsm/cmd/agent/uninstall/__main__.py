from dynamite_nsm.cmd.agent.uninstall import interface as agent_uninstaller_interface

if __name__ == '__main__':
    parser = agent_uninstaller_interface.get_parser()
    args = parser.parse_args()
    agent_uninstaller_interface.execute(args)
