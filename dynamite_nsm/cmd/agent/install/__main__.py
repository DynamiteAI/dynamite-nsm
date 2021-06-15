from dynamite_nsm.cmd.agent.install import interface as agent_installer_interface

if __name__ == '__main__':
    parser = agent_installer_interface.get_parser()
    args = parser.parse_args()
    agent_installer_interface.execute(args)
