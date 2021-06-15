from dynamite_nsm.cmd.agent.optimize import interface as agent_optimizer_interface

if __name__ == '__main__':
    parser = agent_optimizer_interface.get_parser()
    args = parser.parse_args()
    agent_optimizer_interface.execute(args)
