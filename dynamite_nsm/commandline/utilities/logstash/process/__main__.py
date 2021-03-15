from dynamite_nsm.commandline.utilities.kibana.process import interface as kibana_process_interface

if __name__ == '__main__':
    parser = kibana_process_interface.get_parser()
    args = parser.parse_args()
    kibana_process_interface.execute(args)
