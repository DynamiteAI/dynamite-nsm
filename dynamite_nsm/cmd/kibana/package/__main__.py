from dynamite_nsm.cmd.kibana.package import interface as kibana_package_interface

if __name__ == '__main__':
    parser = kibana_package_interface.get_parser()
    args = parser.parse_args()
    result = kibana_package_interface.execute(args)
    if args.action in ['list', 'list-saved-objects']:
        print(result)
