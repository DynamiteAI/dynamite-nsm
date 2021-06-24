from dynamite_nsm.cmd.kibana.package import interface as kibana_package_interface

if __name__ == '__main__':
    parser = kibana_package_interface.get_parser()
    args = parser.parse_args()
    result = kibana_package_interface.execute(args)
    if result and args.entry_method_name in ['list', 'list_saved_objects', 'list_tenants']:
        print(result)
