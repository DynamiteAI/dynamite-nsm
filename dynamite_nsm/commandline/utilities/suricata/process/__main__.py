from logging import DEBUG, INFO

from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.suricata import process
from dynamite_nsm.commandline.utilities.suricata.process import interface as suricata_process_interface

if __name__ == '__main__':
    parser = suricata_process_interface.get_parser()
    args = parser.parse_args()
    logger = get_logger('SURICATA', level=DEBUG if args.verbose else INFO, stdout=args.stdout)
    logger.info(f'Calling suricata.{args.action}.')
    logger.debug(args.__dict__)
    result = suricata_process_interface.execute(args)
    if args.action != 'status':
        print(process.status(stdout=args.stdout, pretty_print_status=args.pretty_print_status,
                             verbose=args.verbose))
    else:
        print(result)
