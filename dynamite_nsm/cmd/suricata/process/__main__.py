from logging import DEBUG, INFO

from dynamite_nsm.logger import get_logger
from dynamite_nsm.cmd.suricata.process import interface as suricata_process_interface

if __name__ == '__main__':
    parser = suricata_process_interface.get_parser()
    args = parser.parse_args()
    logger = get_logger('suricata.process', level=DEBUG if args.verbose else INFO, stdout=args.stdout)
    logger.info(f'Calling suricata.process.{args.entry_method_name}.')
    logger.debug(args.__dict__)
    result = suricata_process_interface.execute(args)
    print(result)
