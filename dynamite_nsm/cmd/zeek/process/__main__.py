from logging import DEBUG, INFO

from dynamite_nsm.logger import get_logger
from dynamite_nsm.services.zeek import process
from dynamite_nsm.cmd.zeek.process import interface as zeek_process_interface

if __name__ == '__main__':
    parser = zeek_process_interface.get_parser()
    args = parser.parse_args()
    logger = get_logger('ZEEK', level=DEBUG if args.verbose else INFO, stdout=args.stdout)
    logger.info(f'Calling zeek.process.{args.entry_method_name}.')
    logger.debug(args.__dict__)
    result = zeek_process_interface.execute(args)
    print(result)
