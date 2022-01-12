import os
import gzip
import linecache
from typing import Generator, Optional

from dynamite_nsm import exceptions, utilities


class LogFileSize:

    def __init__(self, file_line_count: int, loaded_entries: int):
        """
        A simple object that represents the latest line offset reached and the number of entries loaded into memory.
        Args:
            file_line_count: The offset of the last reached (cached) line
            loaded_entries: The number of entries loaded into memory
        """
        self.file_line_count = file_line_count
        self.loaded_entries = loaded_entries


class LogFile:

    def __init__(self, log_path: str, log_sample_size: Optional[int] = 500, gzip_decode: Optional[bool] = False):
        """A Generic log object
        Args:
            log_path: The path to a log file
            log_sample_size: The number of most recent entries to include
            gzip_decode: If True, we'll decode the log before reading it in
        """
        if not utilities.is_setup():
            raise exceptions.DynamiteNotSetupError()
        self.log_path = log_path
        self.log_sample_size = log_sample_size
        self.exists = False
        self.current_line = 0
        if gzip_decode and not log_path.endswith('.decoded'):
            decoded_log_path = log_path + '.decoded'
            if not os.path.exists(decoded_log_path):
                with open(decoded_log_path, 'w') as out:
                    with gzip.open(log_path, 'rb') as f:
                        line = f.readline().decode('utf-8', errors='ignore')
                        while line:
                            out.write(line)
                            try:
                                line = f.readline().decode('utf-8', errors='ignore')
                            except gzip.BadGzipFile:
                                pass

            self.log_path = decoded_log_path
        linecache.updatecache(self.log_path)
        self.last_line_num = self.find_latest_line_offset()
        if self.last_line_num < self.log_sample_size:
            self.entries = [entry for entry in self.iter_cache(start=1)]
        else:
            self.entries = [entry for entry in self.iter_cache(start=self.last_line_num - self.log_sample_size + 1)]

    def __len__(self):
        return self.last_line_num

    def __iter__(self):
        return self

    def __next__(self):
        self.current_line += 1
        line = linecache.getline(self.log_path, self.current_line)
        if line:
            return line
        else:
            raise StopIteration

    def iter_cache(self, start: Optional[int] = 1, step: Optional[int] = 1) -> Generator:
        """Relatively Memory efficient method of accessing very large files on disk
        Args:
            start: The starting line
            step: The step between line offsets
        Returns:
             The line at a particular offset
        """

        i = start
        while True:
            line = linecache.getline(self.log_path, i)
            if line:
                yield line
            else:
                break
            i += step

    def find_latest_line_offset(self, step: Optional[int] = 500000) -> int:
        """Relatively fast way of finding the latest offset; algorithm guesses high offset and if over divides the step
        by half and repeats
        Args:
            step: The starting step between line offsets
        Returns:
             Most recent line number
        """
        offset = 1
        while step > 0:
            for _ in self.iter_cache(start=offset, step=step):
                offset += step
            step = int(step/2)
            offset -= step
        return offset

    def refresh(self) -> None:
        """
        Refresh linecache

        Returns:
            None

        """
        linecache.updatecache(self.log_path)
        if self.last_line_num < self.log_sample_size:
            self.entries = [entry for entry in self.iter_cache(start=1)]
        else:
            self.entries = [entry for entry in self.iter_cache(start=self.last_line_num - self.log_sample_size + 1)]

    def size(self) -> LogFileSize:
        """
        Get the log file size with last offset reached

        Returns: A LogFileSize object containing the latest line offset and the total number of log entries available

        """
        return LogFileSize(self.find_latest_line_offset(), len(self.entries))
