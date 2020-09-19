import os
import gzip
import linecache


class LogFileSize:

    def __init__(self, file_line_count, loaded_entries):
        self.file_line_count = file_line_count
        self.loaded_entries = loaded_entries


class LogFile:

    def __init__(self, log_path, log_sample_size=500, gzip_decode=False):
        self.log_path = log_path
        self.exists = False
        if gzip_decode and not log_path.endswith('.decoded'):
            decoded_log_path = log_path + '.decoded'
            if not os.path.exists(decoded_log_path):
                with open(decoded_log_path, 'w') as out:
                    with gzip.open(log_path, 'rb') as f:
                        line = f.readline().decode('utf-8', errors='ignore')
                        while line:
                            out.write(line)
                            line = f.readline().decode('utf-8', errors='ignore')
            self.log_path = decoded_log_path
        linecache.updatecache(self.log_path)
        last_line_num = self.get_latest_line_offset()
        if last_line_num < log_sample_size:
            self.entries = [entry for entry in self.iter_cache(start=1)]
        else:
            self.entries = [entry for entry in self.iter_cache(start=last_line_num - log_sample_size + 1)]

    def iter_cache(self, start=1, step=1):
        i = start
        while True:
            line = linecache.getline(self.log_path, i)
            if line:
                yield line
            else:
                break
            i += step

    def get_latest_line_offset(self, step=10000):
        offset = 1
        while step > 0:
            for i, _ in enumerate(self.iter_cache(start=offset, step=step)):
                offset += step
            offset -= step
            step = int(step/2)
        return offset

    def size(self):
        return LogFileSize(self.get_latest_line_offset(), len(self.entries))