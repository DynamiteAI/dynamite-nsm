import linecache


class LogFileSize:

    def __init__(self, file_line_count, loaded_entries):
        self.file_line_count = file_line_count
        self.loaded_entries = loaded_entries


class LogFile:

    def __init__(self, log_path, log_sample_size=500):
        self.log_path = log_path
        self.exists = False
        linecache.updatecache(log_path)
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
        while step > 1:
            for i, _ in enumerate(self.iter_cache(start=offset, step=step)):
                offset += step
            offset -= step
            step = int(step/2)
        return offset

    def size(self):
        return LogFileSize(self.get_latest_line_offset, len(self.entries))