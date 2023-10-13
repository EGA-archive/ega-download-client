class DataFileError(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class MD5MismatchError(DataFileError):
    def __init__(self, message: str):
        super().__init__(message)


class SliceError(DataFileError):
    def __init__(self, message: str):
        super().__init__(message)


class MaxRetriesReachedError(DataFileError):
    def __init__(self, message: str, download_stats_list):
        super().__init__(message)
        self.download_stats_list = download_stats_list
