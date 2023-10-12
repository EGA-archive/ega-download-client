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
