class Error(Exception):
    pass


class VolumeNotAvailableError(Error):
    pass


class InvalidHeader(Error):
    pass


class FileNotFoundError(Error, FileNotFoundError):
    pass


class IsADirectoryError(Error, IsADirectoryError):
    pass


class NotADirectoryError(Error, NotADirectoryError):
    pass


class NotASymlinkError(Error):
    pass


class NotAnRDMFileError(Error):
    pass
