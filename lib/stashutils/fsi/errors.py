"""Errors and Exceptions."""


class OperationFailure(IOError):
    """raise this if a operation (e.g. cd) fails.
    The FSI is responsible for undoing errors."""


class IsDir(OperationFailure):
    """raise this if a command only works on a file but a dirname is passed."""


class IsFile(OperationFailure):
    """raise this if a command only works on a dir but a filename is passed."""


class AlreadyExists(OperationFailure):
    """raise this if something already exists."""
