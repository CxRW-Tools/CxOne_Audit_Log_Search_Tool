"""Base operation class."""


class Operation:
    def __init__(self, config, auth_manager, api_client=None, progress=None, debug_logger=None):
        self.config = config
        self.auth = auth_manager
        self.api_client = api_client
        self.progress = progress
        self.logger = debug_logger

    def execute(self):
        raise NotImplementedError("Operation must implement execute method")
