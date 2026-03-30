import os
from datetime import datetime


class FileManager:
    """Output and debug paths under ./output."""

    def __init__(self, config, debug=False):
        self.config = config
        self.debug = debug

    def setup_directories(self):
        os.makedirs(self.config.output_directory, exist_ok=True)
        if getattr(self.config, "temp_directory", None):
            os.makedirs(self.config.temp_directory, exist_ok=True)
        if self.debug:
            print("Output directory:", self.config.output_directory)

    def get_output_csv_path(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.config.output_filename_template.format(
            tenant=self.config.tenant_name,
            timestamp=timestamp,
        )
        return os.path.join(self.config.output_directory, filename)

    def get_debug_log_path(self, base_csv_path):
        return os.path.splitext(base_csv_path)[0] + "_debug.txt"

    def get_standalone_debug_log_path(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = f"audit_events_{self.config.tenant_name}_{timestamp}_debug.txt"
        return os.path.join(self.config.output_directory, name)
