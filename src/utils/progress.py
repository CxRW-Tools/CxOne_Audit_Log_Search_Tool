import sys
from tqdm import tqdm


class ProgressTracker:
    def __init__(self, debug=False):
        self.debug = debug
        self.current_bar = None

    def create_bar(self, total, description, unit="items"):
        if self.current_bar:
            self.current_bar.close()
        self.current_bar = tqdm(
            total=total,
            desc=description,
            unit=unit,
            ncols=120,
            file=sys.stdout,
            disable=self.debug,
        )
        return self.current_bar

    def update(self, n=1):
        if self.current_bar:
            self.current_bar.update(n)

    def close(self):
        if self.current_bar:
            self.current_bar.close()
            self.current_bar = None


class StageTracker:
    def __init__(self, debug=False):
        self.debug = debug

    def start_stage(self, stage_name):
        print("\n" + "=" * 120)
        print(stage_name)
        print("=" * 120)

    def end_stage(self, stage_name, **stats):
        print(f"\n{stage_name} completed:")
        for k, v in stats.items():
            print(f"  {k}: {v}")
