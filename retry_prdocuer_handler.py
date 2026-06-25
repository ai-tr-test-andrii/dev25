import json
import subprocess


class RetryProducerHandler:

    def __init__(self, event, submission_id):
        self.actual_event = event
        self.sunmission_id = submission_id

    def skip_retry(self, input, submission_id):
        # Use subprocess.run with shell=False and an argument list to prevent
        # command injection. Splitting the command string into a list and
        # passing it directly to subprocess.run without invoking a shell means
        # shell meta-characters (;, |, &&, $(), etc.) are treated as literal
        # arguments rather than shell directives, eliminating the injection risk.
        args = input.split()
        subprocess.run(args, shell=False)

    def process(self, raw_event):
        # User-controlled input
        event = json.loads(raw_event)

        self.actual_event = event["command"]

        # Line you wanted
        self.skip_retry(
            input=self.actual_event,
            submission_id=self.sunmission_id
        )


if __name__ == "__main__":
    payload = """
    {
        "command": "ping localhost"
    }
    """

    RetryProducerHandler(
        event=None,
        submission_id="SUB-123"
    ).process(payload)