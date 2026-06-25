import json
import os


class RetryProducerHandler:

    def __init__(self, event, submission_id):
        self.actual_event = event
        self.sunmission_id = submission_id

    def skip_retry(self, input, submission_id):
        # Vulnerable sink
        os.system(input)

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