"""The Gate 1 probe's decision table.

The probe exists to answer one question after a deploy: is the wallet recipient
allowlist actually enforced on the running build? Its value is entirely in
mapping each response to the right conclusion, because the two failure modes it
separates have opposite remedies — a fail-open means stop, an unrecognised
action type means redeploy — and the handoff's standing trap is "resolving" the
second by hand-adding the action type, which silently produces the first.

So the table is tested rather than trusted.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "wallet_gate1_probe.py"
_spec = importlib.util.spec_from_file_location("wallet_gate1_probe", _SCRIPT)
probe = importlib.util.module_from_spec(_spec)
sys.modules["wallet_gate1_probe"] = probe
_spec.loader.exec_module(probe)

BLOCKED_RECIPIENT = "0x9999999999999999999999999999999999999999"


class _StubClient:
    """Stands in for InntrisAgentClient. Records what the probe submitted."""

    last_call: dict = {}

    def __init__(self, status, body, *, raises=None):
        self._status = status
        self._body = body
        self._raises = raises

    def verify(self, action_type, payload):
        type(self).last_call = {"action_type": action_type, "payload": payload}
        if self._raises is not None:
            raise self._raises
        return self._status, self._body


@pytest.fixture
def run_probe(monkeypatch):
    """Run the probe against a stubbed Core, returning its exit code."""
    monkeypatch.setenv("INNTRIS_CORE_URL", "https://api.example.invalid")
    monkeypatch.setenv("INNTRIS_AGENT_ID", "11111111-1111-1111-1111-111111111111")
    monkeypatch.setenv("INNTRIS_PRIVATE_KEY_B64", "A" * 43 + "=")

    def _run(status, body, *, raises=None, argv=None):
        stub = _StubClient(status, body, raises=raises)
        monkeypatch.setattr(
            probe.InntrisAgentClient,
            "from_seed_b64",
            classmethod(lambda _cls, *_args, **_kwargs: stub),
        )
        monkeypatch.setattr(
            sys,
            "argv",
            argv or ["wallet_gate1_probe.py", "--recipient", BLOCKED_RECIPIENT],
        )
        return probe.main()

    return _run


class TestDecisionTable:
    def test_expected_violation_passes_the_gate(self, run_probe):
        code = run_probe(403, {"violation_code": "wallet_recipient_not_allowed"})
        assert code == probe.EXIT_ENFORCED

    def test_approval_is_reported_as_fail_open(self, run_probe):
        # The one outcome that must never be mistaken for success.
        assert run_probe(200, {"verdict": "approved"}) == probe.EXIT_FAIL_OPEN

    def test_approved_verdict_on_a_non_200_is_still_fail_open(self, run_probe):
        assert run_probe(202, {"verdict": "APPROVED"}) == probe.EXIT_FAIL_OPEN

    @pytest.mark.parametrize(
        "violation", ["action_not_allowed", "action_type_unknown"]
    )
    def test_unrecognised_action_type_means_the_deploy_did_not_land(
        self, run_probe, violation
    ):
        code = run_probe(403, {"violation_code": violation})
        assert code == probe.EXIT_DEPLOY_MISSING

    @pytest.mark.parametrize(
        "violation",
        [
            "trust_score_too_low",
            "agent_not_active",
            "wallet_chain_not_allowed",
            "wallet_policy_invalid",
            "wallet_recipient_required",
            None,
        ],
    )
    def test_any_other_denial_is_inconclusive_not_a_pass(self, run_probe, violation):
        # Blocked for another reason proves the agent is gated, not that the
        # recipient allowlist is what gated it.
        code = run_probe(403, {"violation_code": violation})
        assert code == probe.EXIT_UNKNOWN

    def test_the_four_outcomes_are_distinct_exit_codes(self):
        codes = {
            probe.EXIT_ENFORCED,
            probe.EXIT_PROBE_FAILED,
            probe.EXIT_DEPLOY_MISSING,
            probe.EXIT_FAIL_OPEN,
            probe.EXIT_UNKNOWN,
        }
        assert len(codes) == 5
        assert probe.EXIT_ENFORCED == 0, "only enforcement may exit zero"


class TestProbeCannotRun:
    def test_a_transport_error_is_not_reported_as_enforcement(self, run_probe):
        code = run_probe(None, None, raises=ConnectionError("no route to host"))
        assert code == probe.EXIT_PROBE_FAILED

    def test_missing_credentials_exit_without_submitting(self, monkeypatch):
        for var in ("INNTRIS_CORE_URL", "INNTRIS_AGENT_ID", "INNTRIS_PRIVATE_KEY_B64"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setattr(
            sys, "argv", ["wallet_gate1_probe.py", "--recipient", BLOCKED_RECIPIENT]
        )
        assert probe.main() == probe.EXIT_PROBE_FAILED


class TestWhatIsSubmitted:
    def test_the_probe_submits_a_wallet_transaction(self, run_probe):
        run_probe(403, {"violation_code": "wallet_recipient_not_allowed"})
        assert _StubClient.last_call["action_type"] == "wallet_transaction"

    def test_the_payload_carries_the_chain_and_recipient(self, run_probe):
        run_probe(403, {"violation_code": "wallet_recipient_not_allowed"})
        payload = _StubClient.last_call["payload"]
        assert payload["recipient"] == BLOCKED_RECIPIENT
        assert payload["chain"] == "eip155:8453", "Base is the demo chain default"

    def test_the_probe_signs_rather_than_broadcasts(self, run_probe):
        # wallet-companion is mainnet-only, so the demo signs and never sends.
        run_probe(403, {"violation_code": "wallet_recipient_not_allowed"})
        assert _StubClient.last_call["payload"]["operation"] == "sign-transaction"

    def test_the_chain_is_overridable(self, run_probe):
        run_probe(
            403,
            {"violation_code": "wallet_recipient_not_allowed"},
            argv=[
                "wallet_gate1_probe.py",
                "--recipient",
                BLOCKED_RECIPIENT,
                "--chain",
                "eip155:10",
            ],
        )
        assert _StubClient.last_call["payload"]["chain"] == "eip155:10"
