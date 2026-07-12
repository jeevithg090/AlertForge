from __future__ import annotations

import os

os.environ.setdefault("DASHSCOPE_API_KEY", "")
os.environ.setdefault("USE_MOCK_TOOLS", "true")


def test_import_metrics_twice_no_crash():
    import importlib

    mod = importlib.import_module("app.services.metrics")
    for _ in range(3):
        importlib.reload(mod)


def test_record_action_and_sample_value():
    from app.services.metrics import record_action, sf_actions_total

    record_action("block_ip", "DENIED")
    val = sf_actions_total.labels(action_type="block_ip", status="DENIED")._value.get()
    assert float(val) >= 1.0


def test_reason_kind_derivation():
    from app.services.metrics import _reason_kind

    assert _reason_kind("shared source IP 1.2.3.4") == "shared_ip"
    assert _reason_kind("duplicate signature collision") == "signature"
    assert _reason_kind("shared host bastion-01") == "shared_host"
    assert _reason_kind("shared user j.doe") == "shared_user"
    assert _reason_kind("unknown correlation") == "other"


def test_record_ingested_and_correlated():
    from app.services.metrics import (
        record_correlated,
        record_ingested,
        sf_alerts_correlated_total,
        sf_alerts_ingested_total,
    )

    record_ingested("siem")
    record_correlated("shared source IP 1.2.3.4")

    ingested_val = sf_alerts_ingested_total.labels(source="siem")._value.get()
    assert float(ingested_val) >= 1.0

    correlated_val = sf_alerts_correlated_total.labels(reason_kind="shared_ip")._value.get()
    assert float(correlated_val) >= 1.0


def test_record_stage():
    from app.services.metrics import record_stage

    record_stage("triage", 1.5)
    assert True


def test_set_approval_queue_size():
    from app.services.metrics import set_approval_queue_size, sf_approval_queue_size

    set_approval_queue_size(5)
    assert sf_approval_queue_size._value.get() == 5.0
