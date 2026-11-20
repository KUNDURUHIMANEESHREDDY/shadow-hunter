from __future__ import annotations


def test_lambda_entrypoint_exposes_handler():
    # Importing the module requires the AWS deployment extra (Mangum).
    from shadow_hunter.lambda_handler import handler

    assert callable(handler)
