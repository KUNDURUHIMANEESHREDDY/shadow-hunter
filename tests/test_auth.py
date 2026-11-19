from shadow_hunter.auth import TokenAuthenticator


def test_customer_identity_comes_from_token_configuration_not_request_body():
    auth = TokenAuthenticator(
        customer_tokens={
            "opaque-customer-token": {
                "subject_id": "subject-1",
                "tenant_id": "tenant-1",
                "customer_id": "customer-1",
            }
        }
    )
    principal = auth.authenticate_customer("opaque-customer-token")
    assert principal is not None
    assert principal.customer_id == "customer-1"
    assert auth.authenticate_customer("not-the-token") is None


def test_operator_tokens_are_separate_from_customer_tokens():
    auth = TokenAuthenticator(
        customer_tokens={"customer-token": {
            "subject_id": "subject-1", "tenant_id": "tenant-1", "customer_id": "customer-1"
        }},
        operator_tokens={"operator-token": {"subject_id": "support-1"}},
    )
    assert auth.authenticate_operator("customer-token") is None
    assert auth.authenticate_customer("operator-token") is None
    assert auth.authenticate_operator("operator-token") == "support-1"
