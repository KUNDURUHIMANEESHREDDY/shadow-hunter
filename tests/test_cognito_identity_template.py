from __future__ import annotations

from pathlib import Path

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

ROOT = Path(__file__).resolve().parents[1]
IDENTITY_TEMPLATE = ROOT / "infra" / "cognito" / "identity-stack.yaml"
EXISTING_POOL_TEMPLATE = ROOT / "infra" / "cognito" / "pre-token-generation.yaml"

_TRUSTED_ATTRIBUTES = {"custom:tenant_id", "custom:customer_id"}


class CloudFormationLoader(yaml.SafeLoader):
    """Parse CloudFormation YAML while preserving intrinsic-tagged values."""


def _construct_intrinsic(loader, tag_suffix, node):
    if isinstance(node, ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    elif isinstance(node, MappingNode):
        value = loader.construct_mapping(node, deep=True)
    else:
        raise TypeError(f"Unsupported CloudFormation node: {type(node).__name__}")
    return {"intrinsic": tag_suffix, "value": value}


CloudFormationLoader.add_multi_constructor("!", _construct_intrinsic)


def _load_template(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as stream:
        template = yaml.load(stream, Loader=CloudFormationLoader)
    assert isinstance(template, dict)
    return template


def _resource(template: dict, name: str, expected_type: str) -> dict:
    resource = template["Resources"][name]
    assert resource["Type"] == expected_type
    return resource


def test_new_user_pool_is_admin_provisioned_with_immutable_trusted_attributes():
    template = _load_template(IDENTITY_TEMPLATE)
    assert template["Parameters"]["Environment"]["AllowedValues"] == ["production"]
    assert template["Parameters"]["UserPoolTier"]["AllowedValues"] == [
        "ESSENTIALS",
        "PLUS",
    ]
    assert "Default" not in template["Parameters"]["UserPoolTier"]

    user_pool = _resource(template, "ShadowHunterUserPool", "AWS::Cognito::UserPool")
    properties = user_pool["Properties"]
    assert user_pool["DeletionPolicy"] == "Retain"
    assert user_pool["UpdateReplacePolicy"] == "Retain"
    assert properties["DeletionProtection"] == "ACTIVE"
    assert properties["AdminCreateUserConfig"]["AllowAdminCreateUserOnly"] is True
    assert properties["MfaConfiguration"] == "ON"
    assert properties["EnabledMfas"] == ["SOFTWARE_TOKEN_MFA"]

    schema = {attribute["Name"]: attribute for attribute in properties["Schema"]}
    for name in ("tenant_id", "customer_id"):
        assert schema[name]["AttributeDataType"] == "String"
        assert schema[name]["Mutable"] is False
        assert schema[name]["DeveloperOnlyAttribute"] is False

    trigger = properties["LambdaConfig"]["PreTokenGenerationConfig"]
    assert trigger["LambdaVersion"] == "V3_0"
    assert trigger["LambdaArn"] == {
        "intrinsic": "GetAtt",
        "value": "CognitoPreTokenGenerationFunction.Arn",
    }

    permission = _resource(
        template,
        "CognitoPreTokenGenerationInvokePermission",
        "AWS::Lambda::Permission",
    )["Properties"]
    assert permission["Principal"] == "cognito-idp.amazonaws.com"
    assert permission["SourceArn"] == {
        "intrinsic": "GetAtt",
        "value": "ShadowHunterUserPool.Arn",
    }


def test_every_human_app_client_has_an_explicit_trusted_attribute_write_allowlist():
    template = _load_template(IDENTITY_TEMPLATE)
    client_resources = {
        name: resource["Properties"]
        for name, resource in template["Resources"].items()
        if resource["Type"] == "AWS::Cognito::UserPoolClient"
    }
    assert set(client_resources) == {
        "ShadowHunterCustomerAppClient",
        "ShadowHunterOperatorAppClient",
        "ShadowHunterAgentAppClient",
    }

    human_clients = {
        "ShadowHunterCustomerAppClient",
        "ShadowHunterOperatorAppClient",
    }
    for name in human_clients:
        client = client_resources[name]
        assert client["GenerateSecret"] is False
        assert client["WriteAttributes"] == ["email"]
        assert client["ReadAttributes"] == ["email", "email_verified"]
        assert not (_TRUSTED_ATTRIBUTES & set(client["WriteAttributes"]))
        assert not (_TRUSTED_ATTRIBUTES & set(client["ReadAttributes"]))
        assert client["AllowedOAuthFlows"] == ["code"]
        assert client["SupportedIdentityProviders"] == ["COGNITO"]
        assert "ALLOW_USER_SRP_AUTH" in client["ExplicitAuthFlows"]
        assert "ALLOW_USER_PASSWORD_AUTH" not in client["ExplicitAuthFlows"]
        assert "ALLOW_ADMIN_USER_PASSWORD_AUTH" not in client["ExplicitAuthFlows"]
        assert "aws.cognito.signin.user.admin" not in client["AllowedOAuthScopes"]
        assert client["UserPoolId"] == {
            "intrinsic": "Ref",
            "value": "ShadowHunterUserPool",
        }

    customer = client_resources["ShadowHunterCustomerAppClient"]
    operator = client_resources["ShadowHunterOperatorAppClient"]
    assert "shadow-hunter/customer" in customer["AllowedOAuthScopes"]
    assert "shadow-hunter-api/refunds" in customer["AllowedOAuthScopes"]
    assert operator["AllowedOAuthScopes"] == ["openid", "email"]

    operator_group = _resource(
        template,
        "ShadowHunterOperatorGroup",
        "AWS::Cognito::UserPoolGroup",
    )["Properties"]
    assert operator_group["GroupName"] == "shadow_hunter_operators"
    assert "Users" not in operator_group

    agent = client_resources["ShadowHunterAgentAppClient"]
    assert agent["GenerateSecret"] is True
    assert agent["AllowedOAuthFlows"] == ["client_credentials"]
    assert agent["ExplicitAuthFlows"] == ["ALLOW_TOKEN_EXCHANGE_DELEGATION"]
    assert "aws.cognito.signin.user.admin" not in agent["AllowedOAuthScopes"]


def test_existing_pool_addon_cannot_be_mistaken_for_a_secured_identity_stack():
    template = _load_template(EXISTING_POOL_TEMPLATE)
    resource_types = {
        resource["Type"] for resource in template["Resources"].values()
    }
    assert "AWS::Cognito::UserPool" not in resource_types
    assert "AWS::Cognito::UserPoolClient" not in resource_types
    assert "UserPoolId" in template["Parameters"]
