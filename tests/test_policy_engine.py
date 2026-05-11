from app.policy_engine import PolicyEngine


def test_policy_loads():
    policy = PolicyEngine("policies/default_policy.yaml")
    assert policy.policy_id == "default-enterprise-policy"
    assert policy.get("input_guardrails.block_prompt_injection") is True
