"""
clo.native -- provider-native enforcement artefacts, shared by tools/clo_compile.py
and the NATIVE baseline (baselines/run_baselines.py).

AWS: CloudFormation resources for the AWS Config managed rule REQUIRED_TAGS (at most six
keys per rule). Organisation-wide requirements become AWS::Config::OrganizationConfigRule;
OU- and account-level requirements become AWS::Config::ConfigRule, to be deployed with
CloudFormation StackSets to the OU or account named in the resource's Metadata.
Azure: assignments of the built-in "Require a tag on resources" (one per key and scope:
management group or subscription), and, for type-scoped requirements, a custom audit
definition on the listed resource types.
"""
import json

REQUIRE_TAG = "/providers/Microsoft.Authorization/policyDefinitions/871b6d14-10aa-478d-b590-94f262ecfa99"


def _params(keys):
    return {f"tag{j + 1}Key": k for j, k in enumerate(keys)}


def aws_rules(name, scope_kind, scope_id, keys, cfn_types=None):
    out = []
    for i in range(0, len(keys), 6):
        chunk = keys[i:i + 6]
        rn = f"{name}-{i // 6}"[:64]
        if scope_kind == "organization":
            md = {"RuleIdentifier": "REQUIRED_TAGS", "InputParameters": json.dumps(_params(chunk))}
            if cfn_types:
                md["ResourceTypesScope"] = cfn_types
            out.append({"Type": "AWS::Config::OrganizationConfigRule",
                        "Properties": {"OrganizationConfigRuleName": rn, "OrganizationManagedRuleMetadata": md}})
        else:
            props = {"ConfigRuleName": rn, "Source": {"Owner": "AWS", "SourceIdentifier": "REQUIRED_TAGS"},
                     "InputParameters": _params(chunk)}
            if cfn_types:
                props["Scope"] = {"ComplianceResourceTypes": cfn_types}
            out.append({"Type": "AWS::Config::ConfigRule", "Properties": props,
                        "Metadata": {"DeployWithStackSetTo": {"kind": scope_kind, "id": scope_id}}})
    return out


def azure_scope(scope_kind, scope_id):
    return f"/subscriptions/{scope_id}" if scope_kind == "account" else \
        f"/providers/Microsoft.Management/managementGroups/{scope_id}"


def azure_items(name, scope_kind, scope_id, keys, arm_types=None):
    out = []
    scope = azure_scope(scope_kind, scope_id)
    for k in keys:
        if arm_types:
            dname = f"{name}-{k}-def"[:64]
            out.append({"type": "Microsoft.Authorization/policyDefinitions", "apiVersion": "2021-06-01", "name": dname,
                        "properties": {"mode": "Indexed", "displayName": f"Audit tag '{k}' on {len(arm_types)} types",
                                       "policyRule": {"if": {"allOf": [{"field": "type", "in": arm_types},
                                                                        {"field": f"tags['{k}']", "exists": "false"}]},
                                                      "then": {"effect": "audit"}}}})
            pdid = f"{scope}/providers/Microsoft.Authorization/policyDefinitions/{dname}"
            params = {}
        else:
            pdid, params = REQUIRE_TAG, {"tagName": {"value": k}}
        out.append({"type": "Microsoft.Authorization/policyAssignments", "apiVersion": "2022-06-01",
                    "name": f"{name}-{k}"[:64], "scope": scope,
                    "properties": {"policyDefinitionId": pdid, "parameters": params, "enforcementMode": "DoNotEnforce"}})
    return out
