#!/usr/bin/env python3
"""
gen_abox.py -- synthetic A-Boxes for measuring CLO reasoning cost.

Produces an N-Triples A-Box of N resources with the shape of a mid-size
multi-cloud estate: about 2.3 labels per resource, 30 % of resources partOf
another resource, 67 resource types over six providers, about 12 % of types
without labelling support. Types are generated (rtb_*), not taken from the
catalogue, so the workload does not depend on it.

This is a scaling workload: no defect is planted and the values are random.

Usage:
  python3 tools/gen_abox.py --n 1584 --seed 1 --out abox_1584.nt
"""
import argparse
import random

CLO = "http://example.org/clo/ontology/clo#"
RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
NAMED = "http://www.w3.org/2002/07/owl#NamedIndividual"
ONTO = "http://www.w3.org/2002/07/owl#Ontology"

# (provider individual, BaseKinds offered). 67 types in total.
PROVIDERS = {
    "AWS": ["InstanceKind", "VolumeKind", "SnapshotKind", "BucketKind", "NetworkKind",
            "SubnetKind", "SecurityGroupKind", "LoadBalancerKind", "DatabaseKind",
            "ServerlessFunctionKind", "QueueKind", "RoleKind", "UserKind",
            "AutoScalingGroupKind", "DNSZoneKind", "IPAddressKind", "GatewayKind",
            "StackKind"],
    "Azure": ["InstanceKind", "VolumeKind", "BucketKind", "NetworkKind", "SubnetKind",
              "SecurityGroupKind", "LoadBalancerKind", "DatabaseKind",
              "ServerlessFunctionKind", "QueueKind", "RoleKind", "UserKind",
              "DNSZoneKind", "IPAddressKind", "CertificateKind"],
    "GCP": ["InstanceKind", "VolumeKind", "SnapshotKind", "BucketKind", "NetworkKind",
            "SubnetKind", "FirewallKind", "LoadBalancerKind", "DatabaseKind",
            "ServerlessFunctionKind", "RoleKind", "UserKind", "DNSZoneKind",
            "AIModelKind"],
    "Kubernetes": ["InstanceKind", "LoadBalancerKind", "VolumeKind", "NetworkKind",
                   "RoleKind", "ManagedKubernetesClusterKind", "AccessKeyKind",
                   "QueueKind"],
    "DigitalOcean": ["InstanceKind", "VolumeKind", "BucketKind", "LoadBalancerKind",
                     "FirewallKind", "DatabaseKind", "SnapshotKind"],
    "GitHub": ["GroupKind", "UserKind", "StackKind", "PolicyKind", "AccessKeyKind"],
}
KEYS = ["environment", "team", "owner", "project", "cost-center", "app",
        "Environment", "env", "tier", "managed-by", "data-class", "service"]
VALUES = ["production", "prod", "staging", "dev", "sandbox", "platform-team",
          "data-team", "web", "api", "batch", "CC-1001", "CC-2002", "terraform",
          "helm", "public", "internal", "confidential", "frontend", "backend",
          "ml", "test-qa", "ops", "billing", "search", "auth", "Production",
          "qa", "infra", "core", "edge"]


def u(local):
    return f"<{CLO}{local}>"


def triple(f, s, p, o):
    f.write(f"{s} {p} {o} .\n")


def lit(v):
    return '"' + v.replace('"', r'\"') + '"'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, required=True)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    rnd = random.Random(a.seed)
    T, NI = f"<{RDF_TYPE}>", f"<{NAMED}>"

    with open(a.out, "w") as f:
        triple(f, f"<http://example.org/clo/ontology/clo-bench-{a.n}>", T, f"<{ONTO}>")
        types = []
        for prov, kinds in PROVIDERS.items():
            for k in kinds:
                rt = u(f"rtb_{prov}_{k}")
                types.append(rt)
                support = "none" if (prov == "GitHub" and k != "StackKind") or rnd.random() < 0.05 else (
                    "partial" if rnd.random() < 0.15 else "full")
                triple(f, rt, T, u("ResourceType")); triple(f, rt, T, NI)
                triple(f, rt, u("implementsBaseKind"), u(k))
                triple(f, rt, u("hostedBy"), u(prov))
                triple(f, rt, u("labelingSupport"), lit(support))
        assert len(types) == 67, len(types)
        for k in KEYS:
            triple(f, u("kb_" + k.replace("-", "_")), T, u("LabelKey"))
            triple(f, u("kb_" + k.replace("-", "_")), T, NI)
            triple(f, u("kb_" + k.replace("-", "_")), u("keyName"), lit(k))
        for v in VALUES:
            triple(f, u("vb_" + v.replace("-", "_")), T, u("LabelValue"))
            triple(f, u("vb_" + v.replace("-", "_")), T, NI)
            triple(f, u("vb_" + v.replace("-", "_")), u("valueName"), lit(v))
        n_acc = max(3, a.n // 130)
        for i in range(n_acc):
            triple(f, u(f"accb_{i}"), T, u("Account")); triple(f, u(f"accb_{i}"), T, NI)
        for cat in ["Compute", "Storage", "Networking"]:
            p = u(f"polb_{cat}")
            triple(f, p, T, u("LabelingPolicy")); triple(f, p, T, NI)
            triple(f, p, u("appliesToCategory"), u(cat))
            triple(f, p, u("requiresLabel"), u("kb_environment"))
        triple(f, u("polb_root"), T, u("LabelingPolicy")); triple(f, u("polb_root"), T, NI)

        n_labels = 0
        for i in range(a.n):
            r = u(f"rb_{i}")
            triple(f, r, T, u("CloudResource")); triple(f, r, T, NI)
            triple(f, r, u("resourceId"), lit(f"id-{i}"))
            triple(f, r, u("hasResourceType"), rnd.choice(types))
            triple(f, r, u("belongsToAccount"), u(f"accb_{rnd.randrange(n_acc)}"))
            if i > 0 and rnd.random() < 470 / 1584:
                triple(f, r, u("partOf"), u(f"rb_{rnd.randrange(i)}"))
            elif rnd.random() < 0.05:
                triple(f, r, u("governedBy"), u("polb_root"))
            # 2.27 labels on average, about 10 % with none
            k = 0 if rnd.random() < 0.10 else min(len(KEYS), 1 + int(rnd.expovariate(1 / 1.98)))
            for j in rnd.sample(KEYS, k):
                lb = u(f"lb_{i}_{n_labels}")
                n_labels += 1
                triple(f, r, u("hasLabel"), lb)
                triple(f, lb, T, u("Label")); triple(f, lb, T, NI)
                triple(f, lb, u("hasLabelKey"), u("kb_" + j.replace("-", "_")))
                triple(f, lb, u("hasLabelValue"), u("vb_" + rnd.choice(VALUES).replace("-", "_")))
    print(f"{a.out}: {a.n} resources, {n_labels} labels ({n_labels / a.n:.2f}/resource)")


if __name__ == "__main__":
    main()
