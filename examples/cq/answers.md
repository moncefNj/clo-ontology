# Competency questions, answered on company_example.ttl

## CQ1  Which keys must a resource carry, which role needs each, and which policy imposes it?

| resource | key | role | policy |
|---|---|---|---|
| pay-receipts | app | Development | Payments team standard |
| pay-receipts | cost-center | FinOps | Shared labelling standard |
| pay-receipts | data-classification | Security | Shared labelling standard |
| pay-receipts | environment | Operations | Shared labelling standard |
| pay-receipts | owner | Operations | Shared labelling standard |

## CQ2  Which resources on other providers are of the same kind as a given one?

| resource | provider | other | otherProvider | kind |
|---|---|---|---|---|
| i-pay-01 | AWS | vm-build | Azure | InstanceKind |

## CQ3  Which keys does each team actually use that differ from the shared (canonical) key?

| team | used | canonical |
|---|---|---|
| Payments | env | environment |

## CQ4  Which resources are in audit scope, and on which of them may absence be concluded?

| resource | type | verdict |
|---|---|---|
| db-pay | aws_rds_instance | closed-world verdict |
| gke-shared | gcp_container_cluster | closed-world verdict |
| i-legacy-7 | aws_ec2_instance | closed-world verdict |
| i-pay-01 | aws_ec2_instance | closed-world verdict |
| pay-receipts | gcp_bucket | closed-world verdict |
| sql-analytics | gcp_sql_database_instance | closed-world verdict |
| vm-build | azure_compute_virtual_machine | closed-world verdict |
| vpc-core | aws_vpc | closed-world verdict |
| vol-scratch | aws_ec2_volume | in scope, no verdict (record incomplete) |
| admins | aws_iam_group | out of audit scope |

## CQ5  May a missing value of each required key be filled in automatically, and from where?

| key | sources |
|---|---|
| app | team-default, inherit |
| cost-center | team-default, inherit |
| data-classification | none: ask the owner |
| environment | account-default, inherit |
| owner | inherit |

## CQ6  For each governance role: how many complete, in-scope resources do policies serving it govern, and how many carry every key it needs?

| role | governed | covered |
|---|---|---|
| Development | 3 | 1 |
| FinOps | 8 | 3 |
| Operations | 8 | 2 |
| Platform engineering | 0 | 0 |
| Security | 8 | 3 |

