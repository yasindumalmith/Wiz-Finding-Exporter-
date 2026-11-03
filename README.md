# Wiz Two-Menu CSV Exporter — Read-Only POC

This is a **separate project** and does **not modify** the previous Wiz exporter. The CLI lets you select **(1) a finding category** and **(2) a resource group**, then choose a specific group member when supported. It writes CSV only after an actual scoped Wiz GraphQL query succeeds.

## Start on Ubuntu

```bash
unzip wiz_two_menu_poc.zip
cd wiz_two_menu_poc
python3 -m venv .venv
source .venv/bin/activate
pip install requests
export WIZ_API_URL='https://api.YOUR_REGION.app.wiz.io/graphql'
export WIZ_AUTH_URL='https://auth.app.wiz.io/oauth/token' # adapt for tenant
export WIZ_CLIENT_ID='YOUR_CLIENT_ID'
read -rsp 'Wiz Client Secret: ' WIZ_CLIENT_SECRET; echo
export WIZ_CLIENT_SECRET
python3 wiz_two_menu_export.py
```

Keep credentials and exported findings out of Git. Never paste a token or secret into this chat. API permission scopes depend on the category; typical ones are `read:vulnerabilities`, `read:projects`, and `read:resources` for relevant inventory.

## What actually works *without additional tenant schema mapping?*

| Finding category | Group | State |
|---|---|---|
| Vulnerability Findings | No group | Supported by query; 10 records default |
| Vulnerability Findings | Project | Query includes published `projectId` vulnerability filter; project names listed through `projects`, or enter ID manually; **test in tenant** |
| Vulnerability Findings | Code Repository | Requires repository-branch *affected asset IDs* in `resource_groups.json` |
| Vulnerability Findings | Container Registry | Requires all related container-image *affected asset IDs* in `resource_groups.json` |
| Vulnerability Findings | Kubernetes Cluster | Requires all related workload/image *affected asset IDs* in `resource_groups.json` |
| Vulnerability Findings | Kubernetes Namespace | Requires related affected asset IDs in `resource_groups.json` |
| SAST Findings | No group | Queries IDs only; must validate `sastFindings` in tenant |
| SAST Findings | Any specific group | Tenant profile and supported filter required |
| Secrets, configuration, host, etc. | Any group | Tenant profile and supported filter required (not assumed) |

**Not yet an automatic clone of the Wiz GUI group-by menu.** In Wiz the GUI can group by Security Graph relationships that are not guaranteed to map to a direct `filterBy` field. This code explicitly refuses unsupported combinations instead of giving misleading CSVs.

## Group/resource ID mapping (for Vulnerability Findings)

After verifying the relationships using the Wiz API Explorer's Security Graph inventory queries, populate `resource_groups.json` as follows (use your OWN tenant's real names and IDs, not these samples):

```json
{
  "code_repository": [
    {"name": "sample-backend", "affected_asset_ids": ["REAL_REPOSITORY_BRANCH_ASSET_ID"]}
  ],
  "container_registry": [
    {"name": "sample-registry", "affected_asset_ids": ["REAL_IMAGE_ASSET_ID_1", "REAL_IMAGE_ASSET_ID_2"]}
  ],
  "kubernetes_cluster": [],
  "kubernetes_namespace": []
}
```

The `affected_asset_ids` list must refer to **the IDs of assets that actually appear in `vulnerabilityFindings.vulnerableAsset.id`**, not necessarily registry/cluster resource IDs. Registry/cluster ownership must be established via Wiz Security Graph relationship queries; do not simply use the registry ID as the vulnerable asset ID. The app splits lists of IDs into batches of 30 and deduplicates by finding ID. A mapping is only complete if all relevant assets have been discovered.

## Tenant-verified GraphQL profiles for other categories

The application includes a generic profile extension (no guessed GraphQL collection names). To enable more categories/groupings, create a GraphQL file that aliases the result connection as `findings`, with `nodes` and `pageInfo { hasNextPage endCursor }`. Include `$first`, `$after`, and, when grouped, `$filterBy` to enforce the selected group.

Then add the profile to `tenant_profiles.json`:

```json
{
  "sast": {
    "query": "queries/TENANT_REVIEWED_SAST_GROUPED.graphql",
    "group_filter_fields": {"project": "TENANT_CONFIRMED_PROJECT_FIELD"},
    "supports_all": false
  }
}
```

The script **does not assume** that the same fields/filters are supported by all finding categories. Obtain the exact query and input type from **Wiz Settings → API Explorer**. A filter variable that uses an unsupported field will be rejected by Wiz; this is preferable to an incorrect report.

**Security note:** When adding Secret Findings, include metadata only (ID/type/severity/location), never return secret values or token material. Do not store tokens or secrets in CSV.

## Limits and completeness

`--page-size 10 --max-pages 1` is default; therefore CSV is a sample. For a complete selected group use `--page-size 100 --max-pages 0` after verifying a narrow resource scope and confirming the command. Report completeness depends on both the resolved asset mapping and exhausting pagination, and changes in Wiz during pagination can affect counts.

## Errors are intentional

- Missing permissions or unsupported GraphQL fields: exit; no report.
- Resource group not mapped: exit; no report.
- Invalid/missing API token: exit; no report.
- `hasNextPage` with a max-pages cutoff: report marked **partial** in terminal output.
- No matches: header-only CSV, provided the query succeeded.

## References

- https://docs.wiz.io/ (Wiz API Explorer requires tenant access)
- https://docs.brinqa.com/docs/connectors/wiz/ (finding types, projects, API integration examples)
- https://docs.qualys.com/en/conn/latest/integrations/wiz_connector.htm (vulnerability finding assetId filter)
- https://docs.getdx.com/connectors/wiz/ (projects, cloud resources, configurations)
