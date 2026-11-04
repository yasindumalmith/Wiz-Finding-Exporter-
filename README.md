# Wiz Two-Menu CSV Exporter — Read-Only POC

This is a **separate project** and does **not modify** the previous Wiz exporter. The CLI lets you select **(1) a finding category** and **(2) a resource group**, then choose a specific group member when supported. The SAST → Code Repository route discovers repositories in Wiz and exports their detailed findings. Other supported routes retain their existing behavior.

## Start on Ubuntu

```bash
cd wiz_two_menu_poc
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export WIZ_API_URL='https://api.YOUR_REGION.app.wiz.io/graphql'
export WIZ_CLIENT_ID='YOUR_CLIENT_ID'
read -rsp 'Wiz Client Secret: ' WIZ_CLIENT_SECRET; echo
export WIZ_CLIENT_SECRET
python3 wiz_two_menu_export.py
```

`WIZ_API_URL`, `WIZ_CLIENT_ID`, and `WIZ_CLIENT_SECRET` are required. `WIZ_AUTH_URL` defaults to `https://auth.app.wiz.io/oauth/token`; set it if your tenant uses another auth endpoint. `WIZ_AUDIENCE` defaults to `wiz-api`. Ensure the client has permission to read the relevant Wiz findings and inventory. Keep credentials and exported findings out of Git. Never paste a token or secret into this chat.

## Run with Docker

From the project directory, build the image and create a host directory for CSV reports:

```bash
docker build -t wiz-two-menu-exporter .
mkdir -p reports
```

Export the three required environment variables in your shell as shown above, then run the interactive menu:

```bash
docker run --rm -it \
  --user "$(id -u):$(id -g)" \
  --env WIZ_API_URL \
  --env WIZ_CLIENT_ID \
  --env WIZ_CLIENT_SECRET \
  --mount "type=bind,src=$(pwd)/reports,dst=/app/reports" \
  wiz-two-menu-exporter
```

CSV files appear in the host `reports/` directory. The `--user` option lets the container write files as your Linux user. If you use optional `WIZ_AUTH_URL` or `WIZ_AUDIENCE` settings, add `--env WIZ_AUTH_URL` or `--env WIZ_AUDIENCE` to the run command. Exporter arguments go after the image name, for example `wiz-two-menu-exporter --page-size 100`. To use edited `resource_groups.json`, `tenant_profiles.json`, or query files without rebuilding, mount those files into `/app` with Docker's read-only bind mounts.

## SAST repository export

Run `python3 wiz_two_menu_export.py`, then choose **2. SAST Findings**, **2. Code Repository**, and a repository from the numbered list. The list comes from `sastFindingsGroupedByValues` using `REPOSITORY`; it shows each repository name, finding count, and platform. The script follows every repository-group cursor before showing the list. It uses `repository.id` from the selected group, not the group's JSON-encoded `id`.

The script then calls `sastFindings` with the selected repository ID in `filterBy.resource.repositoryId.equals`. It follows every finding cursor by default and writes a detailed CSV in `reports/`, for example `reports/sast_wiz-code-demo_public-demo.csv`. Use `--out-dir PATH` for another output directory. The file includes finding details, repository and branch columns, code location, timestamps, and source URL. Null values become empty cells. CSV quoting handles multiline text; spreadsheet formula escaping and UTF-8 with BOM remain enabled.

Use `python3 wiz_two_menu_export.py --page-size 100` to request larger pages. To request a finding sample, use `python3 wiz_two_menu_export.py --max-pages 1`. The repository list is still fetched completely; only the chosen repository's findings are page-limited. SAST repository sample filenames include `_sample`; if more pages existed, they also include `_partial`. Other routes still default to one finding page. `--max-pages 0` explicitly requests all pages and prompts for confirmation, as before. Existing report files are never overwritten; repeat exports receive a numeric suffix.

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
| SAST Findings | Code Repository | Dynamically lists repository groups, then exports all detailed findings for the selected repository by default; demo-tenant workflow supplied by user, live validation of this code pending |
| SAST Findings | Other specific groups | Tenant profile and supported filter required |
| Secrets, configuration, host, etc. | Any group | Tenant profile and supported filter required (not assumed) |

The menu's Group By options are still hardcoded. Only SAST → Code Repository discovers group members from grouped finding results. Other grouping dimensions and category-specific discovery are planned for later phases. In Wiz the GUI can group by Security Graph relationships that are not guaranteed to map to a direct `filterBy` field. This code explicitly refuses unsupported combinations instead of giving misleading CSVs.

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

The default page size is 10. SAST → Code Repository fetches all group pages and all matching finding pages unless `--max-pages` is explicitly set. Other routes default to one finding page. For a complete export on those routes use `--page-size 100 --max-pages 0` after verifying a narrow resource scope and confirming the command. A page-limited export with more results is marked `_partial` in its filename and terminal output. Report completeness also depends on any manually resolved asset mapping, and changes in Wiz during pagination can affect counts.

## Errors are intentional

- Missing permissions or unsupported GraphQL fields: exit; no report.
- Resource group not mapped: exit; no report.
- Invalid/missing API token: exit; no report.
- Missing or repeated pagination cursor, or malformed page information: exit without a report.
- `hasNextPage` with a max-pages cutoff: report marked **partial** in its filename and terminal output.
- No matches: header-only CSV, provided the query succeeded.

## References

- https://docs.wiz.io/ (Wiz API Explorer requires tenant access)
- https://docs.brinqa.com/docs/connectors/wiz/ (finding types, projects, API integration examples)
- https://docs.qualys.com/en/conn/latest/integrations/wiz_connector.htm (vulnerability finding assetId filter)
- https://docs.getdx.com/connectors/wiz/ (projects, cloud resources, configurations)
