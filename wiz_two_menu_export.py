#!/usr/bin/env python3
"""Wiz two-menu, read-only CSV export POC.

Menu 1: finding collection. Menu 2: resource group.
Only execute validated group queries. Non-validated combinations refuse to export.
This does not change the previously generated Wiz exporter.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

BASE = Path(__file__).resolve().parent
MENU = [
    ("vulnerability", "Vulnerability Findings"),
    ("sast", "SAST Findings"),
    ("cloud_config", "Cloud Configuration Findings"),
    ("host_config", "Host Configuration Findings"),
    ("attack_surface", "Attack Surface Findings"),
    ("data", "Data Findings"),
    ("secrets", "Secret Findings"),
    ("end_of_life", "End of Life Findings"),
    ("network", "Network Exposure"),
    ("excessive_access", "Excessive Access Findings"),
    ("identity", "Identity Access Findings"),
    ("ai", "AI Security Findings"),
    ("pentest", "Penetration Test Findings"),
]
GROUPS = [
    ("project", "Project"),
    ("code_repository", "Code Repository"),
    ("container_registry", "Container Registry"),
    ("kubernetes_cluster", "Kubernetes Cluster"),
    ("kubernetes_namespace", "Kubernetes Namespace"),
    ("all", "No resource grouping (sample only)"),
]


def menu(title: str, entries: list[str]) -> int:
    if not entries:
        raise RuntimeError(f"No entries available in {title}")
    print(f"\n{title}")
    print("-" * len(title))
    for i, value in enumerate(entries, 1):
        print(f"  {i}. {value}")
    while True:
        try:
            answer = input("Select a number (q to quit): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            raise SystemExit("\nCancelled")
        if answer == "q":
            raise SystemExit(0)
        if answer.isdigit() and 1 <= int(answer) <= len(entries):
            return int(answer) - 1
        print("Invalid selection.")


def safe_slug(value: str) -> str:
    return (re.sub(r"[^a-z0-9_-]+", "_", value.casefold()).strip("_")[:72] or "selection")


def safe_cell(value: Any) -> str:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False)
    if value is None:
        return ""
    result = str(value)
    # Prevent spreadsheet formula execution when opening a CSV.
    if result.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + result
    return result


def flatten(obj: dict, prefix: str = "") -> dict:
    result = {}
    for key, value in obj.items():
        name = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            result.update(flatten(value, name))
        else:
            result[name] = value
    return result


class WizClient:
    def __init__(self):
        import requests
        required = [name for name in ("WIZ_API_URL", "WIZ_CLIENT_ID", "WIZ_CLIENT_SECRET")
                    if not os.getenv(name)]
        if required:
            raise RuntimeError("Missing environment variables: " + ", ".join(required))
        self.s = requests.Session()
        self.s.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        self.api_url = os.environ["WIZ_API_URL"]
        self.authenticate()

    def authenticate(self):
        auth_url = os.getenv("WIZ_AUTH_URL", "https://auth.app.wiz.io/oauth/token")
        response = self.s.post(auth_url, data={
            "grant_type": "client_credentials",
            "audience": os.getenv("WIZ_AUDIENCE", "wiz-api"),
            "client_id": os.environ["WIZ_CLIENT_ID"],
            "client_secret": os.environ["WIZ_CLIENT_SECRET"],
        }, timeout=30)
        response.raise_for_status()
        token = response.json().get("access_token")
        if not token:
            raise RuntimeError("Wiz authentication returned no access_token")
        self.s.headers["Authorization"] = "Bearer " + token

    def graphql(self, query: str, variables: dict) -> dict:
        response = self.s.post(self.api_url, json={"query": query, "variables": variables}, timeout=90)
        if response.status_code == 401:
            self.authenticate()
            response = self.s.post(self.api_url, json={"query": query, "variables": variables}, timeout=90)
        response.raise_for_status()
        payload = response.json()
        if payload.get("errors"):
            msgs = "; ".join(str(err.get("message", err)) for err in payload["errors"])
            raise RuntimeError(f"GraphQL query rejected: {msgs}")
        if "data" not in payload or payload["data"] is None:
            raise RuntimeError("GraphQL response contains no data")
        return payload["data"]


def fetch_connection(client: WizClient, query: str, variables: dict, alias: str,
                     page_size: int, max_pages: int) -> tuple[list[dict], bool]:
    results = []
    cursor = None
    seen = set()
    partial = False
    for page in range(max_pages if max_pages else 1000000):
        data = client.graphql(query, {**variables, "first": page_size, "after": cursor})
        conn = data.get(alias)
        if not isinstance(conn, dict) or not isinstance(conn.get("nodes"), list):
            raise RuntimeError(f"Expected data.{alias}.nodes; check your tenant's GraphQL schema")
        results.extend(conn["nodes"])
        info = conn.get("pageInfo") or {}
        print(f"  Page {page + 1}: received {len(conn['nodes'])} findings", flush=True)
        if not info.get("hasNextPage"):
            break
        if max_pages and (page + 1) >= max_pages:
            partial = True
            break
        new_cursor = info.get("endCursor")
        if not new_cursor or new_cursor in seen:
            raise RuntimeError("Missing/repeated pagination cursor; refusing incomplete export")
        seen.add(new_cursor)
        cursor = new_cursor
    return results, partial


def get_projects(client: WizClient) -> list[dict]:
    query = '''query ProjectChooser($first: Int, $after: String) {
      projects(first: $first, after: $after) {
        nodes { id name }
        pageInfo { hasNextPage endCursor }
      }
    }'''
    projects, limited = fetch_connection(client, query, {}, "projects", 100, 20)
    if limited:
        print("WARNING: Project list is incomplete; use manual ID for a missing project")
    return sorted((p for p in projects if p.get("id")),
                  key=lambda p: str(p.get("name") or ""))


def load_group_mapping(path: Path, group: str) -> list[dict]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get(group, [])
    if not isinstance(entries, list):
        raise RuntimeError(f"Expected {group} to be a list in {path}")
    return [x for x in entries if isinstance(x, dict) and x.get("name")
            and isinstance(x.get("affected_asset_ids"), list) and x.get("affected_asset_ids")]


def select_group(client: WizClient, group: str, mapping_path: Path) -> tuple[str, list[str]]:
    """Return display name, affected asset ids OR [project id]. Never silently ignore a filter."""
    if group == "project":
        try:
            projects = get_projects(client)
        except Exception as exc:
            print(f"Project discovery unavailable ({exc}). You may enter an ID manually.")
            projects = []
        if projects:
            options = [f"{p.get('name') or p['id']} ({p['id']})" for p in projects] + ["Enter project ID manually"]
            choice = menu("STEP 3 — Select Wiz Project", options)
            if choice < len(projects):
                return str(projects[choice].get("name") or projects[choice]["id"]), [str(projects[choice]["id"])]
        project_id = input("Enter exact Wiz Project ID: ").strip()
        if not project_id:
            raise RuntimeError("Project ID is required")
        return project_id, [project_id]
    choices = load_group_mapping(mapping_path, group)
    if not choices:
        raise RuntimeError(
            f"No verified {group.replace('_', ' ')} → affected asset ID mapping. "
            "This relationship is not equivalent to vulnerableAsset.type. "
            f"Populate {mapping_path.name} using IDs from your tenant's Wiz Security Graph/API Explorer. "
            "No CSV was generated."
        )
    choice = menu("STEP 3 — Select Resource", [f"{x['name']} ({len(x['affected_asset_ids'])} related assets)" for x in choices])
    entry = choices[choice]
    ids = [str(x) for x in entry["affected_asset_ids"] if str(x).strip()]
    if not ids:
        raise RuntimeError("Selected resource has no verified affected asset IDs")
    return str(entry["name"]), list(dict.fromkeys(ids))


def prepare_plan(category: str, group: str, ids: list[str], profiles: dict) -> tuple[str, dict, str, str]:
    """Return query, base variables, output label, and split-list filter key."""
    if category == "vulnerability":
        query_path = BASE / "queries" / "vulnerability_filtered.graphql"
        if group == "project":
            return query_path.read_text(encoding="utf-8"), {"filterBy": {"projectId": ids}}, "Vulnerability", "projectId"
        if group == "all":
            return query_path.read_text(encoding="utf-8"), {"filterBy": {}}, "Vulnerability", ""
        return query_path.read_text(encoding="utf-8"), {"filterBy": {"assetId": ids}}, "Vulnerability", "assetId"
    if category == "sast" and group == "all":
        return (BASE / "queries" / "sast_ids.graphql").read_text(encoding="utf-8"), {}, "SAST", ""
    # Other category/group combinations require tenant-reviewed query and filter mapping.
    profile = profiles.get(category, {})
    query_relative = profile.get("query")
    if not query_relative or not isinstance(query_relative, str):
        raise RuntimeError(f"{category} requires a tenant-verified query in tenant_profiles.json. No CSV generated.")
    path = (BASE / query_relative).resolve()
    if BASE not in path.parents or not path.is_file():
        raise RuntimeError("Profile query path missing or outside project directory")
    if group == "all":
        if not profile.get("supports_all", False):
            raise RuntimeError("Unfiltered retrieval is not enabled for this category")
        return path.read_text(encoding="utf-8"), {}, category, ""
    key = profile.get("group_filter_fields", {}).get(group)
    if not key or not isinstance(key, str):
        raise RuntimeError(
            f"{category} / {group}: filter mapping not verified in tenant_profiles.json. No CSV generated."
        )
    return path.read_text(encoding="utf-8"), {"filterBy": {key: ids}}, category, key


def export(client: WizClient, category: str, group: str, resource: str, ids: list[str],
           page_size: int, max_pages: int, profiles: dict, output_dir: Path):
    query, vars_base, label, list_key = prepare_plan(category, group, ids, profiles)
    # Guard: a query that doesn't declare $filterBy cannot enforce resource filtering.
    if group != "all" and "$filterBy" not in query:
        raise RuntimeError("Selected resource filter is absent from query; export refused")
    # Batch large related-resource ID sets, deduplicate findings across overlapping assets.
    id_batches = [ids[i:i + 30] for i in range(0, len(ids), 30)] if group != "all" else [[]]
    unique = {}
    incomplete = False
    for batch_no, batch in enumerate(id_batches, 1):
        variables = json.loads(json.dumps(vars_base))
        if list_key:
            variables["filterBy"][list_key] = batch
        print(f"Fetching batch {batch_no}/{len(id_batches)}...")
        findings, partial = fetch_connection(client, query, variables, "findings", page_size, max_pages)
        incomplete |= partial
        for idx, finding in enumerate(findings):
            if not isinstance(finding, dict):
                raise RuntimeError("Unexpected finding record format")
            key = str(finding.get("id") or f"{batch_no}:{idx}")
            unique[key] = finding
    rows = [{"finding_category": label, "group_type": group,
             "group_name": resource, **flatten(n)} for n in unique.values()]
    fields = ["finding_category", "group_type", "group_name", "id"]
    fields += sorted({k for r in rows for k in r} - set(fields))
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"{safe_slug(category)}_{safe_slug(group)}_{safe_slug(resource)}.csv"
    with output.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: safe_cell(row.get(key)) for key in fields})
    print(f"\nCSV saved: {output} ({len(rows)} unique findings)")
    if incomplete:
        print("WARNING: Page limit reached. This CSV is a PARTIAL sample, not a complete group export.")
    if category == "sast":
        print("Note: current SAST query returns finding IDs only; additional fields need API Explorer validation.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--page-size", type=int, default=10)
    parser.add_argument("--max-pages", type=int, default=1,
                        help="Per query/batch; default 1 page. 0 retrieves all pages.")
    parser.add_argument("--groups", type=Path, default=BASE / "resource_groups.json")
    parser.add_argument("--profiles", type=Path, default=BASE / "tenant_profiles.json")
    parser.add_argument("--out-dir", type=Path, default=BASE / "reports")
    args = parser.parse_args()
    if not 1 <= args.page_size <= 200 or args.max_pages < 0:
        parser.error("--page-size must be between 1 and 200, --max-pages >= 0")
    print("Wiz two-menu CSV exporter (read-only POC)")
    category_idx = menu("STEP 1 — Select Finding Category", [item[1] for item in MENU])
    category = MENU[category_idx][0]
    group_idx = menu("STEP 2 — Select Group By", [item[1] for item in GROUPS])
    group = GROUPS[group_idx][0]
    profiles = json.loads(args.profiles.read_text(encoding="utf-8")) if args.profiles.exists() else {}
    # Fail-fast unsupported category/group before attempting authentication.
    if category != "vulnerability" and not (category == "sast" and group == "all"):
        if not profiles.get(category, {}).get("query"):
            raise RuntimeError(
                "This category/group needs a tenant-verified GraphQL query and filter mapping. "
                "See README.md. No CSV generated."
            )
    if args.max_pages == 0:
        answer = input("This may fetch many records. Type YES to continue: ").strip()
        if answer != "YES":
            raise SystemExit("Cancelled")
    client = WizClient()
    print("Authenticated (token hidden).")
    if group == "all":
        name, ids = "all_accessible", []
    else:
        name, ids = select_group(client, group, args.groups)
    export(client, category, group, name, ids, args.page_size, args.max_pages, profiles, args.out_dir)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError) as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        raise SystemExit(2)
