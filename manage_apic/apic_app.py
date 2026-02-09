from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request
from logging.handlers import RotatingFileHandler

import ipaddress
import logging
import os
import re
from typing import Any

import requests

apic_blueprint = Blueprint(
    "apic",
    __name__,
    template_folder="templates",
    static_folder="static",
)

LOG_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "logs", "manage_apic")
)
os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger("manage_apic")
logger.setLevel(logging.INFO)
if not logger.handlers:
    file_handler = RotatingFileHandler(
        os.path.join(LOG_DIR, "apic.log"),
        maxBytes=5_000_000,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(
        logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s")
    )
    logger.addHandler(file_handler)

APICS: dict[str, dict[str, str]] = {
    "POD-ANZ": {"name": "DC2 - POD1", "url": "https://10.255.255.1"},
    "POD-RBX": {"name": "DC1 - POD2", "url": "https://10.255.255.2"},
}
DEFAULT_VRF_DN_FILTER = "SLF-DEFAULT:SLF-DEFAULT_VRF"

GATEWAY_MAP = {
    "192.168.200.115": "DC2-FWSDWAN",
    "192.168.200.169": "DC1-NEXUS-5K",
    "192.168.200.170": "DC1-NEXUS-5K",
    "10.67.30.154": "DC2-FI56",
    "172.22.2.154": "DC1-FI12",
    "192.168.200.195": "DC1-FI03",
    "192.168.200.203": "DC1-FWSDWAN",
    "10.67.30.50": "DC2-FI05",
    "172.16.55.64": "Loopback leaf",
    "172.16.55.65": "Loopback leaf",
    "172.16.55.66": "Loopback leaf",
    "172.16.55.67": "Loopback leaf",
    "172.16.59.64": "Loopback leaf",
    "172.16.59.66": "Loopback leaf",
    "172.16.50.66": "Loopback leaf",
    "172.16.50.64": "Loopback leaf",
    "172.16.2.66": "Loopback leaf",
    "172.16.2.68": "Loopback leaf",
    "172.16.8.64": "Loopback leaf",
}

requests.packages.urllib3.disable_warnings()
TIMEOUT = (5, 30)


def build_username(raw: str, auth_mode: str) -> str:
    if auth_mode == "local":
        if raw.lower().startswith("apic:local\\"):
            return raw
        return f"apic:Local\\{raw}"
    return raw


def apic_login(apic_url: str, username: str, password: str) -> dict[str, str]:
    payload = {"aaaUser": {"attributes": {"name": username, "pwd": password}}}
    response = requests.post(
        f"{apic_url}/api/aaaLogin.json",
        json=payload,
        verify=False,
        timeout=TIMEOUT,
    )
    if response.status_code != 200:
        raise RuntimeError(f"Login failed on {apic_url}: {response.text}")

    token = response.json()["imdata"][0]["aaaLogin"]["attributes"]["token"]
    return {"Cookie": f"APIC-cookie={token}", "Content-Type": "application/json"}


def _safe_get(
    apic_url: str,
    path: str,
    headers: dict[str, str],
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = f"{apic_url}{path}"
    response = requests.get(
        url,
        headers=headers,
        params=params,
        verify=False,
        timeout=TIMEOUT,
    )
    if response.status_code != 200:
        raise RuntimeError(f"GET {url} failed: {response.text}")
    return response.json()


def add_gateway_names(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for row in rows:
        ip = (row.get("nh_addr") or "").split("/")[0]
        row["gateway_name"] = GATEWAY_MAP.get(ip, "")
    return rows


def fetch_routes_from_apic(
    apic_url: str,
    headers: dict[str, str],
    vrf_dn_filter: str,
) -> list[dict[str, Any]]:
    params = {
        "query-target-filter": f'wcard(uribv4Route.dn,"{vrf_dn_filter}")',
        "rsp-subtree": "full",
        "order-by": "uribv4Route.dn|asc",
    }
    data = _safe_get(apic_url, "/api/class/uribv4Route.json", headers, params)

    routes: list[dict[str, Any]] = []
    for entry in data.get("imdata", []):
        route_obj = entry.get("uribv4Route")
        if not route_obj:
            continue

        attrs = route_obj.get("attributes", {})
        dn = attrs.get("dn", "")
        node_match = re.search(r"node-(\d+)", dn)
        node = node_match.group(1) if node_match else ""

        prefix = attrs.get("prefix", "")
        pfx_len = attrs.get("prefixLength", "")
        if pfx_len and "/" not in prefix:
            prefix = f"{prefix}/{pfx_len}"

        children = route_obj.get("children") or []
        if not children:
            routes.append(
                {
                    "prefix": prefix,
                    "nh_addr": "",
                    "pref": "",
                    "route_type": "",
                    "vrf": attrs.get("vrf", dn),
                    "node": node,
                }
            )
            continue

        for child in children:
            nh = child.get("uribv4Nexthop", {}).get("attributes", {})
            routes.append(
                {
                    "prefix": prefix,
                    "nh_addr": nh.get("addr", ""),
                    "pref": nh.get("pref", ""),
                    "route_type": nh.get("routeType", ""),
                    "vrf": nh.get("vrf", attrs.get("vrf", dn)),
                    "node": node,
                }
            )

    return routes


def resolve_endpoint(apic_url: str, headers: dict[str, str], ip: str) -> dict[str, Any]:
    params = {
        "query-target-filter": f'eq(fvCEp.ip,"{ip}")',
        "rsp-subtree": "full",
    }
    data = _safe_get(apic_url, "/api/node/class/fvCEp.json", headers, params)
    imdata = data.get("imdata", [])
    if not imdata:
        return {"ip": ip, "found": False}

    attrs = imdata[0]["fvCEp"]["attributes"]
    dn = attrs.get("dn", "")

    tenant = dn.split("/tn-")[1].split("/")[0] if "/tn-" in dn else ""
    epg = dn.split("/epg-")[1].split("/")[0] if "/epg-" in dn else ""

    leaf = ""
    iface = ""
    children = imdata[0]["fvCEp"].get("children", [])
    for child in children:
        path = child.get("fvRsCEpToPathEp", {}).get("attributes", {}).get("tDn", "")
        if not path:
            continue
        if "/paths-" in path:
            leaf = path.split("/paths-")[1].split("/")[0]
        elif "/protpaths-" in path:
            leaf = path.split("/protpaths-")[1].split("/")[0]
        if "pathep-[" in path:
            iface = path.split("pathep-[", 1)[1].split("]", 1)[0]
        break

    return {
        "ip": ip,
        "found": True,
        "tenant": tenant,
        "epg": epg,
        "leaf": leaf,
        "iface": iface,
        "vlan": attrs.get("encap") or "",
        "dn": dn,
    }


def best_route_for_ip(routes: list[dict[str, Any]], dst_ip: str) -> dict[str, Any] | None:
    try:
        target = ipaddress.ip_address(dst_ip)
    except ValueError:
        return None

    best_route: dict[str, Any] | None = None
    best_prefix_len = -1

    for route in routes:
        prefix = (route.get("prefix") or "").strip()
        if "/" not in prefix:
            continue

        try:
            network = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue

        if target in network and network.prefixlen > best_prefix_len:
            best_prefix_len = network.prefixlen
            best_route = route

    return best_route


def fetch_events(
    apic_url: str,
    headers: dict[str, str],
    ip_filters: list[str],
    limit_per_ip: int = 100,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for ip in ip_filters:
        if not ip:
            continue
        params = {
            "query-target-filter": f'wcard(eventRecord.descr,"{ip}")',
            "order-by": "eventRecord.created|desc",
            "page-size": limit_per_ip,
        }
        try:
            data = _safe_get(apic_url, "/api/class/eventRecord.json", headers, params)
        except Exception as exc:
            logger.error("eventRecord fetch error on %s for %s: %s", apic_url, ip, exc)
            continue

        for item in data.get("imdata", []):
            rec = item.get("eventRecord", {}).get("attributes", {})
            rows.append(
                {
                    "created": rec.get("created"),
                    "severity": rec.get("severity"),
                    "code": rec.get("code"),
                    "descr": rec.get("descr"),
                    "affected": rec.get("affected"),
                }
            )

    dedup = {(r["created"], r["code"], r["descr"]): r for r in rows}
    out = list(dedup.values())
    out.sort(key=lambda x: x.get("created", ""), reverse=True)
    return out


def fetch_fabric_overview(apic_url: str, headers: dict[str, str]) -> dict[str, Any]:
    nodes_data = _safe_get(
        apic_url,
        "/api/node/class/fabricNode.json",
        headers,
        {"order-by": "fabricNode.id|asc"},
    )

    ports_data = _safe_get(
        apic_url,
        "/api/node/class/l1PhysIf.json",
        headers,
        {"order-by": "l1PhysIf.dn|asc", "page-size": 1000},
    )

    leafs: dict[str, dict[str, Any]] = {}
    spines: list[dict[str, Any]] = []

    for item in nodes_data.get("imdata", []):
        attrs = item.get("fabricNode", {}).get("attributes", {})
        role = attrs.get("role", "")
        node_id = attrs.get("id", "")
        node_name = attrs.get("name", f"node-{node_id}")
        state = attrs.get("fabricSt", attrs.get("state", "unknown"))

        if role == "leaf":
            leafs[node_id] = {
                "node": node_id,
                "name": node_name,
                "state": state,
                "ports": [],
            }
        elif role == "spine":
            spines.append(
                {
                    "node": node_id,
                    "name": node_name,
                    "state": state,
                    "ports_up": 0,
                    "ports_total": 0,
                }
            )

    for item in ports_data.get("imdata", []):
        attrs = item.get("l1PhysIf", {}).get("attributes", {})
        dn = attrs.get("dn", "")
        match = re.search(r"node-(\d+)", dn)
        if not match:
            continue
        node_id = match.group(1)
        if node_id not in leafs:
            continue

        leafs[node_id]["ports"].append(
            {
                "id": attrs.get("id", ""),
                "admin": attrs.get("adminSt", ""),
                "oper": attrs.get("operSt", ""),
                "speed": attrs.get("speed", ""),
                "action_enabled": False,
            }
        )

    for leaf in leafs.values():
        leaf["ports"].sort(key=lambda p: p.get("id", ""))

    return {
        "leafs": sorted(list(leafs.values()), key=lambda x: x.get("node", "")),
        "spines": sorted(spines, key=lambda x: x.get("node", "")),
    }


def fetch_vlan_table(apic_url: str, headers: dict[str, str]) -> list[dict[str, Any]]:
    params = {
        "rsp-subtree": "full",
        "page-size": 1000,
        "order-by": "fvBD.dn|asc",
    }
    data = _safe_get(apic_url, "/api/class/fvBD.json", headers, params)

    out: list[dict[str, Any]] = []
    for item in data.get("imdata", []):
        bd = item.get("fvBD")
        if not bd:
            continue

        attrs = bd.get("attributes", {})
        dn = attrs.get("dn", "")
        tenant = dn.split("/tn-")[1].split("/")[0] if "/tn-" in dn else ""
        bd_name = attrs.get("name", "")

        vlan = ""
        subnet = ""

        for child in bd.get("children", []) or []:
            if "fvSubnet" in child and not subnet:
                subnet = child["fvSubnet"].get("attributes", {}).get("ip", "")
            if "fvRsBd" in child and not vlan:
                tdn = child["fvRsBd"].get("attributes", {}).get("tDn", "")
                if "vlan-" in tdn:
                    vlan = tdn.split("vlan-")[-1]

        out.append(
            {
                "tenant": tenant,
                "bd": bd_name,
                "vlan": f"vlan-{vlan}" if vlan else "",
                "encap": f"vlan-{vlan}" if vlan else "",
                "subnet": subnet,
            }
        )

    return out


@apic_blueprint.route("/", methods=["GET"])
def page():
    return render_template("manage_apic.html", apics=APICS)


@apic_blueprint.route("/connect", methods=["POST"])
def connect_and_load():
    data = request.get_json(force=True) or {}
    pods = data.get("pods") or ["POD-ANZ"]
    auth_mode = data.get("auth_mode", "local")
    username = build_username((data.get("username") or "").strip(), auth_mode)
    password = (data.get("password") or "").strip()
    vrf_dn = data.get("vrf_dn_filter") or DEFAULT_VRF_DN_FILTER

    if not username or not password:
        return jsonify({"ok": False, "error": "Username / password requis."}), 400

    rows: list[dict[str, Any]] = []
    errors: list[str] = []

    for pod in pods:
        apic = APICS.get(pod)
        if not apic:
            continue
        try:
            headers = apic_login(apic["url"], username, password)
            pod_rows = fetch_routes_from_apic(apic["url"], headers, vrf_dn)
            for row in pod_rows:
                row["pod"] = pod
            rows.extend(pod_rows)
        except Exception as exc:
            msg = f"[{pod}] {exc}"
            errors.append(msg)
            logger.error(msg)

    add_gateway_names(rows)

    return jsonify(
        {
            "ok": True,
            "errors": errors,
            "count": len(rows),
            "unique_prefixes": len({r.get("prefix", "") for r in rows}),
            "rows": rows,
        }
    )


@apic_blueprint.route("/pathtrace", methods=["POST"])
def pathtrace():
    data = request.get_json(force=True) or {}
    pods = data.get("pods") or ["POD-ANZ"]
    auth_mode = data.get("auth_mode", "local")
    username = build_username((data.get("username") or "").strip(), auth_mode)
    password = (data.get("password") or "").strip()
    vrf_dn = data.get("vrf_dn") or DEFAULT_VRF_DN_FILTER
    src_ip = (data.get("src_ip") or "").strip()
    dst_ip = (data.get("dst_ip") or "").strip()

    if not username or not password or not src_ip or not dst_ip:
        return (
            jsonify(
                {
                    "ok": False,
                    "error": "username, password, src_ip et dst_ip sont requis.",
                }
            ),
            400,
        )

    results = []
    errors = []

    for pod in pods:
        apic = APICS.get(pod)
        if not apic:
            continue
        try:
            headers = apic_login(apic["url"], username, password)
            src = resolve_endpoint(apic["url"], headers, src_ip)
            dst = resolve_endpoint(apic["url"], headers, dst_ip)
            routes = fetch_routes_from_apic(apic["url"], headers, vrf_dn)
            add_gateway_names(routes)
            route = best_route_for_ip(routes, dst_ip) or {}
            results.append({"pod": pod, "src": src, "dst": dst, "route": route})
        except Exception as exc:
            msg = f"[{pod}] pathtrace error: {exc}"
            errors.append(msg)
            logger.error(msg)

    return jsonify({"ok": True, "results": results, "errors": errors})


@apic_blueprint.route("/events", methods=["POST"])
def events():
    data = request.get_json(force=True) or {}
    pods = data.get("pods") or ["POD-ANZ"]
    auth_mode = data.get("auth_mode", "local")
    username = build_username((data.get("username") or "").strip(), auth_mode)
    password = (data.get("password") or "").strip()
    ip_filters = data.get("ip_filters") or []
    limit_per_ip = int(data.get("limit") or 100)

    if not username or not password:
        return jsonify({"ok": False, "error": "username / password requis."}), 400

    rows_out: list[dict[str, Any]] = []
    errors: list[str] = []

    for pod in pods:
        apic = APICS.get(pod)
        if not apic:
            continue
        try:
            headers = apic_login(apic["url"], username, password)
            events_rows = fetch_events(
                apic["url"], headers, ip_filters, limit_per_ip=limit_per_ip
            )
            for row in events_rows:
                row["pod"] = pod
            rows_out.extend(events_rows)
        except Exception as exc:
            msg = f"[{pod}] events error: {exc}"
            errors.append(msg)
            logger.error(msg)

    return jsonify({"ok": True, "rows": rows_out[:400], "errors": errors})


@apic_blueprint.route("/fabric", methods=["POST"])
def fabric():
    data = request.get_json(force=True) or {}
    pods = data.get("pods") or ["POD-ANZ"]
    auth_mode = data.get("auth_mode", "local")
    username = build_username((data.get("username") or "").strip(), auth_mode)
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"ok": False, "error": "username / password requis."}), 400

    rows = []
    errors = []

    for pod in pods:
        apic = APICS.get(pod)
        if not apic:
            continue
        try:
            headers = apic_login(apic["url"], username, password)
            overview = fetch_fabric_overview(apic["url"], headers)
            rows.append({"pod": pod, **overview})
        except Exception as exc:
            msg = f"[{pod}] fabric error: {exc}"
            errors.append(msg)
            logger.error(msg)

    return jsonify({"ok": True, "rows": rows, "readonly": True, "errors": errors})


@apic_blueprint.route("/vlans", methods=["POST"])
def vlans():
    data = request.get_json(force=True) or {}
    pods = data.get("pods") or ["POD-ANZ"]
    auth_mode = data.get("auth_mode", "local")
    username = build_username((data.get("username") or "").strip(), auth_mode)
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"ok": False, "error": "username / password requis."}), 400

    rows: list[dict[str, Any]] = []
    errors: list[str] = []

    for pod in pods:
        apic = APICS.get(pod)
        if not apic:
            continue
        try:
            headers = apic_login(apic["url"], username, password)
            pod_rows = fetch_vlan_table(apic["url"], headers)
            for row in pod_rows:
                row["pod"] = pod
            rows.extend(pod_rows)
        except Exception as exc:
            msg = f"[{pod}] vlans error: {exc}"
            errors.append(msg)
            logger.error(msg)

    return jsonify({"ok": True, "rows": rows, "errors": errors})
