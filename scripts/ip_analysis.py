#!/usr/bin/env python3
# /// script
# dependencies = ["py-ip2region"]
# ///
"""IP 分析脚本：聚合多源公开 API + DNSBL，返回归属地、网络信息、风险判断。

数据源：
  - ipinfo.io（归属地 + org + asn，免费额度 50k/月）
  - ipapi.co（补充归属地 + ASN/ISP，免费 1000/天）
  - ip.sb（补充 ASN + ISP）
  - RDAP（ASN 注册信息 → hosting 判断）
  - Spamhaus ZEN DNSBL（黑名单/垃圾邮件/代理/Tor，DNS 查询）
  - SpamCop DNSBL（垃圾邮件检测）
  - CBL DNSBL（僵尸网络/恶意软件检测）
  - Tor exit node list（DNS 查询）
  - abuseipdb.com（风险评分，需 ABUSEIPDB_KEY，可选增强）

用法：
  uv run ip_analysis.py <ip_address>
"""

import argparse
import json
import os
import re
import socket
import sys
import time
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

MAX_RETRIES = 2
RETRY_DELAY = 1  # seconds

# CDN URLs for ip2region data files (large files not bundled with skill)
XDB_CDN_URLS = {
    "ip2region_v4.xdb": "https://h23.static.yximgs.com/kos/nlav111379/poify/9dd3414dadd14ea6afe671d7a.xdb",
    "ip2region_v6.xdb": "https://h4.static.yximgs.com/kos/nlav111379/poify/9dd3414dadd14ea6afe671d7b.xdb",
}

# Tiered hosting risk keywords
RISK_TIER_KEYWORDS = {
    "high": ["tor", "exit", "relay", "proxy", "vpn", "anonymizer"],
    "medium": [
        "hosting", "datacenter", "server", "vps", "dedicated",
        "colocation", "backend", "digitalocean", "ovh", "hetzner",
        "linode", "vultr", "rackspace", "bluehost", "hostgator",
    ],
    "low": [
        "cloud", "cdn", "akamai", "fastly", "cloudflare",
        "amazon", "aws", "google", "azure", "microsoft",
        "alibaba", "tencent", "huawei", "oracle", "godaddy",
        "infrastructure",
    ],
}

# ipinfo.io asn_type → risk tier
ASN_TYPE_RISK_MAP = {
    "hosting": "medium",
    "business": "low",
    "isp": None,
    "education": None,
}

# DNSBL servers + Spamhaus ZEN return code interpretation
DNSBL_SERVERS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "cbl.abuseat.org",
]

# Spamhaus ZEN return codes → meaning
SPAMHAUS_CODES = {
    "127.0.0.2": "SBL: 已确认垃圾邮件来源/黑灰产",
    "127.0.0.3": "SBL: 已确认垃圾邮件运营者",
    "127.0.0.4": "XBL: 僵尸网络/恶意软件/被劫持",
    "127.0.0.5": "XBL: 僵尸网络/恶意软件/被劫持",
    "127.0.0.6": "XBL: 僵尸网络/恶意软件/被劫持",
    "127.0.0.7": "XBL: 僵尸网络/恶意软件/被劫持",
    "127.0.0.10": "PBL: ISP 维护的策略禁止直接发送邮件（非 residential）",
    "127.0.0.11": "PBL: ISP 维护的策略禁止直接发送邮件（非 residential）",
}

# Known VPN/proxy provider org names (expanded beyond keywords)
VPN_PROXY_ORGS = [
    # Major VPN providers
    "nordvpn", "expressvpn", "surfshark", "cyberghost", "mullvad",
    "protonvpn", "proton ag", "pia", "private internet access",
    "tefincom", "express vpn international", "seedvpn", "purevpn",
    "hide.me", "ipvanish", "strongvpn", "warp", "tunnelbear",
    # Proxy/anonymizer services
    "luminati", "bright data", "oxidlabs", "geosurf", "proxyrack",
    "smartproxy", "oxylabs", "soax", "packetstream", "iproyal",
    # Chinese VPN/proxy
    "ssr", "v2ray", "shadowsocks", "clash",
]

# Chinese-specific org keywords for IP usage type classification
# IDC/datacenter indicators → 机房/机构 IP
CN_IDC_KEYWORDS = [
    "idc", "data center", "datacenter", "机房", "云计算",
    "alibaba", "阿里云", "alibaba advertising",
    "tencent cloud", "腾讯云", "tencent computing",
    "huawei cloud", "华为云", "huawei technologies",
    "baidu cloud", "百度云", "baidu",
    "jd cloud", "京东云", "jingdong",
    "qiniu", "七牛",
    "ucloud", "优刻得",
    "kingsoft", "金山云",
    "sinnet", "首都在线",
    "cloudmx", "云端时代",
    "21vianet", "世纪互联",
    "chinanet center", "网宿",
    "baishan", "白山云",
    "zenlayer",
    "cdn",
    "tor-exit", "tor exit", "tor relay",  # Tor exit in hostname/org
]

# Chinese residential ISP indicators → 家庭宽带 IP
CN_RESidential_KEYWORDS = [
    "china telecom", "中国电信", "chinanet", "telecommunications corporation",
    "china unicom", "中国联通", "cunicom", "unicom",
    "china mobile", "中国移动", "cmcc", "mobile communications",
    "province network", "宽带", "broadband",
    "cernet", "教育网",
]

# Chinese ISP org name patterns → 家庭宽带 (province-level ISP names)
CN_PROVINCE_PATTERN = r"(province|省)"


def _fetch(url: str, retries: int = MAX_RETRIES, headers: dict = None) -> dict | None:
    """GET JSON from url, retry up to retries times on transient errors."""
    default_headers = {"User-Agent": "MyFlicker-IPAnalysis/1.0", "Accept": "application/json"}
    if headers:
        default_headers.update(headers)
    for attempt in range(retries + 1):
        try:
            req = Request(url, headers=default_headers)
            with urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except (URLError, HTTPError) as exc:
            if attempt < retries:
                time.sleep(RETRY_DELAY)
                continue
            print(f"[WARN] Failed to fetch {url}: {exc}", file=sys.stderr)
            return None
    return None


def _reverse_ip(ip: str) -> str:
    """Reverse IP octets for DNSBL query format."""
    parts = ip.split(".")
    parts.reverse()
    return ".".join(parts)


def _ensure_xdb(xdb_name: str, xdb_path: str) -> bool:
    """Ensure xdb file exists locally; download from CDN if missing.

    Returns True if file is available, False if download failed.
    """
    if os.path.exists(xdb_path) and os.path.getsize(xdb_path) > 0:
        return True

    cdn_url = XDB_CDN_URLS.get(xdb_name)
    if not cdn_url:
        print(f"[WARN] No CDN URL configured for {xdb_name}", file=sys.stderr)
        return False

    os.makedirs(os.path.dirname(xdb_path), exist_ok=True)
    print(f"[INFO] Downloading {xdb_name} ({'~11MB' if 'v4' in xdb_name else '~35MB'}) from CDN...", file=sys.stderr)
    try:
        req = Request(cdn_url, headers={"User-Agent": "MyFlicker-IPAnalysis/1.0"})
        with urlopen(req, timeout=120) as resp:
            with open(xdb_path, "wb") as f:
                while True:
                    chunk = resp.read(1024 * 1024)  # 1MB chunks
                    if not chunk:
                        break
                    f.write(chunk)
        size_mb = os.path.getsize(xdb_path) / (1024 * 1024)
        print(f"[INFO] Downloaded {xdb_name} ({size_mb:.1f}MB)", file=sys.stderr)
        return True
    except Exception as exc:
        print(f"[ERROR] Failed to download {xdb_name}: {exc}", file=sys.stderr)
        # Clean up partial file
        if os.path.exists(xdb_path):
            os.remove(xdb_path)
        return False


def query_ip2region(ip: str, skill_dir: str) -> dict | None:
    """ip2region 离线库：微秒级查询，中国归属地全中文 + ISP 标注。

    数据格式: Country|Province|City|ISP|iso-alpha2-code
    xdb 文件随 skill 一起安装，位于 <skill_dir>/data/ 目录。
    """
    try:
        from ip2region.searcher import new_with_file_only
        from ip2region.util import IPv4, IPv6
    except ImportError:
        print("[WARN] py-ip2region not installed, offline lookup skipped", file=sys.stderr)
        return None

    # Determine version
    is_ipv6 = ":" in ip
    version = IPv6 if is_ipv6 else IPv4
    xdb_name = "ip2region_v6.xdb" if is_ipv6 else "ip2region_v4.xdb"
    xdb_path = os.path.join(skill_dir, "data", xdb_name)

    # Auto-download from CDN if xdb file is missing
    if not _ensure_xdb(xdb_name, xdb_path):
        print(f"[WARN] {xdb_name} not available (local + CDN download failed), offline lookup skipped", file=sys.stderr)
        return None

    try:
        # Use file-only mode (simplest, no memory cache needed for single queries)
        searcher = new_with_file_only(version, xdb_path)
        result_str = searcher.search(ip)
        searcher.close()

        if not result_str:
            return None

        # Parse: Country|Province|City|ISP|iso-alpha2-code
        parts = result_str.split("|")
        country = parts[0] if len(parts) > 0 else ""
        province = parts[1] if len(parts) > 1 else ""
        city = parts[2] if len(parts) > 2 else ""
        isp = parts[3] if len(parts) > 3 else ""
        iso_code = parts[4] if len(parts) > 4 else ""

        return {
            "country": country,
            "province": province,
            "city": city,
            "isp": isp,
            "country_code": iso_code,
            "raw": result_str,
        }
    except Exception as exc:
        print(f"[WARN] ip2region lookup failed for {ip}: {exc}", file=sys.stderr)
        return None


def query_dnsbl(ip: str) -> dict:
    """Query multiple DNSBL servers via DNS. Returns listings per server.

    DNSBL query format: <reversed-ip>.<dnsbl-server>
    If listed, DNS returns 127.0.0.X codes indicating the type of listing.
    """
    rev_ip = _reverse_ip(ip)
    result = {
        "is_blacklisted": False,
        "listings": [],
        "tor_exit": False,
        "botnet": False,
        "spam_source": False,
        "policy_block": False,
    }

    # Check Tor exit nodes via DNS (dnsexitlist.org or dan.me.uk)
    tor_domain = f"{rev_ip}.dnsexitlist.org"
    try:
        addr = socket.getaddrinfo(tor_domain, None, socket.AF_INET)
        result["tor_exit"] = True
        result["is_blacklisted"] = True
        result["listings"].append({
            "server": "dnsexitlist.org",
            "type": "tor_exit",
            "meaning": "Tor 出口节点，匿名中转",
        })
    except socket.gaierror:
        pass  # Not a Tor exit

    # Check each DNSBL
    for bl_server in DNSBL_SERVERS:
        domain = f"{rev_ip}.{bl_server}"
        try:
            addr_info = socket.getaddrinfo(domain, None, socket.AF_INET)
            return_codes = [x[4][0] for x in addr_info]
            result["is_blacklisted"] = True

            for code in set(return_codes):
                code_str = str(code)
                meaning = SPAMHAUS_CODES.get(code_str, "未知黑名单标记")

                # Categorize
                if code_str in ("127.0.0.2", "127.0.0.3"):
                    result["spam_source"] = True
                elif code_str in ("127.0.0.4", "127.0.0.5", "127.0.0.6", "127.0.0.7"):
                    result["botnet"] = True
                elif code_str in ("127.0.0.10", "127.0.0.11"):
                    result["policy_block"] = True

                result["listings"].append({
                    "server": bl_server,
                    "return_code": code_str,
                    "meaning": meaning,
                })
        except socket.gaierror:
            pass  # Not listed on this DNSBL

    return result


def query_ipinfo(ip: str) -> dict | None:
    """ipinfo.io: 归属地 + org + asn + hostname + timezone."""
    data = _fetch(f"https://ipinfo.io/{ip}/json")
    if data and "ip" in data:
        asn_raw = data.get("asn", {}) or {}
        return {
            "country": data.get("country"),
            "country_code": data.get("country"),
            "region": data.get("region"),
            "city": data.get("city"),
            "postal": data.get("postal"),
            "timezone": data.get("timezone"),
            "loc": data.get("loc"),
            "hostname": data.get("hostname"),
            "org": data.get("org"),
            "asn_id": asn_raw.get("id") if isinstance(asn_raw, dict) else str(asn_raw),
            "asn_name": asn_raw.get("name") if isinstance(asn_raw, dict) else "",
            "asn_type": asn_raw.get("type") if isinstance(asn_raw, dict) else "",
        }
    return None


def query_ipapi_co(ip: str) -> dict | None:
    """ipapi.co: 补充归属地 + ASN/ISP + 时区/邮编/货币/语言等基础信息。"""
    data = _fetch(f"https://ipapi.co/{ip}/json/")
    if data and "ip" in data:
        return {
            "country": data.get("country_name"),
            "country_code": data.get("country_code"),
            "country_code_iso3": data.get("country_code_iso3"),
            "region": data.get("region"),
            "city": data.get("city"),
            "postal": data.get("postal"),
            "lat": data.get("latitude"),
            "lon": data.get("longitude"),
            "timezone": data.get("timezone"),
            "utc_offset": data.get("utc_offset"),
            "in_eu": data.get("in_eu"),
            "country_calling_code": data.get("country_calling_code"),
            "currency": data.get("currency"),
            "currency_name": data.get("currency_name"),
            "languages": data.get("languages"),
            "country_area": data.get("country_area"),
            "country_population": data.get("country_population"),
            "asn": data.get("asn"),
            "org": data.get("org"),
            "network": data.get("network"),
            "version": data.get("version"),
        }
    return None


def query_ip_sb(ip: str) -> dict | None:
    """ip.sb: ASN + ISP 补充。"""
    data = _fetch(f"https://api.ip.sb/geoip/{ip}")
    if data and "ip" in data:
        return {
            "country": data.get("country"),
            "country_code": data.get("country_code"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "asn": data.get("asn"),
            "asn_organization": data.get("asn_organization"),
            "organization": data.get("organization"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
        }
    return None


def query_rdap(ip: str) -> dict | None:
    """RDAP: IP 注册信息，判断 hosting/datacenter。"""
    data = _fetch(f"https://rdap.arin.net/registry/ip/{ip}")
    if not data:
        return None
    org_name = ""
    entities = data.get("entities", [])
    for ent in entities:
        vcard = ent.get("vcardArray", [])
        if vcard and len(vcard) > 1:
            for field in vcard[1]:
                if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
                    org_name = str(field[3])
                    break
    cidr = ""
    cidrs = data.get("cidr0_cidrs", [])
    if cidrs:
        prefix = cidrs[0].get("v4prefix", cidrs[0].get("v6prefix", ""))
        length = cidrs[0].get("length", "")
        if prefix and length:
            cidr = f"{prefix}/{length}"
    return {
        "rdap_server": data.get("port43", "rdap.arin.net"),
        "org_name": org_name,
        "cidr": cidr,
    }


def query_abuseipdb(ip: str) -> dict | None:
    """abuseipdb.com: 风险评分（可选增强）。需 ABUSEIPDB_KEY 环境变量。"""
    key = os.environ.get("ABUSEIPDB_KEY")
    if not key:
        return None
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose"
    for attempt in range(MAX_RETRIES + 1):
        try:
            req = Request(url, headers={
                "User-Agent": "MyFlicker-IPAnalysis/1.0",
                "Accept": "application/json",
                "Key": key,
            })
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                if "data" in data:
                    d = data["data"]
                    return {
                        "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
                        "total_reports": d.get("totalReports", 0),
                        "num_distinct_sources": d.get("numDistinctSources", 0),
                        "usage_type": d.get("usageType", ""),
                        "hostnames": d.get("hostnames", []),
                        "is_whitelisted": d.get("isWhitelisted", False),
                    }
                return None
        except (URLError, HTTPError) as exc:
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
                continue
            print(f"[WARN] AbuseIPDB request failed: {exc}", file=sys.stderr)
            return None
    return None


def classify_ip_usage(network_info: dict, rdap_info: dict | None, hostname: str = "", ip2region_isp: str = "") -> dict:
    """判断 IP 用途类型：机构（机房/云/企业）vs 家庭（residential ISP）vs CDN。

    ip2region_isp 字段对中国 IP 特别有用：直接标注「联通」「电信」「移动」「阿里」等。
    """
    combined_text = " ".join([
        str(network_info.get("org", "")),
        str(network_info.get("asn_name", "")),
        str(network_info.get("isp", "")),
        str(network_info.get("asn_organization", "")),
        str(network_info.get("organization", "")),
        str(network_info.get("isp_ip2region", "")),
        str(rdap_info.get("org_name", "") if rdap_info else ""),
        str(hostname),
        str(ip2region_isp),
    ]).lower()

    # ip2region ISP direct match for Chinese IPs
    ip2r_lower = ip2region_isp.lower()
    cn_residential_isp = ["联通", "电信", "移动", "铁通", "广电网", "长城宽带", "教育网",
                          "unicom", "telecom", "mobile", "cmcc", "chinanet", "cernet"]
    cn_idc_isp = ["阿里", "腾讯", "华为", "百度", "京东", "金山", "七牛", "青云",
                  "ali", "tencent", "huawei", "baidu"]

    # org name containing IDC keywords → 机构（even if ip2region says 电信/联通）
    org_idc_match = [kw for kw in CN_IDC_KEYWORDS if kw in combined_text]
    if org_idc_match:
        return {"ip_usage_type": "机构（机房/云服务）", "usage_evidence": org_idc_match}

    # ip2region IDC ISP keywords → 机构
    for isp_kw in cn_idc_isp:
        if isp_kw in ip2r_lower:
            return {"ip_usage_type": "机构（机房/云服务）", "usage_evidence": [f"ip2region:{ip2region_isp}"]}

    # ip2region residential ISP keywords → 家庭
    for isp_kw in cn_residential_isp:
        if isp_kw in ip2r_lower:
            return {"ip_usage_type": "家庭（运营商宽带）", "usage_evidence": [f"ip2region:{ip2region_isp}"]}

    # Check asn_type first (if available from ipinfo.io paid tier)
    asn_type = str(network_info.get("asn_type", "")).lower()
    if asn_type == "hosting":
        return {"ip_usage_type": "机构（机房/数据中心）", "usage_evidence": f"asn_type={asn_type}"}
    elif asn_type == "business":
        return {"ip_usage_type": "机构（企业网络）", "usage_evidence": f"asn_type={asn_type}"}
    elif asn_type == "isp":
        return {"ip_usage_type": "家庭（ISP 宽带）", "usage_evidence": f"asn_type={asn_type}"}

    # VPN/proxy → 机构（代理）
    matched_vpns = [vpn for vpn in VPN_PROXY_ORGS if vpn in combined_text]
    if matched_vpns:
        return {"ip_usage_type": "机构（VPN/代理）", "usage_evidence": matched_vpns}

    # Chinese IDC keywords → 机构
    matched_idc = [kw for kw in CN_IDC_KEYWORDS if kw in combined_text]
    if matched_idc:
        # Further distinguish: CDN vs 机房
        if any(kw in combined_text for kw in ["cdn", "chinanet center", "网宿", "baishan", "白山云", "cloudmx", "zenlayer", "akamai", "fastly", "cloudflare"]):
            return {"ip_usage_type": "机构（CDN）", "usage_evidence": matched_idc}
        return {"ip_usage_type": "机构（机房/云服务）", "usage_evidence": matched_idc}

    # International hosting keywords (from risk tier medium)
    matched_hosting = [kw for kw in RISK_TIER_KEYWORDS["medium"] if kw in combined_text]
    if matched_hosting:
        return {"ip_usage_type": "机构（机房/数据中心）", "usage_evidence": matched_hosting}

    # Chinese residential ISP → 家庭
    matched_residential = [kw for kw in CN_RESidential_KEYWORDS if kw in combined_text]
    if matched_residential:
        return {"ip_usage_type": "家庭（运营商宽带）", "usage_evidence": matched_residential}

    # Province pattern in org name (e.g. "China Unicom Beijing Province Network")
    if re.search(CN_PROVINCE_PATTERN, combined_text):
        return {"ip_usage_type": "家庭（运营商宽带）", "usage_evidence": ["province_network"]}

    # International ISP keywords
    matched_low = [kw for kw in RISK_TIER_KEYWORDS["low"] if kw in combined_text]
    if matched_low and not matched_idc and not matched_hosting:
        return {"ip_usage_type": "机构（云服务/企业）", "usage_evidence": matched_low}

    # Default: unknown
    return {"ip_usage_type": "未知", "usage_evidence": []}


def assess_risk(network_info: dict, dnsbl_result: dict, rdap_info: dict | None) -> dict:
    """综合风险评估：DNSBL 黑名单 + 关键词分级 + ASN 类型 + VPN/proxy 库。

    优先级（从高到低）：
    1. DNSBL 黑名单：Tor exit → high，botnet/spam → high，policy_block → medium
    2. VPN/proxy org 库：命中 → high
    3. 关键词分级：high/medium/low
    4. ipinfo asn_type：hosting → medium，business → low
    5. 无信号 → residential
    """
    # --- DNSBL signals (highest priority) ---
    if dnsbl_result["tor_exit"]:
        return {
            "risk_level": "high",
            "is_hosting": True,
            "hosting_signals": ["tor_exit_node"],
            "is_blacklisted": True,
            "blacklist_detail": dnsbl_result["listings"],
            "risk_note": "⚠️ Tor 出口节点，匿名中转，黑灰产高频使用",
        }

    if dnsbl_result["botnet"] or dnsbl_result["spam_source"]:
        return {
            "risk_level": "high",
            "is_hosting": True,
            "hosting_signals": ["botnet" if dnsbl_result["botnet"] else "spam_source"],
            "is_blacklisted": True,
            "blacklist_detail": dnsbl_result["listings"],
            "risk_note": "⚠️ 僵尸网络/垃圾邮件来源/黑灰产 IP，已被 DNSBL 收录",
        }

    # --- VPN/proxy org check ---
    combined_text = " ".join([
        str(network_info.get("org", "")),
        str(network_info.get("asn_name", "")),
        str(network_info.get("isp", "")),
        str(network_info.get("asn_organization", "")),
        str(network_info.get("organization", "")),
        str(network_info.get("isp_ip2region", "")),
        str(rdap_info.get("org_name", "") if rdap_info else ""),
    ]).lower()

    matched_vpns = [vpn for vpn in VPN_PROXY_ORGS if vpn in combined_text]
    if matched_vpns:
        return {
            "risk_level": "high",
            "is_hosting": True,
            "hosting_signals": matched_vpns,
            "is_blacklisted": dnsbl_result["is_blacklisted"],
            "blacklist_detail": dnsbl_result["listings"] if dnsbl_result["is_blacklisted"] else [],
            "risk_note": "⚠️ VPN/代理服务 IP，真实位置被隐藏",
        }

    # --- Keyword tier check ---
    matched_high = [kw for kw in RISK_TIER_KEYWORDS["high"] if kw in combined_text]
    matched_medium = [kw for kw in RISK_TIER_KEYWORDS["medium"] if kw in combined_text]
    matched_low = [kw for kw in RISK_TIER_KEYWORDS["low"] if kw in combined_text]

    asn_type = str(network_info.get("asn_type", "")).lower()
    asn_type_tier = ASN_TYPE_RISK_MAP.get(asn_type)

    is_hosting = bool(matched_high or matched_medium or matched_low or asn_type_tier)

    if matched_high:
        risk_level = "high"
        hosting_signals = matched_high
        risk_note = "⚠️ 匿名/中转服务 IP（proxy/vpn/relay），大概率非真实用户"
    elif matched_medium or asn_type_tier == "medium":
        risk_level = "medium"
        hosting_signals = matched_medium + ([f"asn_type:{asn_type}"] if asn_type_tier == "medium" else [])
        risk_note = "IP 属于 hosting/数据中心/VPS，非真实用户家庭 IP"
    elif matched_low or asn_type_tier == "low":
        risk_level = "low"
        hosting_signals = matched_low + ([f"asn_type:{asn_type}"] if asn_type_tier == "low" else [])
        risk_note = "IP 属于云服务/CDN/企业网络，非 residential 但风险较低"
    elif dnsbl_result["policy_block"]:
        # PBL alone is normal for residential ISP — check if IP is actually residential
        # If org matches residential ISP keywords, downgrade to low
        residential_match = any(kw in combined_text for kw in CN_RESidential_KEYWORDS)
        province_match = "province network" in combined_text
        if residential_match or province_match or asn_type_tier is None:
            risk_level = "low"
            hosting_signals = []
            is_hosting = False
            risk_note = "IP 属于 residential/普通 ISP（PBL 标记为不允许直接发邮件，这是正常策略）"
        else:
            risk_level = "medium"
            hosting_signals = ["policy_block"]
            is_hosting = True
            risk_note = "IP 被 ISP 策略屏蔽（PBL），通常为数据中心/托管 IP"
    else:
        risk_level = "low"
        hosting_signals = []
        is_hosting = False
        risk_note = "IP 属于 residential/普通 ISP，可信度较高"

    return {
        "risk_level": risk_level,
        "is_hosting": is_hosting,
        "hosting_signals": hosting_signals,
        "is_blacklisted": dnsbl_result["is_blacklisted"],
        "blacklist_detail": dnsbl_result["listings"] if dnsbl_result["is_blacklisted"] else [],
        "risk_note": risk_note,
    }


def analyze(ip: str) -> dict:
    """Aggregate results from all sources."""
    result = {"ip": ip}
    basics = {}
    network_info = {}

    # Determine skill directory for ip2region xdb path
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # DNSBL check (fast, DNS-based)
    dnsbl_result = query_dnsbl(ip)

    # Source 0: ip2region (offline, fastest, best for Chinese IPs)
    r0 = query_ip2region(ip, skill_dir)
    if r0:
        result["geo"] = {
            "country": r0.get("country", ""),
            "region": r0.get("province", ""),
            "city": r0.get("city", ""),
            "coordinates": "",
        }
        basics["country_code"] = r0.get("country_code", "")
        # ip2region ISP is very useful for Chinese IPs (联通/电信/阿里 etc.)
        if r0.get("isp") and r0["isp"] != "0":
            basics["ip2region_isp"] = r0["isp"]
            network_info["isp_ip2region"] = r0["isp"]

    # Source 1: ipinfo.io (online, supplements coordinates + hostname + ASN)
    r1 = query_ipinfo(ip)
    if r1:
        if "geo" in result:
            if r1.get("loc"):
                result["geo"]["coordinates"] = r1["loc"]
        else:
            result["geo"] = {
                "country": r1.get("country"),
                "region": r1.get("region"),
                "city": r1.get("city"),
                "coordinates": r1.get("loc", ""),
            }
        basics["hostname"] = r1.get("hostname", "")
        if r1.get("timezone") and not basics.get("timezone"):
            basics["timezone"] = r1["timezone"]
        if r1.get("postal") and not basics.get("postal_code"):
            basics["postal_code"] = r1["postal"]
        # For non-Chinese IPs, ipinfo.io names may be more detailed
        if r0 and r0.get("country") == "中国":
            pass  # Keep ip2region's Chinese names
        elif "geo" in result and r1.get("city") and r1["city"] != "0":
            result["geo"]["city"] = r1["city"]
            if r1.get("region"):
                result["geo"]["region"] = r1["region"]
            if r1.get("country"):
                result["geo"]["country"] = r1["country"]
        network_info["org"] = r1.get("org", "")
        network_info["asn_id"] = r1.get("asn_id", "")
        network_info["asn_name"] = r1.get("asn_name", "")
        network_info["asn_type"] = r1.get("asn_type", "")
        network_info["org"] = r1.get("org", "")
        network_info["asn_id"] = r1.get("asn_id", "")
        network_info["asn_name"] = r1.get("asn_name", "")
        network_info["asn_type"] = r1.get("asn_type", "")

    # Source 2: ipapi.co (online, supplements timezone/currency etc.)
    r2 = query_ipapi_co(ip)
    if r2:
        if "geo" not in result:
            result["geo"] = {
                "country": r2.get("country"),
                "region": r2.get("region"),
                "city": r2.get("city"),
                "coordinates": f"{r2['lat']},{r2['lon']}" if r2.get("lat") else "",
            }
        elif not result["geo"].get("coordinates") and r2.get("lat"):
            result["geo"]["coordinates"] = f"{r2['lat']},{r2['lon']}"
        # Fill basics from ipapi.co (richer detail)
        if r2.get("timezone") and not basics.get("timezone"):
            basics["timezone"] = r2["timezone"]
        if r2.get("utc_offset"):
            basics["utc_offset"] = r2["utc_offset"]
        if r2.get("postal") and not basics.get("postal_code"):
            basics["postal_code"] = r2["postal"]
        if r2.get("country_code"):
            basics["country_code"] = r2["country_code"]
        if r2.get("country_code_iso3"):
            basics["country_code_iso3"] = r2["country_code_iso3"]
        if r2.get("country_calling_code"):
            basics["country_calling_code"] = r2["country_calling_code"]
        if r2.get("currency"):
            basics["currency"] = r2["currency"]
        if r2.get("currency_name"):
            basics["currency_name"] = r2["currency_name"]
        if r2.get("languages"):
            basics["languages"] = r2["languages"]
        if r2.get("in_eu") is not None:
            basics["in_eu"] = r2["in_eu"]
        if r2.get("version"):
            basics["ip_version"] = r2["version"]
        # Network
        if r2.get("asn"):
            network_info["asn"] = r2["asn"]
        if r2.get("org") and not network_info.get("org"):
            network_info["org"] = r2["org"]
        if r2.get("network"):
            network_info["network_cidr"] = r2["network"]

    # Source 3: ip.sb
    r3 = query_ip_sb(ip)
    if r3:
        if "geo" not in result:
            result["geo"] = {
                "country": r3.get("country"),
                "region": "",
                "city": r3.get("city"),
                "coordinates": f"{r3['latitude']},{r3['longitude']}" if r3.get("latitude") else "",
            }
        if r3.get("country_code") and not basics.get("country_code"):
            basics["country_code"] = r3["country_code"]
        if r3.get("isp") and not network_info.get("isp"):
            network_info["isp"] = r3["isp"]
        if r3.get("asn"):
            network_info["asn"] = r3["asn"]
        if r3.get("asn_organization"):
            network_info["asn_organization"] = r3["asn_organization"]
        if r3.get("organization") and not network_info.get("org"):
            network_info["org"] = r3["organization"]

    # Source 4: RDAP
    r4 = query_rdap(ip)
    if r4:
        network_info["rdap_org"] = r4.get("org_name", "")
        network_info["rdap_cidr"] = r4.get("cidr", "")

    # Build basics section
    # Generate map link from coordinates
    coords = result.get("geo", {}).get("coordinates", "")
    if coords and "," in coords:
        basics["map_link"] = f"https://www.google.com/maps?q={coords}"
    basics["ip_version"] = "IPv6" if ":" in ip else "IPv4"

    # IP usage type classification (机构 vs 家庭)
    usage_info = classify_ip_usage(network_info, r4, basics.get("hostname", ""), basics.get("ip2region_isp", ""))
    basics["ip_usage_type"] = usage_info["ip_usage_type"]
    basics["usage_evidence"] = usage_info["usage_evidence"]

    result["basics"] = {k: v for k, v in basics.items() if v}
    result["network"] = {k: v for k, v in network_info.items() if v}

    # Risk assessment
    base_risk = assess_risk(network_info, dnsbl_result, r4)

    # Optional AbuseIPDB enhancement
    r5 = query_abuseipdb(ip)
    if r5:
        abuse_score = r5["abuse_confidence_score"]
        abuse_level = "high" if abuse_score >= 75 else "medium" if abuse_score >= 25 else "low"

        # Combine: AbuseIPDB high overrides everything; medium + hosting → upgrade to high
        if abuse_level == "high":
            combined_level = "high"
        elif abuse_level == "medium" and base_risk["is_hosting"]:
            combined_level = "high"
        elif abuse_level == "medium":
            combined_level = "medium"
        else:
            combined_level = base_risk["risk_level"]

        result["risk"] = {
            **base_risk,
            "risk_level": combined_level,
            "abuse_confidence_score": abuse_score,
            "total_reports": r5["total_reports"],
            "distinct_report_sources": r5["num_distinct_sources"],
            "usage_type": r5["usage_type"],
            "is_whitelisted": r5["is_whitelisted"],
            "hostnames": r5["hostnames"],
        }
    else:
        result["risk"] = base_risk

    return result


def main():
    parser = argparse.ArgumentParser(description="IP address analysis tool")
    parser.add_argument("ip", help="IP address to analyze (e.g. 8.8.8.8)")
    args = parser.parse_args()

    result = analyze(args.ip)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()