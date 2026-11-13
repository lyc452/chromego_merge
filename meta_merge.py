import yaml
import json
import urllib.request
import urllib.error
import logging
import geoip2.database
import socket
import re
import time
from urllib.parse import urlsplit
from collections import OrderedDict


SUPPORTED_TYPES = {
    "hysteria",
    "hysteria2",
    "vless",
    "vmess",
    "tuic",
    "ssr",
    "mieru",
    "shadowquic",
}


def fetch_subscription(url):
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                return response.read().decode("utf-8-sig")
        except urllib.error.HTTPError as error:
            if 400 <= error.code < 500 or attempt == 2:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == 2:
                raise
        time.sleep(attempt + 1)


# 提取节点
def process_urls(url_file, processor):
    try:
        with open(url_file, "r", encoding="utf-8-sig") as file:
            urls = file.read().splitlines()

        for index, url in enumerate(urls):
            url = url.strip()
            if not url or url.startswith("#"):
                continue
            try:
                data = fetch_subscription(url)
                processor(data, index)
            except Exception as e:
                logging.error(f"Error processing {url_file} entry {index + 1}: {e}")
    except Exception as e:
        logging.error(f"Error reading file {url_file}: {e}")


# 提取clash节点（扩展协议支持）
def process_clash(data, index):
    content = yaml.safe_load(data)
    if not isinstance(content, dict):
        logging.warning(f"Skipping invalid Clash subscription entry {index + 1}")
        return

    proxies = content.get("proxies", [])
    
    for proxy in proxies:
        proxy_type = proxy.get("type")
        if proxy_type not in SUPPORTED_TYPES:
            continue
        
        server = proxy.get("server", "")
        location = get_physical_location(server)
        proxy["name"] = f"{location}_{proxy_type}_{index}_{len(merged_proxies) + 1}"
        merged_proxies.append(proxy)


def proxy_name(server, proxy_type, source, index, suffix=""):
    location = get_physical_location(server)
    parts = [location, proxy_type, source, str(index)]
    if suffix:
        parts.append(str(suffix))
    return "_".join(parts)


def get_physical_location(address):
    address = address.strip('[]')
    try:
        ip_address = socket.gethostbyname(address)
    except socket.gaierror:
        ip_address = address

    try:
        reader = geoip2.database.Reader("GeoLite2-City.mmdb")
        response = reader.city(ip_address)
        country = response.country.name or "Unknown"
        city = response.city.name or "Unknown"
        return f"{country}_{city}"
    except geoip2.errors.AddressNotFoundError:
        return "Unknown"
    except Exception as e:
        logging.error(f"Error getting location for {address}: {e}")
        return "Unknown"


# 处理hysteria（保留原有逻辑）
def process_hysteria(data, index):
    try:
        json_data = json.loads(data)
        server_ports = json_data["server"]
        server_part, port_part = server_ports.rsplit(":", 1)
        server = server_part.strip('[]')
        ports_slt = port_part.split(",")
        server_port = int(ports_slt[0])
        
        location = get_physical_location(server)
        name = f"{location}_hy_{index}"

        proxy = {
            "name": name,
            "type": "hysteria",
            "server": server,
            "port": server_port,
            "auth_str": json_data["auth_str"],
            "up": 1000,
            "down": 1000,
            "fast-open": True,
            "protocol": json_data["protocol"],
            "sni": json_data["server_name"],
            "skip-cert-verify": json_data["insecure"],
            "alpn": [json_data["alpn"]],
        }
        merged_proxies.append(proxy)
    except Exception as e:
        logging.error(f"Error processing hysteria data for index {index}: {e}")


# 处理hysteria2（保留原有逻辑）
def process_hysteria2(data, index):
    try:
        json_data = json.loads(data)
        server_ports = json_data["server"]
        server_part, port_part = server_ports.rsplit(":", 1)
        server = server_part.strip('[]')
        ports_slt = port_part.split(",")
        server_port = int(ports_slt[0])
        
        location = get_physical_location(server)
        name = f"{location}_hy2_{index}"

        proxy = {
            "name": name,
            "type": "hysteria2",
            "server": server,
            "port": server_port,
            "password": json_data["auth"],
            "fast-open": True,
            "sni": json_data["tls"]["sni"],
            "skip-cert-verify": json_data["tls"]["insecure"],
        }
        merged_proxies.append(proxy)
    except Exception as e:
        logging.error(f"Error processing hysteria2 data for index {index}: {e}")


def process_xray(data, index):
    try:
        config = json.loads(data)
        for outbound in config.get("outbounds", []):
            if outbound.get("protocol") != "vless":
                continue

            settings = outbound.get("settings", {}).get("vnext", [])
            stream = outbound.get("streamSettings", {})
            security = stream.get("security", "")
            tls_settings = stream.get("tlsSettings", {})
            reality = stream.get("realitySettings", {})
            transport = stream.get("xhttpSettings", {})
            for server_index, server_config in enumerate(settings):
                users = server_config.get("users", [])
                for user_index, user in enumerate(users):
                    server = server_config.get("address", "")
                    proxy = {
                        "name": proxy_name(server, "vless", "xray", index, f"{server_index}_{user_index}"),
                        "type": "vless",
                        "server": server,
                        "port": int(server_config.get("port", 443)),
                        "uuid": user.get("id", ""),
                        "encryption": user.get("encryption", ""),
                        "tls": security in ("tls", "reality"),
                    }
                    if user.get("flow"):
                        proxy["flow"] = user["flow"]
                    servername = reality.get("serverName") or tls_settings.get("serverName")
                    if servername:
                        proxy["servername"] = servername
                    fingerprint = reality.get("fingerprint") or tls_settings.get("fingerprint")
                    if fingerprint:
                        proxy["client-fingerprint"] = fingerprint
                    if security == "reality":
                        proxy["reality-opts"] = {
                            "public-key": reality.get("publicKey", ""),
                            "short-id": reality.get("shortId", ""),
                        }

                    network = stream.get("network", "tcp")
                    if network:
                        proxy["network"] = network
                    if network == "xhttp":
                        xhttp_options = {}
                        if transport.get("path"):
                            xhttp_options["path"] = transport["path"]
                        if transport.get("mode") in ("stream-one", "stream-up", "packet-up"):
                            xhttp_options["mode"] = transport["mode"]
                        if xhttp_options:
                            proxy["xhttp-opts"] = xhttp_options
                    merged_proxies.append(proxy)
    except Exception as e:
        logging.error(f"Error processing Xray data for index {index}: {e}")


def process_sing_box(data, index):
    try:
        config = json.loads(data)
        for outbound_index, outbound in enumerate(config.get("outbounds", [])):
            if outbound.get("type") != "hysteria":
                continue

            tls = outbound.get("tls", {})
            server = outbound.get("server", "")
            proxy = {
                "name": proxy_name(server, "hysteria", "sb", index, outbound_index),
                "type": "hysteria",
                "server": server,
                "port": int(outbound.get("server_port", 443)),
                "up": outbound.get("up_mbps", 1000),
                "down": outbound.get("down_mbps", 1000),
                "auth-str": outbound.get("auth_str", ""),
                "fast-open": True,
            }
            if outbound.get("protocol"):
                proxy["protocol"] = outbound["protocol"]
            if outbound.get("obfs"):
                proxy["obfs"] = outbound["obfs"]
            if tls.get("server_name"):
                proxy["sni"] = tls["server_name"]
            if tls.get("enabled"):
                proxy["tls"] = True
            if tls.get("insecure"):
                proxy["skip-cert-verify"] = True
            if tls.get("alpn"):
                proxy["alpn"] = tls["alpn"]
            merged_proxies.append(proxy)
    except Exception as e:
        logging.error(f"Error processing sing-box data for index {index}: {e}")


def process_mieru(data, index):
    try:
        config = json.loads(data)
        for profile_index, profile in enumerate(config.get("profiles", [])):
            user = profile.get("user", {})
            for server_index, server_config in enumerate(profile.get("servers", [])):
                server = server_config.get("domainName") or server_config.get("ipAddress", "")
                for binding_index, binding in enumerate(server_config.get("portBindings", [])):
                    port = binding.get("port")
                    if not server or not port:
                        continue

                    proxy = {
                        "name": proxy_name(
                            server, "mieru", "mieru", index,
                            f"{profile_index}_{server_index}_{binding_index}",
                        ),
                        "type": "mieru",
                        "server": server,
                        "username": user.get("name", ""),
                        "password": user.get("password", ""),
                        "transport": binding.get("protocol", "TCP"),
                    }
                    if isinstance(port, str) and "-" in port:
                        proxy["port-range"] = port
                    else:
                        proxy["port"] = int(port)
                    for option in ("multiplexing", "handshake-mode", "traffic-pattern"):
                        if profile.get(option):
                            proxy[option] = profile[option]
                    merged_proxies.append(proxy)
    except Exception as e:
        logging.error(f"Error processing Mieru data for index {index}: {e}")


def process_shadowquic(data, index):
    try:
        config = yaml.safe_load(data)
        outbound = config.get("outbound", {}) if isinstance(config, dict) else {}
        if outbound.get("type") != "shadowquic":
            return

        address = urlsplit("//" + outbound.get("addr", ""))
        if not address.hostname or not address.port:
            logging.warning(f"Skipping ShadowQUIC entry {index + 1}: invalid addr")
            return

        server = address.hostname
        proxy = {
            "name": proxy_name(server, "shadowquic", "shadowquic", index),
            "type": "shadowquic",
            "server": server,
            "port": address.port,
            "username": outbound.get("username", ""),
            "password": outbound.get("password", ""),
        }
        fields = {
            "server-name": "sni",
            "alpn": "alpn",
            "congestion-control": "congestion-controller",
            "zero-rtt": "zero-rtt",
            "over-stream": "udp-over-stream",
        }
        for source_key, proxy_key in fields.items():
            if source_key in outbound:
                proxy[proxy_key] = outbound[source_key]
        merged_proxies.append(proxy)
    except Exception as e:
        logging.error(f"Error processing ShadowQUIC data for index {index}: {e}")


def process_naiveproxy(data, index):
    try:
        json.loads(data)
        logging.warning(
            "Skipping NaiveProxy entry %s: Mihomo has no native NaiveProxy outbound type",
            index + 1,
        )
    except Exception as e:
        logging.error(f"Error processing NaiveProxy data for index {index}: {e}")

# 新增：处理vless/vmess/tuic/ssr的独立解析函数（若有独立URL文件）
def process_vless(data, index):
    try:
        json_data = json.loads(data)
        server = json_data.get("server", "").strip('[]')
        port = int(json_data.get("port", 443))
        location = get_physical_location(server)
        name = f"{location}_vless_{index}"
        
        proxy = {
            "name": name,
            "type": "vless",
            "server": server,
            "port": port,
            "uuid": json_data.get("uuid", ""),
            "network": json_data.get("network", "tcp"),
            "tls": json_data.get("tls", 1),
            "servername": json_data.get("sni", ""),
            "skip-cert-verify": json_data.get("insecure", False),
            "client-fingerprint": json_data.get("fp", "chrome"),
            "reality-opts": {
                "public-key": json_data.get("publicKey", ""),
                "short-id": json_data.get("shortId", "")
            },
            "ws-opts": {
                "path": json_data.get("ws_path", ""),
                "headers": {"Host": json_data.get("ws_host", "")}
            }
        }
        merged_proxies.append(proxy)
    except Exception as e:
        logging.error(f"Error processing vless data for index {index}: {e}")

def update_proxy_groups(config_data, merged_proxies):
    auto_group = None
    select_group = None
    
    # 查找自动选择和节点选择组
    for group in config_data["proxy-groups"]:
        if group["name"] == "自动选择":
            auto_group = group
        elif group["name"] == "节点选择":
            select_group = group

    # 确保自动选择组存在且包含所有节点
    if auto_group:
        auto_group["proxies"] = [proxy["name"] for proxy in merged_proxies]
    else:
        auto_group = {
            "name": "自动选择",
            "type": "url-test",
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 50,
            "proxies": [proxy["name"] for proxy in merged_proxies]
        }
        config_data["proxy-groups"].append(auto_group)

    # 确保节点选择组包含自动选择+所有节点
    if select_group:
        # 先添加自动选择，再添加去重后的节点（排除自动选择自身）
        select_proxies = ["自动选择"] + list(
            {proxy["name"] for proxy in merged_proxies}
        )
        select_group["proxies"] = select_proxies
    else:
        select_group = {
            "name": "节点选择",
            "type": "select",
            "proxies": ["自动选择"] + [proxy["name"] for proxy in merged_proxies]
        }
        config_data["proxy-groups"].insert(0, select_group)  # 确保在最前

    # 移除可能的重复项
    seen = set()
    select_group["proxies"] = [
        x for x in select_group["proxies"] 
        if not (x in seen or seen.add(x))
    ]

# 去重函数：移除除名称外所有属性相同的节点
def remove_duplicate_proxies(proxies):
    seen = set()
    unique_proxies = []
    
    for proxy in proxies:
        signature = json.dumps(
            {key: value for key, value in proxy.items() if key != "name"},
            sort_keys=True,
            ensure_ascii=False,
        )
        if signature not in seen:
            seen.add(signature)
            unique_proxies.append(proxy)
        else:
            logging.debug(f"跳过重复代理: {proxy.get('name', '未知名称')}")
    
    logging.info(f"代理去重完成：原始{len(proxies)}个 → 去重后{len(unique_proxies)}个")
    return unique_proxies


def make_proxy_names_unique(proxies):
    seen = set()
    for proxy in proxies:
        name = proxy["name"]
        if name not in seen:
            seen.add(name)
            continue
        suffix = 2
        while f"{name}_{suffix}" in seen:
            suffix += 1
        proxy["name"] = f"{name}_{suffix}"
        seen.add(proxy["name"])


def main():
    global merged_proxies
    merged_proxies = []

    sources = (
        ("./urls/clash_urls.txt", process_clash),
        ("./urls/hysteria_urls.txt", process_hysteria),
        ("./urls/hysteria2_urls.txt", process_hysteria2),
        ("./urls/xray_urls.txt", process_xray),
        ("./urls/sb_urls.txt", process_sing_box),
        ("./urls/naiveproxy_urls.txt", process_naiveproxy),
        ("./urls/mieru_urls.txt", process_mieru),
        ("./urls/shadowquic_urls.txt", process_shadowquic),
    )
    for url_file, processor in sources:
        process_urls(url_file, processor)

    merged_proxies = remove_duplicate_proxies(merged_proxies)
    make_proxy_names_unique(merged_proxies)

    with open("./templates/clash_template.yaml", "r", encoding="utf-8") as file:
        config_data = yaml.safe_load(file)

    config_data["proxies"] = merged_proxies
    update_proxy_groups(config_data, merged_proxies)

    with open("./sub/merged_proxies_new.yaml", "w", encoding="utf-8") as file:
        yaml.dump(config_data, file, sort_keys=False, allow_unicode=True)

    print(f"聚合完成，保留 {len(merged_proxies)} 个节点（已去重）")


merged_proxies = []

if __name__ == "__main__":
    main()