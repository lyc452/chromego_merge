import yaml
import json
import urllib.request
import logging
import geoip2.database
import socket
import re
from collections import OrderedDict

# 提取节点
def process_urls(url_file, processor):
    try:
        with open(url_file, "r") as file:
            urls = file.read().splitlines()

        for index, url in enumerate(urls):
            try:
                response = urllib.request.urlopen(url)
                data = response.read().decode("utf-8")
                processor(data, index)
            except Exception as e:
                logging.error(f"Error processing URL {url}: {e}")
    except Exception as e:
        logging.error(f"Error reading file {url_file}: {e}")


# 提取clash节点（扩展协议支持）
def process_clash(data, index):
    content = yaml.safe_load(data)
    proxies = content.get("proxies", [])
    
    filtered_proxies = []
    # 扩展支持的协议类型：hysteria/hysteria2/vless/vmess/tuic/ssr
    SUPPORTED_TYPES = ["hysteria", "hysteria2", "vless", "vmess", "tuic", "ssr"]
    for proxy in proxies:
        proxy_type = proxy.get("type")
        if proxy_type not in SUPPORTED_TYPES:
            continue
        
        # 处理地理位置和重命名
        server = proxy.get("server", "")
        location = get_physical_location(server)
        proxy["name"] = f"{location}_{proxy_type}_{index}_{len(filtered_proxies)+1}"
        filtered_proxies.append(proxy)
    
    merged_proxies.extend(filtered_proxies)  # 仅添加过滤后的代理


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
    # 创建签名字典，键为属性元组，值为节点对象
    signature_map = OrderedDict()
    
    for proxy in proxies:
        # 创建属性的签名元组（排除名称字段）
        signature = tuple(sorted([
            (k, tuple(v) if isinstance(v, list) else v)  # 处理列表类型
            for k, v in proxy.items() 
            if k != "name"  # 排除名称字段
        ]))
        
        # 如果签名不存在，添加节点到结果
        if signature not in signature_map:
            signature_map[signature] = proxy
    
    # 返回去重后的节点列表（保留第一个出现的节点）
    return list(signature_map.values())


merged_proxies = []

# 处理 clash URLs（已扩展协议过滤）
process_urls("./urls/clash_urls.txt", process_clash)

# 处理 hysteria URLs
process_urls("./urls/hysteria_urls.txt", process_hysteria)

# 处理 hysteria2 URLs
process_urls("./urls/hysteria2_urls.txt", process_hysteria2)

# 新增：若有独立的vless/vmess/tuic/ssr URL文件，补充处理
# process_urls("./urls/vless_urls.txt", process_vless)
# process_urls("./urls/vmess_urls.txt", process_vmess)
# process_urls("./urls/tuic_urls.txt", process_tuic)
# process_urls("./urls/ssr_urls.txt", process_ssr)

# 去重处理：移除除名称外所有属性相同的节点
merged_proxies = remove_duplicate_proxies(merged_proxies)

# 读取模板
with open("./templates/clash_template.yaml", "r", encoding="utf-8") as file:
    config_data = yaml.safe_load(file)

# 添加过滤后的代理
config_data["proxies"] = merged_proxies

# 更新代理组
update_proxy_groups(config_data, merged_proxies)

# 写入文件
with open("./sub/merged_proxies_new.yaml", "w", encoding="utf-8") as file:
    yaml.dump(config_data, file, sort_keys=False, allow_unicode=True)

print(f"聚合完成，保留 {len(merged_proxies)} 个节点（已去重）")