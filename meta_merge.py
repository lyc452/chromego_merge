import yaml
import json
import urllib.request
import logging
import geoip2.database
import socket
import re


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


# 提取clash节点（添加类型过滤）
def process_clash(data, index):
    content = yaml.safe_load(data)
    proxies = content.get("proxies", [])
    for i, proxy in enumerate(proxies):
        # 仅保留hysteria和hysteria2类型
        if proxy.get("type") not in ["hysteria", "hysteria2"]:
            continue
        location = get_physical_location(proxy["server"])
        proxy["name"] = f"{location}_{proxy['type']}_{index}{i+1}"
    merged_proxies.extend(proxies)


def get_physical_location(address):
    address = re.sub(":.*", "", address)
    try:
        ip_address = socket.gethostbyname(address)
    except socket.gaierror:
        ip_address = address

    try:
        reader = geoip2.database.Reader("GeoLite2-City.mmdb")
        response = reader.city(ip_address)
        country = response.country.name
        city = response.city.name
        return f"{country}_{city}"
    except geoip2.errors.AddressNotFoundError as e:
        print(f"Error: {e}")
        return "Unknown"


# 处理hysteria
def process_hysteria(data, index):
    try:
        json_data = json.loads(data)
        server_ports = json_data["server"]
        server_ports_slt = server_ports.split(":")
        server = server_ports_slt[0]
        ports = server_ports_slt[1]
        ports_slt = ports.split(",")
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


# 处理hysteria2
def process_hysteria2(data, index):
    try:
        json_data = json.loads(data)
        server_ports = json_data["server"]
        server_ports_slt = server_ports.split(":")
        server = server_ports_slt[0]
        ports = server_ports_slt[1]
        ports_slt = ports.split(",")
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


def update_proxy_groups(config_data, merged_proxies):
    for group in config_data["proxy-groups"]:
        if group["name"] in ["自动选择", "节点选择"]:
            group["proxies"] = [proxy["name"] for proxy in merged_proxies]


merged_proxies = []

# 处理 clash URLs（已添加类型过滤）
process_urls("./urls/clash_urls.txt", process_clash)

# 处理 hysteria URLs
process_urls("./urls/hysteria_urls.txt", process_hysteria)

# 处理 hysteria2 URLs
process_urls("./urls/hysteria2_urls.txt", process_hysteria2)

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

print("聚合完成，仅保留hysteria和hysteria2节点")
