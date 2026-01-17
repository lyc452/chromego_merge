import base64
import json
import urllib.request
import yaml
import codecs
import logging
import geoip2.database
import socket
import re
from collections import OrderedDict

# 初始化全局列表
merged_proxies = []

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


def get_physical_location(address):
    address = re.sub(r':\d+$', '', address)
    try:
        ip_address = socket.gethostbyname(address)
    except socket.gaierror:
        ip_address = address

    try:
        reader = geoip2.database.Reader(
            "GeoLite2-City.mmdb"
        )
        response = reader.city(ip_address)
        country = response.country.name
        return f"{country}"
    except geoip2.errors.AddressNotFoundError as e:
        print(f"Error: {e}")
        return "Unknown"
    except Exception as e:
        logging.error(f"Error getting location for {address}: {e}")
        return "Unknown"


# 提取clash节点（恢复所有协议）
def process_clash(data, index):
    # 解析YAML格式的内容
    content = yaml.safe_load(data)

    # 提取proxies部分并合并到merged_proxies中
    proxies = content.get("proxies", [])
    
    # 处理hysteria2节点
    for proxy in proxies:
        if proxy["type"] == "hysteria2":
            server = proxy.get("server", "")
            port = int(proxy.get("port", 443))
            auth = proxy.get("password", "")
            obfs = proxy.get("obfs", "")
            obfs_password = proxy.get("obfs-password", "")
            sni = proxy.get("sni", "")
            insecure = int(proxy.get("skip-cert-verify", 0))
            location = get_physical_location(server)
            name = f"{location}_hy2_{index}"
            hy2_meta = f"hysteria2://{auth}@{server}:{port}?insecure={insecure}&sni={sni}&obfs={obfs}&obfs-password={obfs_password}#{name}"
            merged_proxies.append(hy2_meta)

        # 处理hysteria节点
        elif proxy["type"] == "hysteria":
            server = proxy.get("server", "")
            port = int(proxy.get("port", 443))
            ports = proxy.get("port", "")
            protocol = proxy.get("protocol", "udp")
            up_mbps = 50
            down_mbps = 80
            alpn = (
                proxy.get("alpn", [])[0]
                if proxy.get("alpn") and len(proxy["alpn"]) > 0
                else None
            )
            obfs = proxy.get("obfs", "")
            insecure = int(proxy.get("skip-cert-verify", 0))
            sni = proxy.get("sni", "")
            fast_open = int(proxy.get("fast_open", 1))
            auth = proxy.get("auth-str", "")
            # 生成URL
            location = get_physical_location(server)
            name = f"{location}_hy_{index}"
            hysteria_meta = f"hysteria://{server}:{port}?peer={sni}&auth={auth}&insecure={insecure}&upmbps={up_mbps}&downmbps={down_mbps}&alpn={alpn}&mport={ports}&obfs={obfs}&protocol={protocol}&fastopen={fast_open}#{name}"
            merged_proxies.append(hysteria_meta)

        # 恢复vless节点解析
        elif proxy["type"] == "vless":
            server = proxy.get("server", "")
            port = int(proxy.get("port", 443))
            udp = proxy.get("udp", "")
            uuid = proxy.get("uuid", "")
            network = proxy.get("network", "")
            tls = int(proxy.get("tls", 0))
            xudp = proxy.get("xudp", "")
            sni = proxy.get("servername", "")
            flow = proxy.get("flow", "")
            publicKey = proxy.get("reality-opts", {}).get("public-key", "")
            short_id = proxy.get("reality-opts", {}).get("short-id", "")
            fp = proxy.get("client-fingerprint", "")
            insecure = int(proxy.get("skip-cert-verify", 0))
            grpc_serviceName = proxy.get("grpc-opts", {}).get("grpc-service-name", "")

            ws_path = proxy.get("ws-opts", {}).get("path", "")
            ws_headers_host = (
                proxy.get("ws-opts", {}).get("headers", {}).get("Host", "")
            )
            if tls == 0:
                security = "none"
            elif tls == 1 and publicKey != "":
                security = "reality"
            else:
                security = "tls"
            location = get_physical_location(server)
            name = f"{location}_vless_{index}"
            # 修复原语法错误：allowInsecure→allowInsecure={insecure}
            vless_meta = f"vless://{uuid}@{server}:{port}?security={security}&allowInsecure={insecure}&flow={flow}&type={network}&fp={fp}&pbk={publicKey}&sid={short_id}&sni={sni}&serviceName={grpc_serviceName}&path={ws_path}&host={ws_headers_host}#{name}"
            merged_proxies.append(vless_meta)

        # 恢复vmess节点解析
        elif proxy["type"] == "vmess":
            server = proxy.get("server", "")
            port = int(proxy.get("port", 443))
            uuid = proxy.get("uuid", "")
            alterId = proxy.get("alterId", "")
            network = proxy.get("network", "")
            tls = int(proxy.get("tls", 0))
            fp = proxy.get("client-fingerprint", "chrome")  # 补充默认值
            insecure = int(proxy.get("skip-cert-verify", 0))  # 补充缺失的变量
            if tls == 0:
                security = "none"
            elif tls == 1:
                security = "tls"
            sni = proxy.get("servername", "")
            ws_path = proxy.get("ws-opts", {}).get("path", "")
            ws_headers_host = (
                proxy.get("ws-opts", {}).get("headers", {}).get("Host", "")
            )
            location = get_physical_location(server)
            name = f"{location}_vmess_{index}"
            # 修复vmess链接格式（标准vmess为JSON Base64编码）
            vmess_dict = {
                "v": "2",
                "ps": name,
                "add": server,
                "port": str(port),
                "id": uuid,
                "aid": alterId,
                "scy": "auto",
                "net": network,
                "type": "none",
                "host": ws_headers_host,
                "path": ws_path,
                "tls": "tls" if tls == 1 else "",
                "sni": sni,
                "fp": fp,
                "alpn": "",
                "skip-cert-verify": insecure == 1
            }
            vmess_json = json.dumps(vmess_dict, ensure_ascii=False)
            vmess_meta = f"vmess://{base64.b64encode(vmess_json.encode()).decode()}"
            merged_proxies.append(vmess_meta)

        # 恢复tuic节点解析
        elif proxy["type"] == "tuic":
            server = proxy.get("server", "")
            port = int(proxy.get("port", 443))
            uuid = proxy.get("uuid", "")
            password = proxy.get("password", "")
            sni = proxy.get("sni", "")
            insecure = int(proxy.get("skip-cert-verify", 0))
            udp_relay_mode = proxy.get("udp-relay-mode", "naive")
            congestion = proxy.get("congestion-controller", "bbr")
            alpn = (
                proxy.get("alpn", [])[0]
                if proxy.get("alpn") and len(proxy["alpn"]) > 0
                else None
            )
            location = get_physical_location(server)
            name = f"{location}_tuic_{index}"
            tuic_meta = f"tuic://{uuid}:{password}@{server}:{port}?sni={sni}&congestion_control={congestion}&udp_relay_mode={udp_relay_mode}&alpn={alpn}&allow_insecure={insecure}#{name}"
            merged_proxies.append(tuic_meta)

        # 恢复ssr节点解析
        elif proxy["type"] == "ssr":
            server = proxy.get("server", "")
            port = int(proxy.get("port", 443))
            password = proxy.get("password", "")
            password = base64.b64encode(password.encode()).decode()
            cipher = proxy.get("cipher", "")
            obfs = proxy.get("obfs", "")
            protocol = proxy.get("protocol", "")
            protocol_param = proxy.get("protocol-param", "")
            protocol_param = base64.b64encode(protocol_param.encode()).decode()
            obfs_param = proxy.get("obfs-param", "")
            obfs_param = base64.b64encode(obfs_param.encode()).decode()
            # 生成URL
            ssr_source = f"{server}:{port}:{protocol}:{cipher}:{obfs}:{password}/?obfsparam={obfs_param}&protoparam={protocol_param}&remarks={base64.b64encode(name.encode()).decode()}&protoparam={protocol_param}&obfsparam={obfs_param}"
            ssr_source = base64.b64encode(ssr_source.encode()).decode()
            ssr_meta = f"ssr://{ssr_source}"
            merged_proxies.append(ssr_meta)

# 执行节点处理
process_urls("./urls/clash_urls.txt", process_clash)

# 去重（基于链接内容）
merged_proxies = list(OrderedDict.fromkeys(merged_proxies))

# 生成Base64订阅文件
with open("./sub/base64.txt", "w", encoding="utf-8") as f:
    # 合并所有节点并编码为Base64
    all_proxies = "\n".join(merged_proxies)
    base64_data = base64.b64encode(all_proxies.encode()).decode()
    f.write(base64_data)

print(f"Base64订阅生成完成，共 {len(merged_proxies)} 个节点（已去重）")