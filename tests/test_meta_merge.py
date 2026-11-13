import unittest
import urllib.error
from unittest.mock import MagicMock, patch

import meta_merge


class MetaMergeTests(unittest.TestCase):
    def setUp(self):
        meta_merge.merged_proxies = []

    @patch("meta_merge.time.sleep")
    @patch("meta_merge.urllib.request.urlopen")
    def test_subscription_fetch_retries_transient_network_errors(self, urlopen, _):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b'{"ok": true}'
        urlopen.side_effect = [urllib.error.URLError("temporary TLS error"), response]

        data = meta_merge.fetch_subscription("https://example.test/subscription")

        self.assertEqual(data, '{"ok": true}')
        self.assertEqual(urlopen.call_count, 2)

    @patch("meta_merge.time.sleep")
    @patch("meta_merge.urllib.request.urlopen")
    def test_subscription_fetch_does_not_retry_client_errors(self, urlopen, sleep):
        urlopen.side_effect = urllib.error.HTTPError(
            "https://example.test/subscription", 404, "Not Found", None, None
        )

        with self.assertRaises(urllib.error.HTTPError):
            meta_merge.fetch_subscription("https://example.test/subscription")

        self.assertEqual(urlopen.call_count, 1)
        sleep.assert_not_called()

    @patch("meta_merge.get_physical_location", return_value="Test")
    def test_xray_vless_xhttp_reality_is_converted(self, _):
        data = """{
          "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{
              "address": "node.example",
              "port": 443,
              "users": [{"id": "test-id", "encryption": "none"}]
            }]},
            "streamSettings": {
              "network": "xhttp",
              "security": "reality",
              "realitySettings": {
                "serverName": "sni.example",
                "fingerprint": "chrome",
                "publicKey": "public-key",
                "shortId": "short-id"
              },
              "xhttpSettings": {"path": "/path", "mode": "auto"}
            }
          }]
        }"""

        meta_merge.process_xray(data, 0)

        proxy = meta_merge.merged_proxies[0]
        self.assertEqual(proxy["type"], "vless")
        self.assertEqual(proxy["network"], "xhttp")
        self.assertTrue(proxy["tls"])
        self.assertEqual(proxy["servername"], "sni.example")
        self.assertEqual(proxy["reality-opts"]["public-key"], "public-key")
        self.assertEqual(proxy["xhttp-opts"], {"path": "/path"})

    @patch("meta_merge.get_physical_location", return_value="Test")
    def test_sing_box_hysteria_outbound_is_converted(self, _):
        data = """{
          "outbounds": [{
            "type": "hysteria",
            "tag": "node",
            "server": "node.example",
            "server_port": 8443,
            "up_mbps": 20,
            "down_mbps": 50,
            "auth_str": "auth",
            "tls": {
              "enabled": true,
              "insecure": true,
              "server_name": "sni.example",
              "alpn": ["h3"]
            }
          }]
        }"""

        meta_merge.process_sing_box(data, 0)

        proxy = meta_merge.merged_proxies[0]
        self.assertEqual(proxy["type"], "hysteria")
        self.assertEqual(proxy["port"], 8443)
        self.assertEqual(proxy["auth-str"], "auth")
        self.assertEqual(proxy["sni"], "sni.example")
        self.assertTrue(proxy["skip-cert-verify"])
        self.assertEqual(proxy["alpn"], ["h3"])

    @patch("meta_merge.get_physical_location", return_value="Test")
    def test_mieru_profile_port_range_is_converted(self, _):
        data = """{
          "profiles": [{
            "profileName": "test",
            "user": {"name": "user", "password": "pass"},
            "servers": [{
              "domainName": "node.example",
              "portBindings": [{"port": "3000-3010", "protocol": "TCP"}]
            }]
          }]
        }"""

        meta_merge.process_mieru(data, 0)

        proxy = meta_merge.merged_proxies[0]
        self.assertEqual(proxy["type"], "mieru")
        self.assertEqual(proxy["port-range"], "3000-3010")
        self.assertNotIn("port", proxy)
        self.assertEqual(proxy["username"], "user")

    @patch("meta_merge.get_physical_location", return_value="Test")
    def test_shadowquic_config_is_converted(self, _):
        data = """inbound:
  type: socks
outbound:
  type: shadowquic
  addr: "[2001:db8::1]:443"
  username: user
  password: pass
  server-name: sni.example
  alpn:
    - h3
  zero-rtt: true
"""

        meta_merge.process_shadowquic(data, 0)

        proxy = meta_merge.merged_proxies[0]
        self.assertEqual(proxy["type"], "shadowquic")
        self.assertEqual(proxy["server"], "2001:db8::1")
        self.assertEqual(proxy["port"], 443)
        self.assertEqual(proxy["sni"], "sni.example")
        self.assertTrue(proxy["zero-rtt"])

    def test_naiveproxy_is_skipped_with_explanation(self):
        with self.assertLogs("root", level="WARNING") as logs:
            meta_merge.process_naiveproxy('{"listen":"socks://127.0.0.1:1080"}', 0)

        self.assertEqual(meta_merge.merged_proxies, [])
        self.assertIn("no native NaiveProxy", logs.output[0])

    def test_deduplication_preserves_distinct_proxy_options(self):
        proxies = [
            {"name": "first", "type": "mieru", "server": "node.example", "port-range": "1000-1005"},
            {"name": "duplicate", "type": "mieru", "server": "node.example", "port-range": "1000-1005"},
            {"name": "different", "type": "mieru", "server": "node.example", "port-range": "2000-2005"},
        ]

        result = meta_merge.remove_duplicate_proxies(proxies)

        self.assertEqual([proxy["name"] for proxy in result], ["first", "different"])


if __name__ == "__main__":
    unittest.main()
