import json
from typing import Any, Dict, Optional
from python_v2ray.profile_parser import ProxyProfile


class XrayConfigBuilder:
    def __init__(self):
        self.config: Dict[str, Any] = {
            "log": {"loglevel": "warning"},
            "stats": {},
            "policy": {
                "system": {
                    "statsInboundUplink": True,
                    "statsInboundDownlink": True,
                    "statsOutboundUplink": True,
                    "statsOutboundDownlink": True,
                },
                "levels": {"0": {"statsuserUplink": True, "statsuserDownlink": True}},
            },
            "inbounds": [],
            "outbounds": [],
            "routing": {"rules": []},
        }
        # self.warp_outbound_tag: Optional[str] = None

    def add_inbound(self, inbound_config: Dict[str, Any]):
        self.config["inbounds"].append(inbound_config)
        return self

    def add_outbound(self, outbound_config: Dict[str, Any]):
        self.config["outbounds"].append(outbound_config)
        return self

    def build_outbound_from_params(
        self, params: ProxyProfile, explicit_tag: Optional[str] = None, **kwargs
    ) -> Optional[Dict[str, Any]]:
        protocol_map = {
            "vless": "vless",
            "mvless": "vless",
            "vmess": "vmess",
            "trojan": "trojan",
            "ss": "shadowsocks",
            "socks": "socks",
            "wireguard": "wireguard",
        }
        xray_protocol_name = protocol_map.get(params.protocol)
        if not xray_protocol_name:
            return None
        stream_settings = self._build_stream_settings(params, **kwargs)
        protocol_settings = self._build_protocol_settings(params)
        final_outbound_tag = explicit_tag if explicit_tag is not None else params.tag
        outbound = {
            "tag": final_outbound_tag,
            "protocol": xray_protocol_name,
            "settings": protocol_settings,
            "streamSettings": stream_settings,
        }
        if params.protocol == "mvless" and params.mux_enabled:
            outbound["mux"] = {"enabled": True, "concurrency": params.mux_concurrency}
        # if self.warp_outbound_tag and params.tag != self.warp_outbound_tag:
        #     outbound.setdefault("streamSettings", {}).setdefault("sockopt", {})[
        #         "dialerProxy"
        #     ] = self.warp_outbound_tag
        return self._remove_empty_values(outbound)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.config, indent=indent, ensure_ascii=False)

    def _build_stream_settings(self, params: ProxyProfile, **kwargs) -> Dict[str, Any]:
        stream_settings: Dict[str, Any] = {"network": params.network}
        if params.security in ["tls", "reality"]:
            stream_settings["security"] = params.security
            security_settings = {
                "allowInsecure": kwargs.get("allow_insecure", False),
                "serverName": params.sni,
                "fingerprint": params.fp,
            }
            if params.alpn:
                security_settings["alpn"] = [
                    val.strip() for val in params.alpn.split(",")
                ]
            if params.security == "reality":
                security_settings.update(
                    {
                        "publicKey": params.pbk,
                        "shortId": params.sid,
                        "spiderX": params.spx,
                    }
                )
                stream_settings["realitySettings"] = security_settings
            else:
                stream_settings["tlsSettings"] = security_settings
        host_for_header = params.host or params.sni
        network_settings = {}
        if params.network == "tcp":
            valid_header_types = [
                "srtp",
                "utp",
                "wechat-video",
                "dtls",
                "wireguard",
                "http",
            ]
            if params.header_type in valid_header_types:
                network_settings = {
                    "tcpSettings": {"header": {"type": params.header_type}}
                }
        elif params.network == "ws":
            ws_path = params.path if params.path else "/"
            network_settings = {
                "wsSettings": {"path": ws_path, "headers": {"Host": host_for_header}}
            }
        elif params.network == "kcp":
            network_settings = {
                "kcpSettings": {
                    "header": {"type": params.header_type},
                    "seed": params.path,
                }
            }
        elif params.network == "h2":
            network_settings = {
                "httpSettings": {"host": [host_for_header], "path": params.path}
            }
        elif params.network == "quic":
            network_settings = {
                "quicSettings": {
                    "security": params.host,
                    "key": params.path,
                    "header": {"type": params.header_type},
                }
            }
        elif params.network == "grpc":
            network_settings = {
                "grpcSettings": {
                    "serviceName": params.path,
                    "multiMode": (params.mode == "multi"),
                }
            }
        elif params.network == "xhttp":
            network_settings = {
                "xhttpSettings": {
                    "host": host_for_header,
                    "path": params.path,
                }
            }
        stream_settings.update(network_settings)
        return stream_settings

    def _build_protocol_settings(self, params: ProxyProfile) -> Dict[str, Any]:
        level = 0
        protocol = params.protocol
        if protocol in ["vless", "mvless"]:
            return {
                "vnext": [
                    {
                        "address": params.address,
                        "port": params.port,
                        "users": [
                            {
                                "id": params.id,
                                "flow": params.flow,
                                "encryption": "none",
                                "level": level,
                            }
                        ],
                    }
                ]
            }
        elif protocol == "vmess":
            return {
                "vnext": [
                    {
                        "address": params.address,
                        "port": params.port,
                        "users": [
                            {
                                "id": params.id,
                                "alterId": params.alter_id,
                                "security": params.scy,
                                "level": level,
                            }
                        ],
                    }
                ]
            }
        elif protocol == "trojan":
            return {
                "servers": [
                    {
                        "address": params.address,
                        "port": params.port,
                        "password": params.password,
                        "level": level,
                    }
                ]
            }
        elif protocol == "ss":
            return {
                "servers": [
                    {
                        "address": params.address,
                        "port": params.port,
                        "password": params.password,
                        "method": params.ss_method,
                        "level": level,
                    }
                ]
            }
        elif protocol == "wireguard":
            reserved = (
                [int(i.strip()) for i in params.wg_reserved.split(",")]
                if params.wg_reserved
                else []
            )
            return {
                "secretKey": params.wg_secret_key,
                "address": params.wg_address.split(",") if params.wg_address else [],
                "peers": [
                    {
                        "publicKey": params.pbk,
                        "endpoint": f"{params.address}:{params.port}",
                    }
                ],
                "mtu": params.wg_mtu,
                "reserved": reserved,
            }
        elif protocol == "socks":
            server = {"address": params.address, "port": params.port, "level": level}
            if params.id:
                server["users"] = [{"user": params.id, "pass": params.password or ""}]
            return {"servers": [server]}
        return {}

    def _remove_empty_values(self, data: Any) -> Any:
        if isinstance(data, dict):
            return {
                k: v
                for k, v in ((k, self._remove_empty_values(v)) for k, v in data.items())
                if v is not None and v not in ["", [], {}]
            }
        if isinstance(data, list):
            return [
                v
                for v in (self._remove_empty_values(item) for item in data)
                if v is not None and v not in ["", [], {}]
            ]
        return data
