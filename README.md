Zeek WhiteList Anomaly Detection

一个为 Zeek 网络安全监控框架设计的高性能白名单异常检测插件，能够有效识别未知威胁与可疑网络活动

# ✨ 核心特性
1. 五元组支持：基于源/目IP、源/目端口和协议进行精确匹配。
2. 灵活过滤：通过直观的配置文件轻松管理白名单规则。
3. 运行时控制：支持动态启用/禁用检测功能，无需重启 Zeek。
4. 高性能：原生集成于 Zeek 框架，提供高效的流量检测。
5. 易于集成：输出标准 Zeek 日志



在 local.zeek 中加载插件：

zeek
@load ./zeek-conn-detection

# 基本配置
编辑配置文件 whitelist.rules：

```
#fields	src_ip	dst_ip	src_port	dst_port	proto	action	id
#types	subnet	subnet	port	port	string	bool	string
192.168.15.16/32	192.168.15.90/32	0	22	any	T	9415
10.0.0.0/24	0.0.0.0/0	443	0	tcp	T	web-outbound
0.0.0.0/0	192.168.1.100/32	0	53	udp	T	dns-server
```


配置说明：

1. IP地址：使用 CIDR 格式 (192.168.1.0/24)
2. 端口：0 表示匹配任何端口
3. 协议：tcp, udp 或 any
4. 动作：T (允许) 或 F (拒绝/告警)  暂时不支持

ID：规则的唯一标识符，用于跟踪和调试

# 扩展开发
如需添加新协议或匹配逻辑，请参考 main.zeek



