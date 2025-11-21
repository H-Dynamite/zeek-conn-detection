

module ConnDetection;

type Idx: record {
	src_ip: subnet;
	dst_ip: subnet;
	src_port: int;
	dst_port: int;
	proto: string;
    id: string;
};

type Val: record {
	action: bool;
};


# This assignment should pass type-checking.
global flow_table: table[subnet, subnet,int,int,string,string] of bool  = {
    # [192.168.145.16, 192.168.40.38] = F,
};

global exclude_flow_table : set[addr] = {
    0.0.0.0,
    255.255.255.255,
    1.1.1.1,
    127.0.0.1,
    [::],
    [::1],
    [0000:0000:0000:0000:0000:0000:0000:0000],
    [FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]
};

# global servers: table[int, string] of Val = table();

export {
    redef enum Notice::Type += {
        AbnormalConnection,
    };
    const multicast_address_range: set[subnet] = set(224.0.0.0/4, [ff00::]/8, 255.255.255.255/32) &redef;
    option default_capture_abnormal_connection: bool = F;
    redef Config::config_files += {"/opt/zeek/share/zeek/site/custom/config.dat"};
}

# 检查连接是否匹配任何规则
function check_connection_against_rules(src_ip: addr,dst_ip:addr,src_port:int,dst_port:int,proto:string): bool
{
    # local src_ip = c$id$orig_h;
    # local dst_ip = c$id$resp_h;
    # local src_port = c$id$orig_p;
    # local dst_port = c$id$resp_p;
    # local proto = (c$conn$proto == tcp) ? "tcp" : "udp";
    
    print fmt("check: %s:%s -> %s:%s (%s)", 
             src_ip, src_port, dst_ip, dst_port, proto);
    
    # 遍历所有规则检查匹配
    for ([rule_src, rule_dst, rule_sport, rule_dport, rule_proto,rule_id] in flow_table)
    {
        # 检查协议
        if (rule_proto != "any" && rule_proto != proto)
            next;
        
        # 检查源IP
        if (rule_src != 0.0.0.0/0 && src_ip !in rule_src )
            next;
        
        # 检查目标IP
        if (rule_dst != 0.0.0.0/0 && dst_ip !in rule_dst)
            next;
        
        # 检查源端口（支持任意端口 0/tcp）
        if (rule_sport != 0 && src_port != rule_sport)
            next;
        
        # 检查目标端口（支持任意端口 0/tcp）
        if (rule_dport != 0 && dst_port != rule_dport)
            next;
        
        # local result = flow_table[rule_src, rule_dst, rule_sport, rule_dport, rule_proto,rule_id];
        # print fmt("pass rule :%s   %s -> %s : %s > %s (%s) = %s", 
        #         rule_id, rule_src, rule_dst, rule_sport, rule_dport, rule_proto, result);
        
        return T;
    }
    
    return F;  # 默认拒绝
}

event line(description: Input::TableDescription, tpe: Input::Event, left: Idx, right: bool)
{
    # Reporter::info(fmt ("line : %s, value: %s", left$src_ip , left$dst_ip));
}

event zeek_init()
{
 	Input::add_table([$source="/opt/zeek/share/zeek/site/custom/flow_table.txt", $name="flow_table", $idx=Idx, $ev=line, $val=Val, $destination=flow_table, $want_record=F,$mode=Input::REREAD]);
}

event new_connection(c: connection)
{

    if(!default_capture_abnormal_connection){
         return;
    }
    local src_ip = c$id$orig_h ;
    local dst_ip = c$id$resp_h ;

    local dp = port_to_count(c$id$resp_p);
    local sp = port_to_count(c$id$orig_p);

    local proto =  to_lower(cat(c$conn$proto)); 
   
    local proto2 =  get_conn_transport_proto(c$id);
 
    Reporter::info(fmt ("new_connection : %s, value: %s", proto , proto2));

    # 排除组播
    if (src_ip in multicast_address_range || dst_ip in multicast_address_range) 
        return;

    # 不认为是资产ip
    if(src_ip in exclude_flow_table  || dst_ip in  exclude_flow_table){
        return;
    }

	if(!check_connection_against_rules(src_ip,dst_ip,sp,dp,proto)){
		NOTICE([$note=ConnDetection::AbnormalConnection,
				$msg=fmt("异常会话，请关注"),
				$conn=c, $suppress_for=1min,
                $identifier=cat(c$id$orig_h, c$id$resp_h, c$id$resp_p)
		    ]);
	}
}