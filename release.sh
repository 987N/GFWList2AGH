#!/bin/bash

# Current Version: 1.2.9

## How to get and use?
# git clone "https://github.com/hezhijie0327/GFWList2AGH.git" && bash ./GFWList2AGH/release.sh

## Function
# Get Data
function GetData() {
    cnacc_domain=(
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt"
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/apple-cn.txt"
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/GoogleFCM/GoogleFCM.list"
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/GovCN/GovCN.list"
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/China/China.list"
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/ChinaMaxNoIP/ChinaMaxNoIP.list"
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/DouYin/DouYin.list"
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Tencent/Tencent.list"
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/UnionPay/UnionPay.list"
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/XiaoHongShu/XiaoHongShu.list"
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/ChinaUnicom/ChinaUnicom.list"
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/ChinaMobile/ChinaMobile.list"
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/ChinaTelecom/ChinaTelecom.list"
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/ChinaNoMedia/ChinaNoMedia.list"
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/JingDong/JingDong.list"
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/BiliBili/BiliBili.list"
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Pinduoduo/Pinduoduo.list"
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/XiaoMi/XiaoMi.list"
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/NetEase/NetEase.list"
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/NetEaseMusic/NetEaseMusic.list"
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/SteamCN/SteamCN.list"
        "https://ruleset.skk.moe/clash/domainset/apple_cn.txt"
    )
    cnacc_trusted=(
        "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf"
        "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/apple.china.conf"
        "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/google.china.conf"
    )
    gfwlist_base64=(
        "https://raw.githubusercontent.com/Loukky/gfwlist-by-loukky/master/gfwlist.txt"
        "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
        "https://raw.githubusercontent.com/poctopus/gfwlist-plus/master/gfwlist-plus.txt"
    )
    gfwlist_domain=(
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt"
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/greatfire.txt"
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/proxy-list.txt"
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Global/Global_Domain.list"
        "https://raw.githubusercontent.com/pexcn/gfwlist-extras/master/gfwlist-extras.txt"
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Telegram/Telegram.list"
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/OpenAI/OpenAI.list"
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Claude/Claude.list"
    )
    gfwlist2agh_modify=(
        "https://raw.githubusercontent.com/987N/GFWList2AGH/refs/heads/source/data/data_modify.txt"
    )
    rm -rf ./gfwlist2* ./Temp && mkdir ./Temp && cd ./Temp
    for cnacc_domain_task in "${!cnacc_domain[@]}"; do
        curl -s --connect-timeout 15 "${cnacc_domain[$cnacc_domain_task]}" | sed "s/^\.//g" >> ./cnacc_domain.tmp
    done
    for cnacc_trusted_task in "${!cnacc_trusted[@]}"; do
        curl -s --connect-timeout 15 "${cnacc_trusted[$cnacc_trusted_task]}" >> ./cnacc_trusted.tmp
    done
    for gfwlist_base64_task in "${!gfwlist_base64[@]}"; do
        curl -s --connect-timeout 15 "${gfwlist_base64[$gfwlist_base64_task]}" | base64 -d >> ./gfwlist_base64.tmp
    done
    for gfwlist_domain_task in "${!gfwlist_domain[@]}"; do
        curl -s --connect-timeout 15 "${gfwlist_domain[$gfwlist_domain_task]}" | sed "s/^\.//g" >> ./gfwlist_domain.tmp
    done
    for gfwlist2agh_modify_task in "${!gfwlist2agh_modify[@]}"; do
        curl -s --connect-timeout 15 "${gfwlist2agh_modify[$gfwlist2agh_modify_task]}" >> ./gfwlist2agh_modify.tmp
    done
}
# Analyse Data
function AnalyseData() {
    # 1. 定义匹配正则
    # 匹配标准域名格式
    domain_regex="^(([a-z]{1})|([a-z]{1}[a-z]{1})|([a-z]{1}[0-9]{1})|([0-9]{1}[a-z]{1})|([a-z0-9][-\.a-z0-9]{1,61}[a-z0-9]))\.([a-z]{2,13}|[a-z0-9-]{2,30}\.[a-z]{2,3})$"
    # 匹配二级域名后缀 (用于 lite 模式)
    lite_domain_regex="^([a-z]{2,13}|[a-z0-9-]{2,30}\.[a-z]{2,3})$"
    
    # 2. 清洗原始数据 (清洗掉前缀、通配符和常见的规则干扰)
    # 针对 iOS 开发中常见的 Clash 格式进行增强处理，移除 +., DOMAIN-SET, full: 等
    function CleanSource() {
        cat "$1" | \
        sed -r "s/^(\+\.|full:|domain:|DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|DOMAIN-SET)[,:]//g" | \
        sed "s/^\.//g" | \
        tr "A-Z" "a-z" | \
        grep -E "${domain_regex}" | \
        sort | uniq
    }

    echo "正在清洗原始数据..."
    CleanSource "./cnacc_domain.tmp" > "./cnacc_checklist.tmp"
    CleanSource "./cnacc_trusted.tmp" > "./cnacc_trust.tmp"
    cat "./gfwlist_base64.tmp" "./gfwlist_domain.tmp" > "./gfwlist_merged.tmp"
    CleanSource "./gfwlist_merged.tmp" > "./gfwlist_checklist.tmp"

    # 3. 处理用户自定义修改 (data_modify.txt)
    # 解析逻辑保持你原有的符号定义，但增加容错
    echo "正在解析自定义修改规则..."
    modify_file="./gfwlist2agh_modify.tmp"
    
    # 提取黑/白名单的加减逻辑
    cat "$modify_file" | grep -v "\#" | grep "\(\@\%\@\)\|\(\@\%\!\)\|\(\!\&\@\)\|\(\@\@\@\)" | tr -d "\!\%\&\(\)\*\@" | grep -E "${domain_regex}" | sort | uniq > "./cnacc_addition.tmp"
    cat "$modify_file" | grep -v "\#" | grep "\(\!\%\!\)\|\(\@\&\!\)\|\(\!\%\@\)\|\(\!\!\!\)" | tr -d "\!\%\&\(\)\*\@" | grep -E "${domain_regex}" | sort | uniq > "./cnacc_subtraction.tmp"
    cat "$modify_file" | grep -v "\#" | grep "\(\@\&\@\)\|\(\@\&\!\)\|\(\!\%\@\)\|\(\@\@\@\)" | tr -d "\!\%\&\(\)\*\@" | grep -E "${domain_regex}" | sort | uniq > "./gfwlist_addition.tmp"
    cat "$modify_file" | grep -v "\#" | grep "\(\!\&\!\)\|\(\@\%\!\)\|\(\!\&\@\)\|\(\!\!\!\)" | tr -d "\!\%\&\(\)\*\@" | grep -E "${domain_regex}" | sort | uniq > "./gfwlist_subtraction.tmp"

    # 4. 针对 J4125 网关环境的自动化过滤
    # 自动过滤局域网常用域名，防止 SmartDNS 将内网域名送去公网解析
    echo "正在执行环境适配过滤..."
    local_exclusion="(local|lan|home|arpa|fnos|pve|debian)" 
    
    # 5. 核心逻辑运算 (求差集与合并)
    # 从 GFW 列表中剔除国内已知域名
    awk 'NR == FNR { tmp[$0] = 1 } NR > FNR { if ( tmp[$0] != 1 ) print }' "./cnacc_checklist.tmp" "./gfwlist_checklist.tmp" > "./gfwlist_raw.tmp"
    
    # 加上用户强制定义的白名单，剔除内网保留域名
    cat "./cnacc_checklist.tmp" "./cnacc_addition.tmp" "./cnacc_trust.tmp" | \
    grep -Ev "${local_exclusion}" | sort | uniq > "./cnacc_added.tmp"
    
    # 加上用户强制定义的黑名单
    cat "./gfwlist_raw.tmp" "./gfwlist_addition.tmp" | sort | uniq > "./gfwlist_added.tmp"

    # 6. 生成最终数据变量
    # 最终剔除用户指定的“减法”域名
    cnacc_data=($(awk 'NR == FNR { tmp[$0] = 1 } NR > FNR { if ( tmp[$0] != 1 ) print }' "./cnacc_subtraction.tmp" "./cnacc_added.tmp"))
    gfwlist_data=($(awk 'NR == FNR { tmp[$0] = 1 } NR > FNR { if ( tmp[$0] != 1 ) print }' "./gfwlist_subtraction.tmp" "./gfwlist_added.tmp"))

    # 生成 Lite 版本 (保留二级域名)
    echo "${cnacc_data[@]}" | tr ' ' '\n' | rev | cut -d "." -f 1,2 | rev | sort | uniq > "./lite_cnacc_data.tmp"
    echo "${gfwlist_data[@]}" | tr ' ' '\n' | rev | cut -d "." -f 1,2 | rev | sort | uniq > "./lite_gfwlist_data.tmp"
    
    lite_cnacc_data=($(cat "./lite_cnacc_data.tmp"))
    lite_gfwlist_data=($(cat "./lite_gfwlist_data.tmp"))

    echo "数据分析完成。国内域名: ${#cnacc_data[@]} 条, 代理域名: ${#gfwlist_data[@]} 条。"
}
# Generate Rules
function GenerateRules() {
    function FileName() {
        if [ "${generate_file}" == "black" ] || [ "${generate_file}" == "whiteblack" ]; then
            generate_temp="black"
        elif [ "${generate_file}" == "white" ] || [ "${generate_file}" == "blackwhite" ]; then
            generate_temp="white"
        else
            generate_temp="debug"
        fi
        if [ "${software_name}" == "smartdns" ]; then
            file_extension="conf"
        else
            file_extension="dev"
        fi
        if [ ! -d "../gfwlist2${software_name}" ]; then
            mkdir "../gfwlist2${software_name}"
        fi
        file_name="${generate_temp}list_${generate_mode}.${file_extension}"
        file_path="../gfwlist2${software_name}/${file_name}"
    }

    case ${software_name} in
        smartdns)
            if [ "${generate_mode}" == "full" ]; then
                if [ "${generate_file}" == "black" ]; then
                    FileName && for gfwlist_data_task in "${!gfwlist_data[@]}"; do
                        echo "${gfwlist_data[$gfwlist_data_task]}" >> "${file_path}"
                    done
                elif [ "${generate_file}" == "white" ]; then
                    FileName && for cnacc_data_task in "${!cnacc_data[@]}"; do
                        echo "${cnacc_data[$cnacc_data_task]}" >> "${file_path}"
                    done
                fi
            elif [ "${generate_mode}" == "lite" ]; then
                if [ "${generate_file}" == "black" ]; then
                    FileName && for lite_gfwlist_data_task in "${!lite_gfwlist_data[@]}"; do
                        echo "${lite_gfwlist_data[$lite_gfwlist_data_task]}" >> "${file_path}"
                    done
                elif [ "${generate_file}" == "white" ]; then
                    FileName && for lite_cnacc_data_task in "${!lite_cnacc_data[@]}"; do
                        echo "${lite_cnacc_data[$lite_cnacc_data_task]}" >> "${file_path}"
                    done
                fi
            fi
        ;;
        *)
            exit 1
    esac
}
# Output Data
function OutputData() {
    ## SmartDNS
    software_name="smartdns" && generate_file="black" && generate_mode="full" && foreign_group="foreign" && GenerateRules
    software_name="smartdns" && generate_file="white" && generate_mode="full" && domestic_group="domestic" && GenerateRules
    cd .. && rm -rf ./Temp
    exit 0
}

## Process
# Call GetData
GetData
# Call AnalyseData
AnalyseData
# Call OutputData
OutputData
