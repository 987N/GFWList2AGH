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
    cnacc_data=($(domain_regex="^(([a-z]{1})|([a-z]{1}[a-z]{1})|([a-z]{1}[0-9]{1})|([0-9]{1}[a-z]{1})|([a-z0-9][-\.a-z0-9]{1,61}[a-z0-9]))\.([a-z]{2,13}|[a-z0-9-]{2,30}\.[a-z]{2,3})$" && lite_domain_regex="^([a-z]{2,13}|[a-z0-9-]{2,30}\.[a-z]{2,3})$" && cat "./gfwlist2agh_modify.tmp" | grep -v "\#" | grep "\(\@\%\@\)\|\(\@\%\!\)\|\(\!\&\@\)\|\(\@\@\@\)" | tr -d "\!\%\&\(\)\*\@" | grep -E "${domain_regex}" | sort | uniq > "./cnacc_addition.tmp" && cat "./gfwlist2agh_modify.tmp" | grep -v "\#" | grep "\(\!\%\!\)\|\(\@\&\!\)\|\(\!\%\@\)\|\(\!\!\!\)" | tr -d "\!\%\&\(\)\*\@" | grep -E "${domain_regex}" | sort | uniq > "./cnacc_subtraction.tmp" && cat "./gfwlist2agh_modify.tmp" | grep -v "\#" | grep "\(\*\%\*\)\|\(\*\*\*\)" | tr -d "\!\%\&\(\)\*\@" | grep -E "${domain_regex}" | xargs | sed "s/\ /\|/g" | sort | uniq > "./cnacc_exclusion.tmp" && cat "./gfwlist2agh_modify.tmp" | grep -v "\#" | grep "\(\*\%\*\)\|\(\*\*\*\)" | tr -d "\!\%\&\(\)\*\@" | grep -E "${lite_domain_regex}" | xargs | sed "s/\ /\|/g" | sort | uniq > "./lite_cnacc_exclusion.tmp" && cat "./gfwlist2agh_modify.tmp" | grep -v "\#" | grep "\(\!\%\*\)\|\(\!\*\*\)" | tr -d "\!\%\&\(\)\*\@" | grep -E "${domain_regex}" | xargs | sed "s/\ /\|/g" | sort | uniq > "./cnacc_keyword.tmp" && cat "./gfwlist2agh_modify.tmp" | grep -v "\#" | grep "\(\!\%\*\)\|\(\!\*\*\)" | tr -d "\!\%\&\(\)\*\@" | grep -E "${lite_domain_regex}" | xargs | sed "s/\ /\|/g" | sort | uniq > "./lite_cnacc_keyword.tmp" && cat "./gfwlist2agh_modify.tmp" | grep -v "\#" | grep "\(\@\&\@\)\|\(\@\&\!\)\|\(\!\%\@\)\|\(\@\@\@\)" | tr -d "\!\%\&\(\)\*\@" | grep -E "${domain_regex}" | sort | uniq > "./gfwlist_addition.tmp" && cat "./gfwlist2agh_modify.tmp" | grep -v "\#" | grep "\(\!\&\!\)\|\(\@\%\!\)\|\(\!\&\@\)\|\(\!\!\!\)" | tr -d "\!\%\&\(\)\*\@" | grep -E "${domain_regex}" | sort | uniq > "./gfwlist_subtraction.tmp" && cat "./gfwlist2agh_modify.tmp" | grep -v "\#" | grep "\(\*\&\*\)\|\(\*\*\*\)" | tr -d "\!\%\&\(\)\*\@" | grep -E "${domain_regex}" | xargs | sed "s/\ /\|/g" | sort | uniq > "./gfwlist_exclusion.tmp" && cat "./gfwlist2agh_modify.tmp" | grep -v "\#" | grep "\(\*\&\*\)\|\(\*\*\*\)" | tr -d "\!\%\&\(\)\*\@" | grep -E "${lite_domain_regex}" | xargs | sed "s/\ /\|/g" | sort | uniq > "./lite_gfwlist_exclusion.tmp" && cat "./gfwlist2agh_modify.tmp" | grep -v "\#" | grep "\(\!\&\*\)\|\(\!\*\*\)" | tr -d "\!\%\&\(\)\*\@" | grep -E "${domain_regex}" | xargs | sed "s/\ /\|/g" | sort | uniq > "./gfwlist_keyword.tmp" && cat "./gfwlist2agh_modify.tmp" | grep -v "\#" | grep "\(\!\&\*\)\|\(\!\*\*\)" | tr -d "\!\%\&\(\)\*\@" | grep -E "${lite_domain_regex}" | xargs | sed "s/\ /\|/g" | sort | uniq > "./lite_gfwlist_keyword.tmp" && cat "./cnacc_addition.tmp" | grep -E "${lite_domain_regex}" | sort | uniq > "./lite_cnacc_addition.tmp" && cat "./gfwlist_addition.tmp" | grep -E "${lite_domain_regex}" | sort | uniq > "./lite_gfwlist_addition.tmp" && cat "./cnacc_trusted.tmp" | sed -r "s/\/114\.114\.114\.114//g;s/server\=\///g;s/^(domain|full|DOMAIN|DOMAIN-SUFFIX)[,:]//g" | tr "A-Z" "a-z" | grep -E "${domain_regex}" | sort | uniq > "./cnacc_trust.tmp" && cat "./cnacc_trust.tmp" | grep -E "${lite_domain_regex}" | sort | uniq > "./lite_cnacc_trust.tmp" && cat "./cnacc_domain.tmp" | sed -r "s/^(domain|full|DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD)[,:]//g" | tr "A-Z" "a-z" | grep -E "${domain_regex}" | sort | uniq > "./cnacc_checklist.tmp" && cat "./gfwlist_base64.tmp" "./gfwlist_domain.tmp" | sed -r "s/^(domain|full|DOMAIN|DOMAIN-SUFFIX)[,:]//g;s/https?\:\/\///g" | tr -d "|" | tr "A-Z" "a-z" | grep -E "${domain_regex}" | sort | uniq > "./gfwlist_checklist.tmp" && cat "./cnacc_checklist.tmp" | rev | cut -d "." -f 1,2 | rev | sort | uniq > "./lite_cnacc_checklist.tmp" && cat "./gfwlist_checklist.tmp" | rev | cut -d "." -f 1,2 | rev | sort | uniq > "./lite_gfwlist_checklist.tmp" && awk 'NR == FNR { tmp[$0] = 1 } NR > FNR { if ( tmp[$0] != 1 ) print }' "./cnacc_checklist.tmp" "./gfwlist_checklist.tmp" > "./gfwlist_raw.tmp" && awk 'NR == FNR { tmp[$0] = 1 } NR > FNR { if ( tmp[$0] != 1 ) print }' "./gfwlist_checklist.tmp" "./cnacc_checklist.tmp" | grep -Ev "(\.($(cat './cnacc_exclusion.tmp'))$)|(^$(cat './cnacc_exclusion.tmp')$)|($(cat './cnacc_keyword.tmp'))" > "./cnacc_raw.tmp" && awk 'NR == FNR { tmp[$0] = 1 } NR > FNR { if ( tmp[$0] != 1 ) print }' "./lite_cnacc_checklist.tmp" "./lite_gfwlist_checklist.tmp" > "./lite_gfwlist_raw.tmp" && awk 'NR == FNR { tmp[$0] = 1 } NR > FNR { if ( tmp[$0] != 1 ) print }' "./lite_gfwlist_checklist.tmp" "./lite_cnacc_checklist.tmp" | grep -Ev "(\.($(cat './lite_cnacc_exclusion.tmp'))$)|(^$(cat './lite_cnacc_exclusion.tmp')$)|($(cat './lite_cnacc_keyword.tmp'))" > "./lite_cnacc_raw.tmp" && awk 'NR == FNR { tmp[$0] = 1 } NR > FNR { if ( tmp[$0] != 1 ) print }' "./cnacc_trust.tmp" "./gfwlist_raw.tmp" | grep -Ev "(\.($(cat './gfwlist_exclusion.tmp'))$)|(^$(cat './gfwlist_exclusion.tmp')$)|($(cat './gfwlist_keyword.tmp'))" > "./gfwlist_raw_new.tmp" && awk 'NR == FNR { tmp[$0] = 1 } NR > FNR { if ( tmp[$0] != 1 ) print }' "./cnacc_trust.tmp" "./lite_gfwlist_raw.tmp" | grep -Ev "(\.($(cat './lite_gfwlist_exclusion.tmp'))$)|(^$(cat './lite_gfwlist_exclusion.tmp')$)|($(cat './lite_gfwlist_keyword.tmp'))" > "./lite_gfwlist_raw_new.tmp" && cat "./cnacc_raw.tmp" "./lite_cnacc_raw.tmp" "./cnacc_addition.tmp" "./lite_cnacc_addition.tmp" "./cnacc_trust.tmp" "./lite_cnacc_trust.tmp" | sort | uniq > "./cnacc_added.tmp" && cat "./gfwlist_raw_new.tmp" "./lite_gfwlist_raw_new.tmp" "./gfwlist_addition.tmp" "./lite_gfwlist_addition.tmp" | sort | uniq > "./gfwlist_added.tmp" && cat "./lite_cnacc_raw.tmp" "./lite_cnacc_addition.tmp" "./lite_cnacc_trust.tmp" | sort | uniq > "./lite_cnacc_added.tmp" && cat "./lite_gfwlist_raw_new.tmp" "./lite_gfwlist_addition.tmp" | sort | uniq > "./lite_gfwlist_added.tmp" && awk 'NR == FNR { tmp[$0] = 1 } NR > FNR { if ( tmp[$0] != 1 ) print }' "./cnacc_subtraction.tmp" "./cnacc_added.tmp" > "./cnacc_data.tmp" && awk 'NR == FNR { tmp[$0] = 1 } NR > FNR { if ( tmp[$0] != 1 ) print }' "./gfwlist_subtraction.tmp" "./gfwlist_added.tmp" > "./gfwlist_data.tmp" && awk 'NR == FNR { tmp[$0] = 1 } NR > FNR { if ( tmp[$0] != 1 ) print }' "./cnacc_subtraction.tmp" "./lite_cnacc_added.tmp" > "./lite_cnacc_data.tmp" && awk 'NR == FNR { tmp[$0] = 1 } NR > FNR { if ( tmp[$0] != 1 ) print }' "./gfwlist_subtraction.tmp" "./lite_gfwlist_added.tmp" > "./lite_gfwlist_data.tmp" && cat "./cnacc_data.tmp" "./lite_cnacc_data.tmp" | sort | uniq | awk "{ print $2 }"))
    gfwlist_data=($(cat "./gfwlist_data.tmp" "./lite_gfwlist_data.tmp" | sort | uniq | awk "{ print $2 }"))
    lite_cnacc_data=($(cat "./lite_cnacc_data.tmp" | sort | uniq | awk "{ print $2 }"))
    lite_gfwlist_data=($(cat "./lite_gfwlist_data.tmp" | sort | uniq | awk "{ print $2 }"))
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
