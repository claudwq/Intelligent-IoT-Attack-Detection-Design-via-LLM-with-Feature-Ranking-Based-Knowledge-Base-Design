import json
import re
import pandas as pd
import ollama


feature_names = [
    "flow_duration", "Header_Length", "Protocol Type", "Duration", "Rate", "Srate", "Drate",
    "fin_flag_number", "syn_flag_number", "rst_flag_number", "psh_flag_number", "ack_flag_number",
    "ece_flag_number", "cwr_flag_number", "ack_count", "syn_count", "fin_count", "urg_count",
    "rst_count", "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP",
    "ARP", "ICMP", "IPv", "LLC", "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "IAT", "Number",
    "Magnitue", "Radius", "Covariance", "Variance", "Weight", "label"
]


df = pd.read_csv('without_syn.csv', header=None, names=feature_names)
filtered_df = df[df['label'].isin([
    'DDoS-ICMP_Flood', 'DDoS-UDP_Flood', 'DDoS-TCP_Flood', 
    'DDoS-PSHACK_Flood', 'DDoS-SYN_Flood', 'DDoS-RSTFINFlood', 
    'DDoS-SynonymousIP_Flood'
])]

attack_types_list = [
    'DDoS-ICMP_Flood', 'DDoS-UDP_Flood', 'DDoS-TCP_Flood', 
    'DDoS-PSHACK_Flood', 'DDoS-SYN_Flood', 'DDoS-RSTFINFlood', 
    'DDoS-SynonymousIP_Flood'
]

# knowledge_base = {
#     'DDoS-ICMP_Flood': "DDoS ICMP flood attacks are characterized by high packet size, magnitude, and total volume.",
#     'DDoS-UDP_Flood': "DDoS UDP flood attacks show high inter-arrival time and large packet bursts with UDP protocol.",
#     'DDoS-TCP_Flood': "DDoS TCP flood attacks use TCP protocol, with high SYN flag counts and irregular packet intervals.",
#     'DDoS-PSHACK_Flood': "DDoS PSHACK flood attacks involve push-acknowledgment flags and high urgency counts.",
#     'DDoS-SYN_Flood': "DDoS SYN flood attacks often originate from a single IP with low syn_count and short duration.",
#     'DDoS-RSTFIN_Flood': "DDoS RSTFIN flood attacks have high reset (RST) and finished (FIN) counts.",
#     'DDoS-SynonymousIP_Flood': "DDoS SynonymousIP flood attacks involve multiple IPs with higher syn_count."
# }

# knowledge_base = {
#     'DDoS-ICMP_Flood': (
#         "DDoS ICMP flood attacks are characterized by the following key features:\n"
#         "- High minimum packet size (Min) typically between 42.0 and 3236.2, indicating large ICMP packets.\n"
#         "- High magnitude, ranging from 9.17 to 120.98, reflecting the intensity of the attack.\n"
#         "- Elevated average packet size (AVG) between 42.0 and 7861.1, suggesting a flood of large packets.\n"
#         "- High total sum of packets, typically between 42.0 and 58371.0, pointing to a large volume of traffic.\n"
#         "- Maximum packet size (Max) between 42.0 and 30329.2 and total size (42.0 to 13098.0).\n"
#         "- Header length ranging up to 9809699.6, slightly above average.\n"
#         "- Inter-Arrival Time (IAT) varies from 0.0 to 167639426.3, indicating rapid packet generation."
#     ),
#     'DDoS-UDP_Flood': (
#         "DDoS UDP flood attacks are characterized by the following key features:\n"
#         "- Very high Inter-Arrival Time (IAT), ranging from 0.0 to 167639426.3, indicating large gaps between packet bursts.\n"
#         "- High rate (Rate) and source rate (Srate) between 0.0 and 7340032.0, suggesting rapid packet transmission.\n"
#         "- Elevated header length up to 9809699.6, reflecting larger packet structures.\n"
#         "- Presence of the UDP protocol, with values ranging between 0.0 and 1.0.\n"
#         "- Magnitude ranges from 9.17 to 120.98, with total size between 42.0 and 13098.0, and total sum between 42.0 and 58371.0."
#     ),
#     'DDoS-PSHACK_Flood': (
#         "DDoS PSHACK flood attacks exhibit the following key features:\n"
#         "- PSH flag number ranges between 0.0 and 1.0, indicating a prevalence of push-acknowledgment flags.\n"
#         "- ACK flag number typically between 0.0 and 1.0, distinguishing it from TCP Floods.\n"
#         "- Moderately high URG count (0.0 to 2984.6) and RST count (0.0 to 8744.5), reflecting urgency and reset behavior.\n"
#         "- Inter-Arrival Time (IAT) ranges from 0.0 to 167639426.3, showing moderate variations.\n"
#         "- Header length can go up to 9809699.6.\n"
#         "- Average packet size (AVG) between 42.0 and 7861.1, with maximum packet size (Max) between 42.0 and 30329.2."
#     ),
#     'DDoS-RSTFIN_Flood': (
#         "DDoS RSTFIN flood attacks are identified by the following key features:\n"
#         "- High RST count, ranging from 0.0 to 8744.5, and FIN count, ranging up to 46.5, indicating a large number of reset and finished connections.\n"
#         "- FIN flag number is consistently between 0.0 and 1.0, showing that FIN flags are prevalent in the attack.\n"
#         "- ACK count is typically between 0.0 and 2.2, showing low acknowledgment activity.\n"
#         "- Inter-Arrival Time (IAT) varies widely, from 0.0 to 167639426.3, showing irregular timing between packets.\n"
#         "- Header length can go up to 9809699.6.\n"
#         "- TCP value is usually 1.0, but this attack type is distinguished by its high RST and FIN counts."
#     ),
#     'DDoS-TCP_Flood': (
#         "DDoS TCP flood attacks are characterized by the following key features:\n"
#         "- The 'TCP' value is always set to 1.0, indicating the use of the TCP protocol for this attack type.\n"
#         "- Inter-Arrival Time (IAT) is high, ranging from 0.0 to 167639426.3, showing irregular packet intervals.\n"
#         "- SYN flag number ranges from 0.0 to 1.0, with SYN count reaching up to 6.76, showing frequent connection attempts.\n"
#         "- Flow duration varies greatly, from 0.0 to 68430.7 seconds, indicating both short and extended attack sessions.\n"
#         "- RST and FIN counts are generally lower than in RSTFIN floods, with RST count up to 8744.5 and FIN count up to 46.5, but often less dominant.\n"
#         "- Total packet volume is high, with total sum values between 42.0 and 58371.0."
#     ),
#     'DDoS-SYN_Flood': (
#         "DDoS SYN flood attacks typically originate from a single IP source and show the following patterns:\n"
#         "- Flow duration is usually short, averaging around 0.13 seconds and rarely exceeding 1 second.\n"
#         "- Header length is generally consistent and lower, with a mean around 61.8.\n"
#         "- Rate and Srate tend to be moderate, averaging 32.7, with controlled packet bursts from one source.\n"
#         "- syn_count is low, averaging around 1.03, rarely exceeding 2, due to single-IP origin behavior."
#     ),
#     'DDoS-SynonymousIP_Flood': (
#         "DDoS SynonymousIP flood attacks involve multiple IPs, showing distributed attack patterns across several sources. Key features:\n"
#         "- Flow duration is longer, averaging around 1.44 seconds, with some sessions extending up to 13 seconds.\n"
#         "- Header length tends to be higher and more variable, averaging around 96.5.\n"
#         "- Rate and Srate are notably high, peaking up to 9167 due to multi-IP packet bursts.\n"
#         "- syn_count is often higher, with an average of 1.76 and peaks up to 3.9, reflecting distributed connection attempts across multiple IPs."
#     )
# }


# knowledge_base = {
#     'DDoS-ICMP_Flood': (
#         "DDoS ICMP flood attacks are characterized by:\n"
#         "- Min packet size: 42.0 – 3,236.2 bytes.\n"
#         "- Avg packet size: 42.0 – 7,861.1 bytes.\n"
#         "- Max packet size: 42.0 – 30,329.2 bytes.\n"
#         "- Total packet sum: 42.0 – 58,371.0 bytes.\n"
#         "- Total size: 42.0 – 13,098.0 bytes.\n"
#         "- Header length up to 9,809,699.6 bytes.\n"
#         "- Inter-Arrival Time (IAT): 0.0 – 167,639,426.3 (rapid packet generation)."
#     ),
#     'DDoS-UDP_Flood': (
#         "DDoS UDP flood attacks have key features:\n"
#         "- Very high IAT: 0.0 – 167,639,426.3 (large gaps between bursts).\n"
#         "- Rate and Srate: 0.0 – 7,340,032.0 (rapid transmission).\n"
#         "- Header length up to 9,809,699.6 bytes.\n"
#         "- UDP protocol value: 0.0 – 1.0.\n"
#         "- Magnitude: 9.17 – 120.98.\n"
#         "- Total size: 42.0 – 13,098.0 bytes.\n"
#         "- Total packet sum: 42.0 – 58,371.0 bytes."
#     ),
#     'DDoS-PSHACK_Flood': (
#         "DDoS PSHACK flood attacks exhibit:\n"
#         "- PSH flag number: 0.0 – 1.0.\n"
#         "- ACK flag number: 0.0 – 1.0.\n"
#         "- URG count: 0.0 – 2,984.6.\n"
#         "- RST count: 0.0 – 8,744.5.\n"
#         "- IAT: 0.0 – 167,639,426.3.\n"
#         "- Header length up to 9,809,699.6 bytes.\n"
#         "- Avg packet size: 42.0 – 7,861.1 bytes.\n"
#         "- Max packet size: 42.0 – 30,329.2 bytes."
#     ),
#     'DDoS-RSTFIN_Flood': (
#         "DDoS RSTFIN flood attacks are identified by:\n"
#         "- RST count: 0.0 – 8,744.5.\n"
#         "- FIN count: 0.0 – 46.5.\n"
#         "- FIN flag number: 0.0 – 1.0.\n"
#         "- ACK count: 0.0 – 2.2.\n"
#         "- IAT: 0.0 – 167,639,426.3.\n"
#         "- Header length up to 9,809,699.6 bytes.\n"
#         "- TCP value usually 1.0."
#     ),
#     'DDoS-TCP_Flood': (
#         "DDoS TCP flood attacks have characteristics:\n"
#         "- TCP value always 1.0.\n"
#         "- IAT: 0.0 – 167,639,426.3.\n"
#         "- SYN flag number: 0.0 – 1.0.\n"
#         "- SYN count: up to 6.76.\n"
#         "- Flow duration: 0.0 – 68,430.7 seconds.\n"
#         "- RST count: up to 8,744.5.\n"
#         "- FIN count: up to 46.5.\n"
#         "- Total packet sum: 42.0 – 58,371.0 bytes."
#     ),
#     'DDoS-SYN_Flood': (
#         "DDoS SYN flood attacks (single IP source) show:\n"
#         "- Flow duration: ~0.13 seconds (rarely exceeds 1 s).\n"
#         "- Header length: mean ~61.8 bytes.\n"
#         "- Rate and Srate: mean ~32.7.\n"
#         "- SYN count: mean ~1.03 (rarely exceeds 2)."
#     ),
#     'DDoS-SynonymousIP_Flood': (
#         "DDoS SynonymousIP flood attacks (multiple IPs) feature:\n"
#         "- Flow duration: ~1.44 seconds (up to 13 s).\n"
#         "- Header length: mean ~96.5 bytes.\n"
#         "- Rate and Srate: up to 9,167.\n"
#         "- SYN count: mean ~1.76 (peaks up to 3.9)."
#     )
# }

# knowledge_base = {
#     'DDoS-ICMP_Flood': "High Min/Avg/Max packet sizes (42.0 – 30,329.2 bytes), large total packet sum.",
#     'DDoS-UDP_Flood': "Very high IAT (0.0 – 167,639,426.3), high Rate/Srate (up to 7,340,032.0).",
#     'DDoS-TCP_Flood': "SYN count up to 6.76, variable flow durations (0.0 – 68,430.7 s).",
#     'DDoS-PSHACK_Flood': "High PSH/ACK flags, URG count (0.0 – 2,984.6), RST count (0.0 – 8,744.5).",
#     'DDoS-RSTFIN_Flood': "High RST count (up to 8,744.5), FIN count (up to 46.5), low ACK count (up to 2.2).",
#     'DDoS-SYN_Flood': "Short flow duration (~0.13 s), low SYN count (~1.03), header length ~61.8 bytes.",
#     'DDoS-SynonymousIP_Flood': "Longer flow duration (~1.44 s), higher SYN count (~1.76), high Rate/Srate (up to 9,167)."
# }
# knowledge_base = {
#     'DDoS-ICMP_Flood': (
#         "DDoS ICMP flood attacks have the following characteristics:\n"
#         "- **Protocol Type**: 1 (ICMP).\n"
#         "- **High Packet Rate**: Elevated 'Rate' values indicating rapid packet transmission.\n"
#         "- **Inter-Arrival Time (IAT)**: Low values, showing minimal time between packets.\n"
#         "- **Packet Sizes**: 'Min', 'Max', and 'AVG' sizes consistent with typical ICMP packets.\n"
#         "- **Header Length**: Consistent with standard ICMP header sizes.\n"
#     ),
#     'DDoS-UDP_Flood': (
#         "DDoS UDP flood attacks are characterized by:\n"
#         "- **Protocol Type**: 17 (UDP).\n"
#         "- **High Packet Rate**: Elevated 'Rate' and 'Srate' values indicating rapid packet transmission.\n"
#         "- **Inter-Arrival Time (IAT)**: Low values, indicating minimal delay between packets.\n"
#         "- **Packet Sizes**: Varying 'Min', 'Max', and 'AVG' sizes depending on the attack payload.\n"
#         "- **Header Length**: Consistent with UDP packets.\n"
#     ),
#     'DDoS-PSHACK_Flood': (
#         "DDoS PSH+ACK flood attacks exhibit the following features:\n"
#         "- **Protocol Type**: 6 (TCP).\n"
#         "- **High PSH and ACK Flags**: Elevated 'psh_flag_number' and 'ack_flag_number'.\n"
#         "- **High Packet Rate**: Indicating rapid transmission of TCP packets with PSH and ACK flags.\n"
#         "- **Inter-Arrival Time (IAT)**: Low values, showing quick succession of packets.\n"
#     ),
#     'DDoS-RSTFIN_Flood': (
#         "DDoS RST+FIN flood attacks are identified by:\n"
#         "- **Protocol Type**: 6 (TCP).\n"
#         "- **High RST and FIN Flags**: Elevated 'rst_flag_number' and 'fin_flag_number'.\n"
#         "- **High Packet Rate**: Rapid transmission of packets with RST and FIN flags.\n"
#         "- **Inter-Arrival Time (IAT)**: Low values, indicating minimal delay between packets.\n"
#     ),
#     'DDoS-TCP_Flood': (
#         "DDoS TCP flood attacks have these characteristics:\n"
#         "- **Protocol Type**: 6 (TCP).\n"
#         "- **High Packet Rate**: Elevated 'Rate' values for TCP packets.\n"
#         "- **Inter-Arrival Time (IAT)**: Low values, indicating rapid packet transmission.\n"
#         "- **Flags**: May involve various TCP flags, but not dominated by SYN, RST, or FIN flags.\n"
#     ),
#     'DDoS-SYN_Flood': (
#         "DDoS SYN flood attacks are characterized by:\n"
#         "- **Protocol Type**: 6 (TCP).\n"
#         "- **High SYN Flags**: Elevated 'syn_flag_number' and 'syn_count', indicating numerous connection attempts.\n"
#         "- **High Packet Rate**: Rapid transmission of SYN packets.\n"
#         "- **Inter-Arrival Time (IAT)**: Low values, showing quick succession of SYN packets.\n"
#         "- **Flow Duration**: Typically short, due to the nature of SYN floods.\n"
#     ),
#     'DDoS-SynonymousIP_Flood': (
#         "DDoS Synonymous IP flood attacks involve multiple IPs with these features:\n"
#         "- **Multiple Source IPs**: Attack traffic originates from various IP addresses.\n"
#         "- **Protocol Type**: 6 (TCP).\n"
#         "- **High SYN Counts**: Elevated 'syn_count' across multiple flows.\n"
#         "- **High Packet Rate**: Due to simultaneous attacks from multiple sources.\n"
#         "- **Flow Duration**: May be longer on average compared to single-source attacks.\n"
#     ),
#     'DoS-TCP_Flood': (
#         "DoS TCP flood attacks are characterized by:\n"
#         "- **Single Source IP**: Attack originates from one IP address.\n"
#         "- **Protocol Type**: 6 (TCP).\n"
#         "- **High Packet Rate**: Elevated 'Rate' values.\n"
#         "- **Inter-Arrival Time (IAT)**: Low values, indicating rapid packet transmission.\n"
#     ),
#     'DoS-UDP_Flood': (
#         "DoS UDP flood attacks exhibit the following:\n"
#         "- **Single Source IP**: Attack originates from one IP address.\n"
#         "- **Protocol Type**: 17 (UDP).\n"
#         "- **High Packet Rate**: Elevated 'Rate' values.\n"
#         "- **Inter-Arrival Time (IAT)**: Low values.\n"
#     ),
#     'DoS-SYN_Flood': (
#         "DoS SYN flood attacks are characterized by:\n"
#         "- **Single Source IP**: Attack originates from one IP address.\n"
#         "- **Protocol Type**: 6 (TCP).\n"
#         "- **High SYN Flags**: Elevated 'syn_flag_number' and 'syn_count'.\n"
#         "- **High Packet Rate**: Rapid transmission of SYN packets.\n"
#         "- **Flow Duration**: Generally short.\n"
#     ),
#     'Mirai-greeth_flood': (
#         "Mirai GRE Ethernet flood attacks have these characteristics:\n"
#         "- **Protocol Type**: 47 (GRE).\n"
#         "- **Large Packet Sizes**: High 'Min', 'Max', and 'AVG' packet sizes.\n"
#         "- **High Packet Rate**: Rapid transmission of GRE packets.\n"
#         "- **Inter-Arrival Time (IAT)**: Low values.\n"
#     ),
#     'Mirai-udpplain': (
#         "Mirai UDP plain flood attacks are characterized by:\n"
#         "- **Protocol Type**: 17 (UDP).\n"
#         "- **High Packet Rate**: Elevated 'Rate' values.\n"
#         "- **Variable Packet Sizes**: Depending on attack configuration.\n"
#         "- **Inter-Arrival Time (IAT)**: Low values.\n"
#     ),
#     'MITM-ArpSpoofing': (
#         "Man-in-the-Middle ARP Spoofing attacks exhibit:\n"
#         "- **Abnormal ARP Traffic**: Unusual patterns in ARP protocol usage.\n"
#         "- **Protocol Type**: May involve non-IP protocols (ARP is not IP-based).\n"
#         "- **Flow Durations and Rates**: May vary significantly.\n"
#         "- **Flags**: Unusual flag counts may be observed.\n"
#     ),
#     'BenignTraffic': (
#         "Normal network traffic characteristics:\n"
#         "- **Protocol Types**: Various protocols used in standard communication.\n"
#         "- **Normal Packet Sizes and Rates**: Values within expected ranges for the network.\n"
#         "- **Flags**: No abnormal patterns in TCP/IP flags.\n"
#         "- **Inter-Arrival Time (IAT)**: Varied, reflecting typical network usage.\n"
#     ),
# }
# knowledge_base = {
#     'DDoS-ICMP_Flood': (
#         "Characteristics of DDoS ICMP Flood attacks:\n"
#         "- **Protocol Type**: 1 (ICMP).\n"
#         "- **High Packet Rate**: Typically above **1000 packets/sec**.\n"
#         "- **Inter-Arrival Time (IAT)**: Very low, often near **0 ms**.\n"
#         "- **Packet Size (Min/Max/AVG)**: Usually **42 bytes** (standard ICMP echo request/reply size).\n"
#         "- **Header Length**: Consistent with ICMP headers (~**20 bytes** for IP header + **8 bytes** for ICMP header).\n"
#         "- **Flags**: Not applicable (ICMP does not use TCP flags).\n"
#     ),
#     'DDoS-UDP_Flood': (
#         "Characteristics of DDoS UDP Flood attacks:\n"
#         "- **Protocol Type**: 17 (UDP).\n"
#         "- **High Packet Rate**: Typically above **1000 packets/sec**.\n"
#         "- **Inter-Arrival Time (IAT)**: Very low, often near **0 ms**.\n"
#         "- **Packet Size**: Varies depending on payload, often larger than **50 bytes**.\n"
#         "- **Header Length**: Consistent with UDP headers (**8 bytes** for UDP header + IP header).\n"
#         "- **Flags**: Not applicable (UDP is connectionless and does not use flags).\n"
#     ),
#     'DDoS-TCP_Flood': (
#         "Characteristics of DDoS TCP Flood attacks:\n"
#         "- **Protocol Type**: 6 (TCP).\n"
#         "- **High Packet Rate**: Typically above **1000 packets/sec**.\n"
#         "- **Inter-Arrival Time (IAT)**: Very low, often near **0 ms**.\n"
#         "- **Packet Size**: Depends on the attack; may vary widely.\n"
#         "- **Flags**: Various TCP flags may be set, but no single flag dominates.\n"
#         "- **SYN, ACK, FIN Counts**: Not significantly elevated.\n"
#     ),
#     'DDoS-PSHACK_Flood': (
#         "Characteristics of DDoS PSH+ACK Flood attacks:\n"
#         "- **Protocol Type**: 6 (TCP).\n"
#         "- **High PSH and ACK Flags**: 'psh_flag_number' and 'ack_flag_number' are elevated (often **1** per packet).\n"
#         "- **High Packet Rate**: Typically above **1000 packets/sec**.\n"
#         "- **Inter-Arrival Time (IAT)**: Very low, near **0 ms**.\n"
#         "- **Packet Size**: Can vary; payload may be present due to PSH flag.\n"
#     ),
#     'DDoS-SYN_Flood': (
#         "Characteristics of DDoS SYN Flood attacks:\n"
#         "- **Protocol Type**: 6 (TCP).\n"
#         "- **High SYN Flags**: 'syn_flag_number' is elevated (often **1** per packet).\n"
#         "- **SYN Count**: High 'syn_count', indicating numerous SYN packets.\n"
#         "- **High Packet Rate**: Typically above **1000 packets/sec**.\n"
#         "- **Inter-Arrival Time (IAT)**: Very low, near **0 ms**.\n"
#         "- **Flow Duration**: Usually short, due to incomplete handshakes.\n"
#         "- **Single or Multiple Source IPs**: Can originate from one or many sources.\n"
#     ),
#     'DDoS-RSTFIN_Flood': (
#         "Characteristics of DDoS RST+FIN Flood attacks:\n"
#         "- **Protocol Type**: 6 (TCP).\n"
#         "- **High RST and FIN Flags**: 'rst_flag_number' and 'fin_flag_number' are elevated (often **1** per packet).\n"
#         "- **RST and FIN Counts**: High 'rst_count' and 'fin_count'.\n"
#         "- **High Packet Rate**: Typically above **1000 packets/sec**.\n"
#         "- **Inter-Arrival Time (IAT)**: Very low, near **0 ms**.\n"
#     ),
#     'DDoS-SynonymousIP_Flood': (
#         "Characteristics of DDoS Synonymous IP Flood attacks:\n"
#         "- **Multiple Source IPs**: High number of unique source IP addresses (> **10 sources**).\n"
#         "- **Protocol Type**: 6 (TCP).\n"
#         "- **High SYN Counts**: Elevated 'syn_count' across multiple flows.\n"
#         "- **High Packet Rate**: Due to simultaneous attacks from multiple sources, typically above **1000 packets/sec**.\n"
#         "- **Inter-Arrival Time (IAT)**: Very low, near **0 ms**.\n"
#         "- **Flow Duration**: May be longer on average compared to single-source attacks.\n"
#         "- **Flags**: High SYN flags; other flags may not be elevated.\n"
#     ),
# }
# knowledge_base = {
#     'DDoS-ICMP_Flood': (
#         "DDoS ICMP flood attacks typically exhibit the following characteristics:\n"
#         "- **Min Packet Size:** Ranges from 42.0 to 992.72, commonly at 42.0.\n"
#         "- **Protocol Type:** Between 0.77 and 15.35, usually close to 1.0 for ICMP.\n"
#         "- **Magnitude:** Intensity ranges from 9.17 to 59.80, with a typical value near 9.17.\n"
#         "- **Average Packet Size (AVG):** Spans from 42.0 to 1885.5, often around 42.0.\n"
#         "- **Total Sum of Packets (Tot sum):** Between 42.0 and 19764.8, commonly near 441.0.\n"
#         "- **ICMP Indicator:** Usually 1.0 (ICMP), with values between 0.0 and 1.0.\n"
#         "- **Max Packet Size:** Ranges from 42.0 to 3468.8, often at 42.0.\n"
#         "- **Total Size of Packets (Tot size):** From 42.0 to 1892.12, typically 42.0.\n"
#         "- **Header Length:** Can reach up to 3188816.86, often starting from 0.0.\n"
#         "- **Inter-Arrival Time (IAT):** Very high, between 0.0 and 100179851.34, with a median around 83128994.35."
#     ),
#     'DDoS-UDP_Flood': (
#         "DDoS UDP flood attacks generally show the following characteristics:\n"
#         "- **Inter-Arrival Time (IAT):** Ranges from a very low 4.39e-06 to a high 99748506.47, typically around 83102993.47.\n"
#         "- **Rate and Source Rate (Srate):** Both range from 6.01 to 1569352.19, with a common value near 7480.80.\n"
#         "- **Header Length:** Spans from 751.5 to 1076354.07, often around 24630.0.\n"
#         "- **UDP Indicator:** Typically 1.0 for UDP, though values range between 0.0 and 1.0.\n"
#         "- **Protocol Type:** Usually 17 for UDP, with values ranging from 4.84 to 17.0.\n"
#         "- **Magnitude:** Intensity varies from 9.97 to 41.16, with a typical value of about 10.0.\n"
#         "- **Minimum Packet Size (Min):** Between 48.74 and 468.37, usually close to 50.0.\n"
#         "- **Total Packet Size (Tot size):** Ranges from 49.88 to 1075.46, with a common value near 50.0.\n"
#         "- **Total Sum of Packets (Tot sum):** Between 150.0 and 11576.45, typically around 525.0."
#     ),
#     'DDoS-TCP_Flood': (
#         "DDoS TCP flood attacks often display the following characteristics:\n"
#         "- **Inter-Arrival Time (IAT):** Ranges from a very low 1.36e-07 to a high 99691821.68, with a typical value around 83068279.07.\n"
#         "- **SYN Count:** Usually 0.0, but can occasionally reach up to 2.25 during high activity.\n"
#         "- **Header Length:** Between 50.96 and 1264522.69, commonly around 54.0.\n"
#         "- **SYN Flag Number:** Typically 0.0, indicating absence or minimal SYN flags during regular traffic.\n"
#         "- **Flow Duration:** Ranges from 0.0 to 1270.90, often 0.0 in shorter-lived connections.\n"
#         "- **FIN Count:** Typically 0.0, but can reach 0.45 during certain TCP exchanges.\n"
#         "- **TCP Indicator:** Often 1.0, confirming TCP protocol usage, but can range from 0.0 to 1.0.\n"
#         "- **URG Count:** Typically 0.0, but can reach up to 367.51 during urgency flag usage.\n"
#         "- **Protocol Type:** Commonly around 6.0, with values ranging from 5.65 to 13.52.\n"
#         "- **ACK Flag Number:** Mostly 0.0, indicating limited acknowledgment flags in standard traffic."
#     ),
#     'DDoS-PSHACK_Flood': (
#         "DDoS PSHACK flood attacks generally display the following characteristics:\n"
#         "- **PSH Flag Number:** Typically 0.0, indicating limited push flags in the traffic.\n"
#         "- **ACK Flag Number:** Ranges from 0.0 to 1.0, distinguishing it from other TCP floods.\n"
#         "- **URG Count:** Often 0.0, but can reach as high as 367.51, showing occasional urgency flags.\n"
#         "- **RST Count:** Varies from 0.0 to 929.22, indicating the presence of reset behavior.\n"
#         "- **Inter-Arrival Time (IAT):** Ranges from a very low 1.36e-07 to a high of 99691821.68, commonly around 83068279.07.\n"
#         "- **Total Packet Size (Tot size):** Between 53.76 and 1177.9, typically around 54.0.\n"
#         "- **Magnitude:** Intensity varies from 10.33 to 40.65, with a common value near 10.39.\n"
#         "- **Header Length:** Between 50.96 and 1264522.69, often around 54.0.\n"
#         "- **Average Packet Size (AVG):** Ranges from 53.34 to 1079.47, commonly near 54.0.\n"
#         "- **Maximum Packet Size (Max):** Between 53.76 and 3022.11, with typical values around 54.0."
#     ),
#     'Mirai-udpplain': (
#         "Mirai-udpplain attacks exhibit sustained, organized UDP traffic characterized by:\n"
#         "- Flow Duration: Moderate, around 0.662 seconds, indicating sustained botnet activity.\n"
#         "- Rate and Srate: Moderate rate around 1114.56, consistent across flows, reflecting a controlled rate of packet transmission.\n"
#         "- Header Length: High and stable at 410946.12, indicative of structured, botnet-generated packets.\n"
#         "- Packet Size (`AVG`): Consistently large (554), showing uniform packet size due to Mirai botnet's packet structure.\n"
#         "- Inter-Arrival Time (IAT): High and steady at 83767545.1, representing regular packet intervals typical of Mirai botnet traffic.\n"
#         "- Magnitude: Moderate at 33.29, indicating the controlled but impactful nature of the attack.\n"
#         "- Distinctive Traits: The consistency in `Header_Length`, packet size, and `IAT` suggests the organized nature of Mirai traffic, in contrast to more variable DDoS patterns."
#     ),
#         'Mirai-greip_flood': (
#         "Mirai-greip flood attacks are characterized by structured botnet traffic using GRE encapsulation, with the following distinguishing features:\n"
#         "- **Flow Duration**: Generally shorter, often close to 0, suggesting shorter bursts compared to Mirai-udpplain.\n"
#         "- **Header Length**: Lower (e.g., around 46.53), typically less than Mirai-udpplain's header length, which is much higher due to UDP packet encapsulation.\n"
#         "- **Standard Deviation of Packet Size (`Std`)**: Shows variability (up to 11.38), indicating packets of differing sizes, unlike the more consistent packet sizes in Mirai-udpplain.\n"
#         "- **Magnitude**: Moderate (e.g., 33.91), reflecting the intensity of the GRE flood but with variability in packet size.\n"
#         "- **Packet Size Consistency (`Min`, `Max`, `AVG`)**: Displays variability across packets, with ranges like 42.0 to 578.0 in `Max`, suggesting fluctuating packet sizes typical of GRE floods.\n"
#         "- **Protocol Type**: Includes GRE-related values that differ from standard UDP, helping distinguish it from Mirai-udpplain.\n"
#         "- **Distinctive Traits**: Shorter flow durations, lower Header Length, and high packet size variability mark Mirai-greip_flood as distinct from UDP-based Mirai attacks."
#     ),
#     'DoS-UDP_Flood': (
#         "DoS UDP flood attacks typically exhibit the following characteristics:\n"
#         "- **Inter-Arrival Time (IAT):** Ranges from a very low 1.91e-07 to a high of 99620005.43, with a typical value around 83012363.36.\n"
#         "- **UDP Indicator:** Usually 1.0, confirming UDP protocol use, though it can range between 0.0 and 1.0.\n"
#         "- **Protocol Type:** Typically 17, aligning with UDP traffic, with values ranging from 0.99 to 17.0.\n"
#         "- **Rate and Source Rate (Srate):** Both range from 0.0 to 4194304.0, with a median around 10628.37, reflecting high but controlled packet rates.\n"
#         "- **Flow Duration:** Generally brief, ranging from 0.0 to 153.74 seconds, often around 0.03 seconds, suggesting short, intense bursts.\n"
#         "- **TCP Indicator:** Usually 0.0, distinguishing it from TCP-based attacks.\n"
#         "- **Header Length:** Ranges from 0.0 to 2229362.56, with a typical value near 16525.0.\n"
#         "- **Average Packet Size (AVG):** Between 42.0 and 1186.43, often around 50.15, indicating moderately sized packets.\n"
#         "- **Magnitude:** Intensity ranges from 9.17 to 46.49, with a common value around 10.02, reflecting a moderate impact level."
#     ),
#     'DDoS-SYN_Flood': (
#         "DDoS SYN flood attacks typically display the following characteristics:\n"
#         "- **Inter-Arrival Time (IAT):** Ranges from 50359654.82 to 100194333.81, with a typical value around 83090041.20, indicating rapid packet intervals.\n"
#         "- **SYN Flag Number:** Typically 1.0, confirming SYN flood traffic, with values ranging between 0.0 and 1.0.\n"
#         "- **SYN Count:** Generally between 0.05 and 2.52, with a median of 1.0, showing frequent SYN packets.\n"
#         "- **Flow Duration:** Ranges from 0.0 to 1550.30 seconds, often close to 0.0, indicating brief, repeated attack bursts.\n"
#         "- **Header Length:** Spans from 42.72 to 2067634.98, with a typical value of 54.0.\n"
#         "- **Rate and Source Rate (Srate):** Both range from 0.0 to 3355443.2, with a common value around 10.54, showing controlled packet flow.\n"
#         "- **Total Sum of Packets (Tot sum):** Ranges from 477.0 to 13323.9, typically around 567.0, indicating a substantial traffic volume.\n"
#         "- **RST Count:** Typically 0.0, but can reach up to 1485.49, reflecting reset packet presence in some instances.\n"
#         "- **TCP Indicator:** Usually 1.0, confirming TCP-based traffic, with values between 0.0 and 1.0."
#     ),
#     'DDoS-SynonymousIP_Flood': (
#         "DDoS SynonymousIP flood attacks typically exhibit the following characteristics:\n"
#         "- **Inter-Arrival Time (IAT):** Ranges from a low 2.26e-06 to a high of 100038436.29, with a median of 83362209.36.\n"
#         "- **SYN Flag Number:** Generally 1.0, confirming SYN flood behavior, though values range from 0.0 to 1.0.\n"
#         "- **SYN Count:** Ranges from 0.0 to 6.76, with a median of 1.68, showing multiple SYN packets across connections.\n"
#         "- **Flow Duration:** Varies from 0.0 to 200.72 seconds, with a typical value around 0.71 seconds, suggesting prolonged connections.\n"
#         "- **Header Length:** Between 52.38 and 3053379.88, with a median of 91.8, indicating larger headers due to multiple IPs.\n"
#         "- **Magnitude:** Ranges from 10.36 to 63.52, with a typical value around 10.39, reflecting higher impact.\n"
#         "- **Average Packet Size (AVG):** From 53.63 to 2279.49, commonly around 54.0, showing packet size consistency.\n"
#         "- **Total Sum of Packets (Tot sum):** Between 135.0 and 24959.7, typically around 567.0, indicating a large volume.\n"
#         "- **RST Count:** Often 0.0, but can reach up to 2615.26, indicating reset flags in some packets.\n"
#         "- **Minimum Packet Size (Min):** Ranges from 49.84 to 967.55, with a median around 54.0."
#     )
# }



# # 将知识库内容转为文本格式
# knowledge_base_content = "\n\n".join([f"{key}: {value}" for key, value in knowledge_base.items()])

# # 生成预测的函数
# def generate_prediction(data):
#     input_text = (
#         f"Given network traffic data: {json.dumps(data)}, "
#         f"and knowledge base: {knowledge_base_content}, "
#         #f"what is the most likely type of attack? Choose one from the following list or 'None of the above': {', '.join(attack_types_list)}, None of the above. "
#         f"what is the most likely type of attack? Choose one from the following list: {', '.join(attack_types_list)}. "
#         "Provide short answer in the format: 'The attack type is ...'."
#     )



    

#----------------------the below one has some improvement---------------
def generate_prediction(data):
    # Extract and interpret key features
    protocol_type = 'ICMP' if data.get('Protocol Type') == 1 else 'UDP' if data.get('Protocol Type') == 17 else 'TCP' if data.get('Protocol Type') == 6 else 'Unknown'
    packet_rate = data.get('Rate')
    iat = data.get('IAT')
    avg_packet_size = data.get('AVG')
    syn_flag = data.get('syn_flag_number')
    psh_flag = data.get('psh_flag_number')
    ack_flag = data.get('ack_flag_number')
    rst_flag = data.get('rst_flag_number')
    fin_flag = data.get('fin_flag_number')

    # Qualitative descriptions
    rate_desc = 'high' if packet_rate > 1000 else 'low'
    iat_desc = 'low' if iat < 1000 else 'high'

    # Create a natural language description
    data_description = f"""
Network Traffic Data:
- Protocol Type: {protocol_type}
- Packet Rate: {packet_rate:.2f} packets/sec ({rate_desc})
- Inter-Arrival Time (IAT): {iat_desc}
- Average Packet Size: {avg_packet_size} bytes
- TCP Flags:
    - SYN: {syn_flag}
    - PSH: {psh_flag}
    - ACK: {ack_flag}
    - RST: {rst_flag}
    - FIN: {fin_flag}
"""

    # Summarize the knowledge base (abbreviated for brevity)
    kb_summary = """
Knowledge Base:
1. DDoS-ICMP_Flood:
   - Protocol: ICMP
   - High packet rate, low IAT
2. DDoS-UDP_Flood:
   - Protocol: UDP
   - High packet rate, low IAT
3. DDoS-TCP_Flood:
   - Protocol: TCP
   - High packet rate
4. DDoS-PSHACK_Flood:
   - Elevated PSH and ACK flags
5. DDoS-SYN_Flood:
   - Elevated SYN flag
6. DDoS-RSTFIN_Flood:
   - Elevated RST and FIN flags
7. DDoS-SynonymousIP_Flood:
   - Multiple source IPs, high SYN counts
"""

    # Construct the prompt
    input_text = f"""
{data_description}

Based on the knowledge base, determine the most likely attack type from the following list:
{', '.join(attack_types_list)}.

Provide your answer in the format: 'The attack type is [Attack Type].' If none match, respond with 'The attack type is Unknown.'
"""

    # Generate the response
    response = ollama.generate(model="phi3", prompt=input_text)#phi3:medium

    if response and 'response' in response:
        return response['response']
    else:
        return "Error: Response did not contain content"

#-----------------------------------------------------------------



#-----------------------------------------------------------------


normalized_attack_types_list = [label.lower().replace("-", "").replace("_", "") for label in attack_types_list]


correct_predictions_per_label = {label: 0 for label in normalized_attack_types_list}
incorrect_predictions_per_label = {label: 0 for label in normalized_attack_types_list}


for index, row in filtered_df.iterrows():
    data = row.to_dict()
    true_label = str(data.pop("label"))
    normalized_true_label = true_label.lower().replace("-", "").replace("_", "")
    #print(f"The input data is {data} and true_label is:{true_label}")

    try:
        
        response_content = generate_prediction(data)
        match = re.search(r"The attack type is (.+)\.", response_content)
        predicted_label = match.group(1).strip().lower().replace("-", "").replace("_", "") if match else ""

       
        if normalized_true_label == predicted_label:
            correct_predictions_per_label[normalized_true_label] += 1
            #print(f"Sample {index + 1}: Correct prediction. Predicted: {response_content.strip()}")
        else:
            incorrect_predictions_per_label[normalized_true_label] += 1
            #print(f"Sample {index + 1}: Incorrect prediction. Predicted: {response_content.strip()}, Expected: {true_label}")
    
    except Exception as e:
        #print(f"Sample {index + 1}: Error processing the request. Exception: {str(e)}")
        incorrect_predictions_per_label[normalized_true_label] += 1


total_samples = len(df)
print(f"Total Samples: {total_samples}")

for label in normalized_attack_types_list:
    total_label_samples = correct_predictions_per_label[label] + incorrect_predictions_per_label[label]
    if total_label_samples > 0:
        accuracy = (correct_predictions_per_label[label] / total_label_samples) * 100
        print("phi3mini with new short KB")
        print(f"Label: {label}")
        print(f"  Total Samples: {total_label_samples}")
        print(f"  Correct Predictions: {correct_predictions_per_label[label]}")
        print(f"  Incorrect Predictions: {incorrect_predictions_per_label[label]}")
        print(f"  Accuracy: {accuracy:.2f}%")
    else:
        print(f"Label: {label} has no samples.")
