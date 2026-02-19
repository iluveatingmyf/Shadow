# test.py
import pyshark

TEST_PCAP = "./data/pcap/R1770396219926_s1_br-lan.pcap"
T_HA_RECORDED = 1771385038.407836  # 替换为你的样本时间

def debug_time_offset():
    print(f"[*] Analyzing PCAP: {TEST_PCAP}")
    cap = pyshark.FileCapture(TEST_PCAP, keep_packets=False)
    first_packet_time = None
    for i, pkt in enumerate(cap):
        if i == 0:
            first_packet_time = float(pkt.sniff_timestamp)
            break
    cap.close()
    print(f"    - First Packet in PCAP: {first_packet_time}")
    print(f"    - Record Time in JSONL: {T_HA_RECORDED}")
    print(f"    - Potential Offset: {T_HA_RECORDED - first_packet_time:.3f}s")
    if abs(T_HA_RECORDED - first_packet_time) > 10:
        print("\n[!] ALERT: Your HA clock and Capture clock are heavily out of sync!")

if __name__ == "__main__":
    debug_time_offset()