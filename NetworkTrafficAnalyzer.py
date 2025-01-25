from scapy.all import IP
import streamlit as st
import pandas as pd
from scapy.all import *
import matplotlib.pyplot as plt
import numpy as np
from io import BytesIO
import time
import logging
from tqdm import tqdm
from tabulate import tabulate

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

def read_pcap(pcap_file):
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        logger.error(f"PCAP file not found: {pcap_file}")
        st.error(f"PCAP file not found: {pcap_file}")
    except Scapy_Exception as e:
        logger.error(f"Error reading PCAP file: {e}")
        st.error(f"Error reading PCAP file: {e}")
    return packets

def extract_packet_data(packets):
    packet_data = []

    for packet in tqdm(packets, desc="Processing packets", unit="packet"):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            Protocol_Name = protocol_name(protocol)
            size = len(packet)
            packet_data.append({"src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol,"Protocol Name": Protocol_Name, "size (bytes)": size})

    return pd.DataFrame(packet_data)

def extract_packet_data_security(packets):
    packet_data = []
    TCP =""
    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            Protocol_Name = protocol_name(protocol)
            size = len(packet)

            if TCP in packet:
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags  # Extract TCP flags
            else:
                dst_port = 0
                flags = None  # No flags for non-TCP packets

            # Append packet information
            packet_data.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "Protcol Name": Protocol_Name,
                "size (bytes)": size,
                "dst_port": dst_port,
                "flags": flags  # Include flags in the DataFrame
            })

    return pd.DataFrame(packet_data)


def protocol_name(number):
    protocol_dict = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
    return protocol_dict.get(number, f"Unknown({number})")

def analyze_packet_data(df):
    total_bandwidth = df["size (bytes)"].sum()

    # Calculate protocol distribution
    protocol_counts = df["protocol"].value_counts(normalize=True) * 100
    protocol_frequency = df["protocol"].value_counts()

    # Reset the indices to make sure both dataframes align properly
    protocol_counts = protocol_counts.reset_index()
    protocol_counts.columns = ["Protocol", "Percentage"]

    protocol_frequency = protocol_frequency.reset_index()
    protocol_frequency.columns = ["Protocol", "Count"]

    # Map protocol numbers to names
    protocol_counts["Protocol"] = protocol_counts["Protocol"].apply(protocol_name)
    protocol_frequency["Protocol"] = protocol_frequency["Protocol"].apply(protocol_name)

    # Merge both dataframes into one
    protocol_counts_df = pd.merge(protocol_frequency, protocol_counts, on="Protocol")

    # Group IP communication data
    ip_communication = df.groupby(["src_ip", "dst_ip"]).size().sort_values(ascending=False)
    ip_communication_percentage = ip_communication / ip_communication.sum() * 100
    ip_communication_table = pd.concat([ip_communication, ip_communication_percentage], axis=1).reset_index()
    ip_communication_table.columns = ["Source IP", "Destination IP", "Count", "Percentage"]

    # Protocols between IPs
    ip_communication_protocols = df.groupby(["src_ip", "dst_ip", "protocol"]).size().reset_index()
    ip_communication_protocols.columns = ["Source IP", "Destination IP", "Protocol", "Count"]
    ip_communication_protocols["Protocol"] = ip_communication_protocols["Protocol"].apply(protocol_name)

    # Calculate the percentage of packets for each protocol between each source-destination pair
    total_counts_per_pair = ip_communication_protocols.groupby(["Source IP", "Destination IP"])["Count"].transform(sum)
    ip_communication_protocols["Percentage"] = (ip_communication_protocols["Count"] / total_counts_per_pair) * 100

    return total_bandwidth, protocol_counts_df, ip_communication_table, protocol_frequency, ip_communication_protocols

# Anomalous Traffic Detection
def detect_anomalous_traffic(df, size_threshold=1000):
    large_packets = df[df["size (bytes)"] > size_threshold]
    protocol_percentage = df["protocol"].value_counts(normalize=True) * 100
    rare_protocols = protocol_percentage[protocol_percentage < 1].index.tolist()
    rare_protocol_traffic = df[df["protocol"].isin(rare_protocols)]
    return large_packets, rare_protocol_traffic

# Top Bandwidth Users Identification
def find_top_bandwidth_users(df, top_n=5):
    bandwidth_usage = df.groupby("src_ip")["size (bytes)"].sum().reset_index()
    bandwidth_usage.columns = ["Source IP", "Total Bandwidth"]
    bandwidth_usage = bandwidth_usage.sort_values(by="Total Bandwidth", ascending=False)
    top_bandwidth_users = bandwidth_usage.head(top_n)
    return top_bandwidth_users

# Protocol-Wise Bandwidth Usage
def protocol_bandwidth_usage(df):
    protocol_usage = df.groupby("protocol")["size (bytes)"].sum().reset_index()
    protocol_usage.columns = ["Protocol", "Total Bandwidth"]
    protocol_usage["Protocol"] = protocol_usage["Protocol"].apply(protocol_name)
    return protocol_usage

# Top Destination Ports
def find_top_destination_ports(df, top_n=5):
    top_ports = df.groupby("dst_port").size().reset_index(name="Count")
    top_ports = top_ports.sort_values(by="Count", ascending=False).head(top_n)
    return top_ports

# Real-Time Traffic Simulation
def real_time_simulation(packets):
    st.subheader("Real-Time Traffic Simulation")
    packet_data = []
    progress_bar = st.progress(0)
    
    for i, packet in enumerate(packets):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            Protocol_Name = protocol_name(protocol)
            size = len(packet)
            packet_data.append({"src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol,"Protocol Name":Protocol_Name, "size (bytes)": size})
        
        if (i+1) % 10 == 0 or i == len(packets) - 1:
            df_sim = pd.DataFrame(packet_data)
            st.write(f"Processed {i+1}/{len(packets)} packets")
            st.table(df_sim.tail(5))
            time.sleep(1)
            progress_bar.progress((i+1)/len(packets))
    
    return df_sim

# Export to CSV
def export_to_csv(df, filename="exported_data.csv"):
    csv = df.to_csv(index=False)
    st.download_button(
        label="Download Data as CSV",
        data=csv,
        file_name=filename,
        mime='text/csv',
    )

def detect_syn_flood(df):
    # Ensure we only analyze TCP packets for SYN flood detection
    print(df)
    if 'flags' in df.columns and 'protocol' in df.columns:
        # Filter TCP packets and look for SYN flags ('S')
        syn_packets = df[(df["protocol"] == 6) & (df["flags"] == "S")]

        # Count SYN packets per source IP
        syn_flood_sources = syn_packets["src_ip"].value_counts().reset_index()
        syn_flood_sources.columns = ["Source IP", "SYN Count"]
        
        # Consider IPs with more than 100 SYN requests as potential SYN flood sources
        potential_syn_flood = syn_flood_sources[syn_flood_sources["SYN Count"] > 5]

        if not potential_syn_flood.empty:
            return potential_syn_flood
        else:
            st.info("No SYN flood detected.")
            return pd.DataFrame()
    else:
        st.error("Error: 'flags' column not found in the data.")
        return pd.DataFrame()  # Return an empty DataFrame if flags are not available



def main():
    st.title("PCAP File Analysis")

    st.write("BY")
    st.write("22PC12 - KARTHIK GANESH")
    st.write("22PC18 - MAHADEV MANOHAR")

    # Upload the PCAP file
    uploaded_file = st.file_uploader("Choose a PCAP file", type=['pcap'])

    if uploaded_file is not None:
        pcap_data = BytesIO(uploaded_file.read())
        packets = read_pcap(pcap_data)
        df = extract_packet_data(packets)
        df_security = extract_packet_data_security(packets)

        # Analyze the packet data
        total_bandwidth, protocol_counts, ip_communication_table, protocol_frequency, ip_communication_protocols = analyze_packet_data(df)

        # Display Total Bandwidth Used
        st.subheader("Total Bandwidth Used")
        total_bandwidth_in_mbps = total_bandwidth / 1e6  # Convert to Mbps
        st.write(f"{total_bandwidth_in_mbps:.2f} Mbps")

        # Display Protocol Distribution
        st.subheader("Protocol Distribution")
        st.table(protocol_counts)

        # Display Protocol Breakdown by IPs
        st.subheader("Share of Protocols Between IPs")
        st.table(ip_communication_protocols)

        # Top N IP Communication Filter
        st.subheader("Top N IP Address Communications")
        top_n = st.slider("Top N IP Communications to Display", 5, 50, 10)
        top_ip_communication_table = ip_communication_table.head(top_n)
        st.table(top_ip_communication_table)

        # Top Bandwidth Users
        st.subheader("Top Bandwidth Users")
        top_bandwidth_users = find_top_bandwidth_users(df, top_n=5)
        st.table(top_bandwidth_users)

        # Protocol-wise Bandwidth Usage
        st.subheader("Protocol-wise Bandwidth Usage")
        protocol_bandwidth = protocol_bandwidth_usage(df)
        st.table(protocol_bandwidth)
        
        # Plot protocol-wise bandwidth usage
        fig, ax = plt.subplots()
        ax.bar(protocol_bandwidth["Protocol"], protocol_bandwidth["Total Bandwidth"], color='skyblue')
        ax.set_ylabel("Total Bandwidth (bytes)")
        ax.set_xlabel("Protocol")
        ax.set_title("Protocol-wise Bandwidth Usage")
        st.pyplot(fig)

        # Anomalous Traffic Detection
        st.subheader("Anomalous Traffic Detection")
        large_packets, rare_protocol_traffic = detect_anomalous_traffic(df, size_threshold=1500)
        
        if not large_packets.empty:
            st.write(f"Detected {len(large_packets)} packets larger than 1500 bytes")
            st.table(large_packets.head())
        else:
            st.write("No large packets detected")
        
        if not rare_protocol_traffic.empty:
            st.write(f"Detected {len(rare_protocol_traffic)} packets from rare protocols (<1% of traffic)")
            st.table(rare_protocol_traffic.head())
        else:
            st.write("No rare protocol traffic detected")

        # Top Destination Ports
        st.subheader("Top Destination Ports")
        top_ports = find_top_destination_ports(df_security, top_n=5)
        st.table(top_ports)

        # Real-Time Traffic Simulation
        st.subheader("Real-Time Traffic Simulation")
        if st.button("Start Real-Time Simulation"):
            real_time_simulation(packets)

        # SYN Flood Detection
        st.subheader("SYN Flood Detection")
        syn_flood_sources = detect_syn_flood(df_security)
        if not syn_flood_sources.empty:
            st.warning("Potential SYN Flood detected from the following IPs:")
            st.table(syn_flood_sources)
        else:
            st.write("No SYN flood detected")

        # Export Data to CSV
        st.subheader("Export Data")
        export_to_csv(df)

        # Interactive Protocol Filtering
        protocol_filter = st.multiselect("Select Protocols to Filter", ['ICMP', 'TCP', 'UDP'], default=['TCP', 'UDP'])  

        # Add a new column for protocol names
        #df['protocol_name'] = df['protocol'].apply(protocol_name)

        # Filter the data based on selected protocols
        filtered_df = df[df['Protocol Name'].isin(protocol_filter)]

        # Display the filtered data
        st.subheader(f"Data Filtered by Protocols: {protocol_filter}")
        st.table(filtered_df[['src_ip', 'dst_ip', 'protocol', 'Protocol Name', 'size (bytes)']])  # Display the relevant columns including protocol number and name


        # Protocol Breakdown by IP
        st.subheader("Protocol Breakdown by IP")
        protocol_breakdown = df.groupby(['src_ip', 'protocol','Protocol Name']).size().unstack(fill_value=0)
        st.table(protocol_breakdown)

        # Packet Size Distribution
        st.subheader("Packet Size Distribution")
        fig_size, ax_size = plt.subplots()
        ax_size.hist(df['size (bytes)'], bins=20, color='skyblue', edgecolor='black')
        ax_size.set_title("Packet Size Distribution")
        ax_size.set_xlabel("Packet Size (bytes)")
        ax_size.set_ylabel("Frequency")
        st.pyplot(fig_size)

if __name__ == "__main__":
    main()

