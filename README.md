# Network Security Packet Analyzer

This is a Streamlit-based application for analyzing and visualizing data from PCAP files. The application allows you to upload a PCAP file, process the packets, and perform various network security analysis tasks, such as detecting anomalous traffic, identifying top bandwidth users, and detecting potential SYN flood attacks.

## Features

- **PCAP File Upload**: Upload PCAP files to analyze network traffic.
- **Protocol Distribution**: View the distribution of different protocols (TCP, UDP, ICMP, etc.) used in the traffic.
- **IP Communication Analysis**: Display communication between IP addresses, including the count and percentage of packets.
- **Bandwidth Usage**: Display the total bandwidth used by the traffic and protocol-wise bandwidth usage.
- **Anomalous Traffic Detection**: Detect large packets and rare protocol traffic.
- **Real-Time Traffic Simulation**: Simulate real-time traffic processing and display the data incrementally.
- **SYN Flood Detection**: Identify potential SYN flood attacks based on the frequency of SYN packets.
- **Top Bandwidth Users**: Identify the top N IP addresses that are consuming the most bandwidth.
- **Export Data**: Export the processed packet data to a CSV file for further analysis.
- **Interactive Filtering**: Filter packet data based on selected protocols (ICMP, TCP, UDP).

## Requirements

To run this application, you need the following Python libraries:

- `scapy`: For reading and processing PCAP files.
- `streamlit`: For creating the web application interface.
- `pandas`: For data manipulation and analysis.
- `matplotlib`: For plotting graphs and visualizations.
- `numpy`: For numerical operations.
- `tqdm`: For showing a progress bar while processing packets.
- `tabulate`: For displaying formatted tables.

You can install the required libraries by running the following command:

```bash
pip install scapy streamlit pandas matplotlib numpy tqdm tabulate
