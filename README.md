# Intrusion Detection System in C

This project implements a basic intrusion detection system capable of detecting malicious network traffic. The program processes network packets to identify suspicious activity and prints a detailed report of the detected threats.

## Overview

The program builds upon a provided skeleton that captures packets using the libpcap library. It extends the functionality to:

1. Parse IP and TCP packet headers.
2. Detect malicious activity such as SYN attacks, ARP cache poisoning, and blacklisted URL requests.
3. Implement multithreading to handle high packet throughput efficiently.

## Report
The program outputs a report of detected threats, including:

* SYN attacks
* ARP cache poisoning attempts
* Blacklisted URL requests

For more details, check the source code and report.
