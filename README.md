# CAPRA: Context-Aware Patch Risk Assessment
 CAPRA is a Python3-based security detection tool for C/C++ program patches. It analyzes the logical behavioral impact of pending patches on source programs to determine whether incorporating the patch might trigger immature vulnerabilities. 
 Operating environment and main dependencies: 
 1) Python 3.10
 2) Ubuntu 22.04.4
 3) Joern 2.0.4
 4) NetworkX 3.3

DataSet:
UAF and Memory leak: data from manually modified SARD-2022-08-11-juliet
Hypocrite Commit: test cases from "Hypocrite Commit"
OpenSSH and Linux: legitimate patches randomly selected from the corresponding open source project
