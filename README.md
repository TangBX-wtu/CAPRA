# CAPRA: Context-Aware Patch Risk Assessment
CAPRA is a Python3-based security detection tool for C/C++ program patches. It analyzes the logical behavioral impact of pending patches on source programs to determine whether incorporating the patch might trigger immature vulnerabilities. 
 Operating environment and main dependencies: 
 1) Python 3.10
 2) Ubuntu 22.04.4
 3) Joern 2.0.4
 4) NetworkX 3.3

CAPRA Usage Instructions:

Execute through command line using：python3 PatchbasedIncrementalDefectDetection.py -p <test file path> -c [1] -d [1] -r [1]
Where -p is the path to the files for analysis, which should contain two folders named 'a' and 'b', storing the source code files before and after modification respectively; -c indicates whether to recreate the code property graph, default value is 0; -d indicates whether to recreate the patch file, default value is 0; -r is used for batch testing. Detailed parameter usage instructions can be obtained through -help.

DataSet-2025:

1）UAF / Memory leak: data from manually modified SARD-2022-08-11-juliet

2）Hypocrite Commit: test cases from "Hypocrite Commit"

3) RealWorld: legitimate commits randomly selected from the corresponding open source projects (Linux, OpenSSH, ffmpeg, libevent, memcached)

4) ComparisionExperiment: a comparative dataset based on the SARD dataset: 1. Each sample only preserves the target file; 2. Each target file only retains code related to the patch context and vulnerability chain (excluding interference from other potential defects that might exist in the remaining code). No modifications are needed for real-world scenario dataset
