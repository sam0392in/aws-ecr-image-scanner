# AWS ECR Image Scanner
[![GitHub go.mod Go version of a Go module](https://img.shields.io/github/go-mod/go-version/gomods/athens.svg)](https://github.com/gomods/athens) 
[![Go Report Card](https://goreportcard.com/badge/github.com/sam0392in/aws-ecr-image-scanner)](https://goreportcard.com/report/github.com/sam0392in/aws-ecr-image-scanner)
![GitHub release (latest by date including pre-releases)](https://img.shields.io/github/v/release/sam0392in/aws-ecr-image-scanner?include_prereleases)


- This binary shows the ecr image scan findings in a human readable format.
- This binary can be integrated with CI pipelines where post docker image creation, scanning can be done to see vulnerabilities.

## Prerequisites
- ECR Scan is enabled in your AWS Account

## Download Binary (Example for MAC Supported System)
```
wget https://github.com/sam0392in/aws-ecr-image-scanner/releases/download/v0.1/aws-ecr-image-scanner-darwin && \
chmod 755 aws-ecr-image-scanner-darwin && \
mv aws-ecr-image-scanner-darwin /usr/local/bin/aws-ecr-image-scanner

```

## Usage
```shell
aws-ecr-image-scanner scan --region eu-west-1 --repo < ECR REPOSITORY NAME > --tag < IMAGE TAG > --severity < SEVERITY >
```

### Arguments
- --region:  Enter AWS Region
- --repo:     Enter Repository Name
- --tag:      Enter Image Tag
- --severity: Comma separated multiple choice, options: critical/high/medium/low/informational/all

### Output
```shell

│────────────────│──────────│────────────────────────────────────────────────────────│──────────────│──────────────────│
│ NAME           │ SEVERITY │ DESCRIPTION                                            │ PACKAGE NAME │ PACKAGE VERSION  │
│────────────────│──────────│────────────────────────────────────────────────────────│──────────────│──────────────────│
│ CVE-2021-33910 │ HIGH     │ basic/unit-name.c in systemd prior to 246.15, 247.8,   │ systemd      │ 245.4-4ubuntu3.2 │
│                │          │ 248.5, and 249.1 has a Memory Allocation with an       │              │                  │
│                │          │ Excessive Size Value (involving strdupa and alloca for │              │                  │
│                │          │ a pathname controlled by a local attacker) that        │              │                  │
│                │          │ results in an operating system crash.                  │              │                  │
│────────────────│──────────│────────────────────────────────────────────────────────│──────────────│──────────────────│
```
