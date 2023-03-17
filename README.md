# AWS ECR Image Scanner
[![GitHub go.mod Go version of a Go module](https://img.shields.io/github/go-mod/go-version/gomods/athens.svg)](https://github.com/gomods/athens) 
[![Go Report Card](https://goreportcard.com/badge/github.com/sam0392in/aws-ecr-image-scanner)](https://goreportcard.com/report/github.com/sam0392in/aws-ecr-image-scanner)
![GitHub release (latest by date including pre-releases)](https://img.shields.io/github/v/release/sam0392in/aws-ecr-image-scanner?include_prereleases)


- This binary shows the ecr image scan findings in a human readable format.
- This binary can be integrated with CI pipelines where post docker image creation, scanning can be done to see vulnerabilities.

## Prerequisites
- ECR Scan is enabled in your AWS Account

## Download Binary 
- Go to github releases https://github.com/sam0392in/aws-ecr-image-scanner/releases
- Download the binary from latest release.

OR

### For MAC OS
```
wget https://github.com/sam0392in/aws-ecr-image-scanner/releases/download/<LATEST TAG>/aws-ecr-image-scanner-darwin && \
chmod 755 aws-ecr-image-scanner-darwin && \
mv aws-ecr-image-scanner-darwin /usr/local/bin/aws-ecr-image-scanner

```

### For Linux OS
```shell
wget https://github.com/sam0392in/aws-ecr-image-scanner/releases/download/<LATEST TAG>/aws-ecr-image-scanner-linux && \
chmod 755 aws-ecr-image-scanner-linux && \
mv aws-ecr-image-scanner-linux /usr/local/bin/aws-ecr-image-scanner
```

## Usage
```shell
aws-ecr-image-scanner scan --repo < ECR REPOSITORY NAME > --tag < IMAGE TAG > --severity < SEVERITY > 
```

### Example:
```
aws-ecr-image-scanner scan --repo sample-test --tag latest --severity critical,high,medium
```

### Flags
```shell
--help:      Show context-sensitive help.
--repo:      Repository Name
--tag:       Image Tag
--severity:  comma separated multiple choice, options: critical/high/medium/low/informational/all
--max-retry: [OPTIONAL] [DEFAULT: 5] Define max retry attempts to get ecr scan status, Used for increasing delay timeout. 1 retry =~ 5 seconds. first retry starts from 2 

```


### Output
```shell

STATUS: waiting to get scan status...

STATUS: ECR Image Scan Completed ..!!!

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
### Error Outputs and Solutions
1.
```shell
STATUS: waiting to get scan status...
ERROR:  ResourceNotReady: exceeded wait attempts
```
#### Solution
specify ```--max-retry``` in command and specify the value > 5

2.
```shell
STATUS: waiting to get scan status...
ERROR:  ResourceNotReady: exceeded wait attempts
ERROR:  ImageNotFoundException: The image with imageId {imageDigest:'null', imageTag:'1.1'} does not exist within the repository with name 'sample-test' in the registry with id '12143546'
```

#### Solution
Enter correct Image Tag or Repo name