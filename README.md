# Exam SCS-C01

- [Incident Response](#Incident-Response)
- [Logging and Monitoring](#Logging-and-Monitoring)
- [Infrastructure Security](#Infrastructure-Security)
- [Identity and Access Management](#Identity-and-Access-Management)
- [Data Protection](#Data-Protection)
- [Appendix](#Appendix)

## Incident Response

### Given an AWS abuse notice, evaluate the suspected compromised instance or exposed access keys.

1. Given an AWS Abuse report about an EC2 instance, securely isolate the instance as part of a forensic investigation.

1. Analyze logs relevant to a reported instance to verify a breach, and collect relevant data.

1. Capture a memory dump from a suspected instance for later deep analysis or for legal compliance reasons.

### Verify that the Incident Response plan includes relevant AWS services.

1. Determine if changes to baseline security configuration have been made.

1. Determine if list omits services, processes, or procedures which facilitate Incident Response.

1. Recommend services, processes, procedures to remediate gaps.

### Evaluate the configuration of automated alerting, and execute possible remediation of security-related incidents and emerging issues.

1. Automate evaluation of conformance with rules for new/changed/removed resources.

1. Apply rule-based alerts for common infrastructure misconfigurations.

1. Review previous security incidents and recommend improvements to existing systems.

## Logging and Monitoring

### Design and implement security monitoring and alerting.

1. Analyze architecture and identify monitoring requirements and sources for monitoring statistics.

1. Analyze architecture to determine which AWS services can be used to automate monitoring and alerting.

1.  Analyze the requirements for custom application monitoring, and determine how this could be achieved.

1.  Set up automated tools/scripts to perform regular audits.

### Troubleshoot security monitoring and alerting.

1. Given an occurrence of a known event without the expected alerting, analyze the service functionality and configuration and remediate.

1. Given an occurrence of a known event without the expected alerting, analyze the permissions and remediate.

1.  Given a custom application which is not reporting its statistics, analyze the configuration and remediate.

1.  Review audit trails of system and user activity.

### Design and implement a logging solution.

1.  Analyze architecture and identify logging requirements and sources for log ingestion.

1. Analyze requirements and implement durable and secure log storage according to AWS best practices.

1.  Analyze architecture to determine which AWS services can be used to automate log ingestion and analysis.

### Troubleshoot logging solutions.

1.  Given the absence of logs, determine the incorrect configuration and define remediation steps.

1. Analyze logging access permissions to determine incorrect configuration and define remediation steps.

1.  Based on the security policy requirements, determine the correct log level, type, and sources.

## Infrastructure Security

### Design edge security on AWS.

1. For a given workload, assess and limit the attack surface.

1. Reduce blast radius (e.g. by distributing applications across accounts and regions).

1.  Choose appropriate AWS and/or third-party edge services such as WAF, CloudFront and Route 53 to protect against DDoS or filter application-level attacks.

1.  Given a set of edge protection requirements for an application, evaluate the mechanisms to prevent and detect intrusions for compliance and recommend required changes.

1.  Test WAF rules to ensure they block malicious traffic.

### Design and implement a secure network infrastructure.

1. Disable any unnecessary network ports and protocols.

1. Given a set of edge protection requirements, evaluate the security groups and NACLs of an application for compliance and recommend required changes.

1.  Given security requirements, decide on network segmentation (e.g. security groups and NACLs) that allow the minimum ingress/egress access required.

1.  Determine the use case for VPN or Direct Connect.

1.  Determine the use case for enabling VPC Flow Logs.

1.  Given a description of the network infrastructure for a VPC, analyze the use of subnets and gateways for secure operation.

### Troubleshoot a secure network infrastructure.

1. Determine where network traffic flow is being denied.

1. Given a configuration, confirm security groups and NACLs have been implemented correctly.

### Design and implement host-based security.

1. Given security requirements, install and configure host-based protections including Inspector, SSM.

1. Decide when to use host-based firewall like iptables.

1. Recommend methods for host hardening and monitoring.

## Identity and Access Management

### Design and implement a scalable authorization and authentication system to access AWS resources.

1. Given a description of a workload, analyze the access control configuration for AWS services and make recommendations that reduce risk.

1. Given a description how an organization manages their AWS accounts, verify security of their root user. • Given your organization’s compliance requirements, determine when to apply user policies and resource policies.

1. Within an organization’s policy, determine when to federate a directory services to IAM.
 
1. Design a scalable authorization model that includes users, groups, roles, and policies.

1. Identify and restrict individual users of data and AWS resources.

1. Review policies to establish that users/systems are restricted from performing functions beyond their responsibility, and also enforce proper separation of duties.

### Troubleshoot an authorization and authentication system to access AWS resources.

1. Investigate a user’s inability to access S3 bucket contents.

1. Investigate a user’s inability to switch roles to a different account.

1. Investigate an Amazon EC2 instance’s inability to access a given AWS resource.

## Data Protection

### Design and implement key management and use.

1. Analyze a given scenario to determine an appropriate key management solution.

1. Given a set of data protection requirements, evaluate key usage and recommend required changes.

1. Determine and control the blast radius of a key compromise event and design a solution to contain the same.

### Troubleshoot key management.

1. Break down the difference between a KMS key grant and IAM policy.

1. Deduce the precedence given different conflicting policies for a given key.

1. Determine when and how to revoke permissions for a user or service in the event of a compromise.

### Design and implement a data encryption solution for data at rest and data in transit.

1. Given a set of data protection requirements, evaluate the security of the data at rest in a workload and recommend required changes.

1. Verify policy on a key such that it can only be used by specific AWS services.

1. Distinguish the compliance state of data through tag-based data classifications and automate remediation.

1. Evaluate a number of transport encryption techniques and select the appropriate method (i.e. TLS, IPsec, client-side KMS encryption).

## Appendix

### Key Tools and Technologies

1. AWS CLI

1. AWS SDK

1. AWS Management Console

1. Network analysis tools (packet capture and flow captures)

1. SSH/RDP

1. Signature Version 4

1. TLS

1. Certificate management 

1. Infrastructure as code (IaC)

### AWS Services and Features

1. AWS Audit Manager

1. AWS CloudTrail

1. Amazon CloudWatch

1. AWS Config

1. AWS Organizations

1. AWS Systems Manager

1. AWS Trusted Advisor

1. Amazon Detective

1. AWS Firewall Manager

1. AWS Network Firewall

1. AWS Security Hub

1. AWS Shield

1. Amazon VPC
	* VPC endpoints

	* Network ACLs

	* Security groups

1. AWS WAF

1. AWS Certificate Manager (ACM)

1. AWS CloudHSM

1. AWS Directory Service

1. Amazon GuardDuty

1. AWS Identity and Access Management (IAM)

1. Amazon Inspector

1. AWS Key Management Service (AWS KMS)

1. Amazon Macie

1. AWS Single Sign-On

### Out-of-scope Services and Features

1. Application development services

1. IoT services

1. Machine learning (ML) services

1. Media services

1. Migration and transfer services
