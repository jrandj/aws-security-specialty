# Exam SCS-C01

- [Incident Response](#Incident-Response)
- [Logging and Monitoring](#Logging-and-Monitoring)
- [Infrastructure Security](#Infrastructure-Security)
- [Identity and Access Management](#Identity-and-Access-Management)
- [Data Protection](#Data-Protection)
- [Appendix](#Appendix)
- [Practise Questions](#Practise-Questions)

## Incident Response

### Given an AWS abuse notice, evaluate the suspected compromised instance or exposed access keys.

1. Given an AWS Abuse report about an EC2 instance, securely isolate the instance as part of a forensic investigation.

    * The AWS Trust & Safety Team may send an abuse report to the security contact on your account. The notice should be reviewed to see what content or activity was reported. Logs that implicate abuse are included along with the abuse report. You will need to reply to the report to explain how you are preventing the abusing activity from recurring. You can also reply to obtain more information.

    * The following steps are recommended if notified of a potential security anomaly on an EC2 instance:
        * Capture  the  metadata  from  the  Amazon  EC2  instance,  before  you  make  any  changes  to  your environment.
        * Protect  the  Amazon  EC2  instance  from  accidental  termination  by  enabling  termination  protection  for the  instance.
        * Isolate  the  Amazon  EC2  instance  by  switching  the  VPC  Security  Group.  However,  be  aware  of  VPC connection  tracking  and  other  containment  techniques.
        * Detach  the  Amazon  EC2  instance  from  any  AWS  Auto  Scaling  groups.
        * Deregister  the  Amazon  EC2  instance  from  any  related  Elastic Load Balancing  service.
        * Snapshot  the  Amazon  EBS  data  volumes  that  are  attached  to  the  EC2  instance  for  preservation  and follow-up  investigations.
        * Tag  the  Amazon  EC2  instance  as  quarantined  for  investigation,  and  add  any  pertinent  metadata,  such as  the  trouble  ticket  associated  with  the  investigation.

1. Analyze logs relevant to a reported instance to verify a breach, and collect relevant data.

    * Logs come in many forms, such as CloudTrail, CloudWatch Logs, VPC flow logs, Windows events, Linux syslog logs, and other application or software specific logs. They contain information about activity occurring within your account such as logs of API actions and infrastructure events.

    * All logs should be collected centrally, and automatically analysed to detect anomalies and indicators of unauthorised activity.

    * Automation should be used to investigate and remediate events as this reduces human effort and error, and enables you to scale investigation capabilities.

    * Alerts should be configured so that they can be actioned by the incident response team. Amazon GuardDuty and AWS Security Hub can be configured to send alerts.

1. Capture a memory dump from a suspected instance for later deep analysis or for legal compliance reasons.

    * Different tools will be required depending on the operating system of the EC2 instance. The tools can be used by accessing the instance via SSH or RDP.

### Verify that the Incident Response plan includes relevant AWS services.

1. Determine if changes to baseline security configuration have been made.

    * Amazon Machine Images (AMIs) provide an initial configuration for an Amazon EC2 instance, which includes the Windows OS and optional customer-specific customizations, such as applications and security controls.

    * Patch Manager is a capability of AWS Systems Manager, which provides predefined patch baselines for each of the operating systems supported by Patch Manager.

    * AWS Config is a service that enables you to assess, audit, and evaluate the configurations of your AWS resources. Config continuously monitors and records your AWS resource configurations and allows you to automate the evaluation of recorded configurations against desired configurations. 

1. Determine if list omits services, processes, or procedures which facilitate Incident Response.

    * AWS offers many services that can be of assistance in an IRP. These include:
        * **AWS Shield:** Provides a managed service offering DDoS protection to applications running in AWS. AWS Shield Standard is free and AWS Shield Advanced costs additional.
        * AWS WAF: Widely used with AWS Shield as it helps protect your layer 7 application-level traffic. AWS WAF Classic allows the creation of basic rules, and AWS WAF which offers more features.
        * **AWS Firewall Manager:** Provides a way to simplify administration and maintenance tasks for AWS WAF, AWS Shield, and Amazon VPC security groups across multiple accounts and resources. Requires AWS account as an owner or member of an AWS organization, an IAM entity that can perform as an administrator role to activate it, and it AWS Config must be configured.
        * **AWS Config:** Tracks and records changes to AWS resources.

    * AWS logging services include:
        * **AWS CloudTrail:** The most commonly used and effective tool for security events. It logs commands issued through AWS services.
        * **Amazon CloudWatch Logs:** Monitors, stores, and provides access to logs from EC2 instances, Route 53, and other AWS resources.

    * AWS services for log analysis include:
        * **Amazon Athena:** Query your log files in S3 using standard SQL queries.
        * **Amazon EMR:** Processes large amounts of data quickly using open-source tools like Apache Spark and Apache Hive.
        * **Amazon Kinesis:** Allows you to easily collect, process, and analyse real-time data. This permits you to read your log data as it comes in to alert quickly on new information and gather timely insights.

    * AWS services for visualisation of your environment include:
        * **Amazon GuardDuty:** A threat detection service that will continuously monitor your accounts and resources for malicious activity and unauthorised behaviour by utilising machine learning, anomaly detection, and integrated threat intelligence. A good tool to give you a quick dashboad glance of any findings based on AWS CloudTrail Logs, Amazon VPC flow logs, and DNS logs.
        * **AWS Security Hub:** AWS Security Hub is considered a single pane-of-glass service and will give you a comprehensive view of high-priority security alerts, configuration, and compliance status across all of your AWS accounts. It can aggregate, organise, and prioritize security alerts and findings from services such as Amazon GuardDuty, Amazon Macie, Amazon Inspector, AWS IAM, AWS Firewall Manager, and even services offered by the AWS Partner Solutions. AWS Security Hub integrates with Amazon Detective to allow for further investigation into events and compliance alerts.
        * **Amazon Detective:** Amazon Detective allows you to easily analyse, investigate, and identify the RCA of a potential security event or suspicious activity. Detective collects log data from your AWS resources and, like GuardDuty, utilizes machine learning, statistical analysis, and graph theory to build a set of data for event investigations.
        * **Amazon Macie:** Amazon Macie is a service AWS offers that takes advantage of machine learning to discover and classify sensitive data in AWS. Macie can discover personally identifiable information (PII) or intellectual property. It provides you with a dashboard and alerts to give visibility into whether this data is being accessed or moved.

1. Recommend services, processes, procedures to remediate gaps.

    * The most common preventative actions for incidents are around securing AWS access keys, utilising MFA devices, and properly configuring Amazon EC2 security groups. The ones not everyone knows about are utilizing perfect forward secrecy with AWS ALBs, AWS API Gateway throttling and caching abilities, and using AWS Systems Manager to perform operational and security operations on AWS resources.

### Evaluate the configuration of automated alerting, and execute possible remediation of security-related incidents and emerging issues.

1. Automate evaluation of conformance with rules for new/changed/removed resources.

    * AWS Config rules help you evaluate the configuration settings of your AWS resources.  AWS Config rules enforce specific compliance checks and controls across your resources. AWS Config rules can include:
        * **Encrypted-volumes:** Check if any EBS volumes that are attached to an EC2 instance are encrypted.
        * **Rootaccount-mfa-enabled:** Checks whether the root account of your AWS account requires multifactor authentication for console sign-in.
        * **Iam-password-policy:** Checks whether the account password policy for IAM users meets the specified requirements.
        * **rds-instance-public-access-check:** Checks whether the Amazon Relational Database Service instances are not publicly accessible.

    * While AWS Config managed rules are very helpful for a variety of compliance needs, you are given the flexibility to create your own custom rules and add them to AWS Config.  You associate each custom rule with an AWS Lambda function, which contains the logic that evaluates whether your AWS resources comply with the rule. When you associate this function with your rule, the rule invokes the function either in response to configuration changes or periodically. The function then evaluates whether your resources comply with your rule and sends its evaluation results to AWS Config. The Lambda function could also take actions to remediate the problem and make your resource compliant.

    * A conformance pack is a collection of AWS Config rules and remediation actions that can be easily deployed as a single entity in an account and a region or across an organization in AWS Organizations.

1. Apply rule-based alerts for common infrastructure misconfigurations.

    * An AWS Lambda function can provide an alert based on an AWS Config rule.

1. Review previous security incidents and recommend improvements to existing systems.

    * The most common preventative actions for incidents are around securing AWS access keys, utilising MFA devices, and properly configuring Amazon EC2 security groups. The ones not everyone knows about are utilizing perfect forward secrecy with AWS ALBs, AWS API Gateway throttling and caching abilities, and using AWS Systems Manager to perform operational and security operations on AWS resources.

## Logging and Monitoring

### Design and implement security monitoring and alerting.

1. Analyze architecture and identify monitoring requirements and sources for monitoring statistics.

    * AWS CloudWatch is a highly scalable, region-specific monitoring service for AWS cloud resources and the applications you run on AWS. CloudWatch can provide real time metrics, alarms, and notifications. The broad spectrum of features supported by CloudWatch is shown below:
        <p align="center">
        <img src="/res/cloudwatch.JPG">
        </p>

     * Most AWS resources you create automatically publish metric data into CloudWatch, so you retrieve statistics based on these metrics. You can also publish your own custom metrics and retrieve statistics on these metrics as well. Note that EC2 does not provide a memory utilisation metric by default.

1. Analyze architecture to determine which AWS services can be used to automate monitoring and alerting.

    * AWS provides additional instance status data than the state (pending, running, stopping etc.) of an instance. This data can troubleshoot network connectivity, system power, software, and hardware issues on the host. These checks can be viewed in the console or using the CLI.

    * It is not sufficient to just have monitoring in place. You should have the ability to act on the alerts generated due to monitoring. This is done using CloudWatch alarms and AWS EventBridge (previously called CloudWatch Events). For notification purposes, CloudWatch provides integration with Amazon SNS, which gives you the ability to send notifications over e-mail, Short Message Service (SMS), a message to an SQS queue, etc.

    * The integration between CloudWatch and other AWS services and resources is shown below:
        <p align="center">
        <img src="/res/cloudwatch_integration.JPG">
        </p>

1.  Analyze the requirements for custom application monitoring, and determine how this could be achieved.

    * The PutMetricData API can be used to publish data points for particular metrics. If the metric does not exist, CloudWatch creates the metric. A custom application can consume this API to provide application monitoring.

    * By using the CloudWatch Logs agent, you can publish your operating system, application, and custom log files to Amazon CloudWatch Logs, where they will be stored in durable fashion for as long as you would like. You can also configure the CloudWatch agent to monitor the incoming log entries for any desired symbols or messages and to present the results as CloudWatch metrics. 

1.  Set up automated tools/scripts to perform regular audits.

    * This is done using CloudWatch alarms and AWS EventBridge (previously called CloudWatch Events). For notification purposes, CloudWatch provides integration with Amazon SNS, which gives you the ability to send notifications over e-mail, Short Message Service (SMS), a message to an SQS queue, etc.

### Troubleshoot security monitoring and alerting.

1. Given an occurrence of a known event without the expected alerting, analyze the service functionality and configuration and remediate.

1. Given an occurrence of a known event without the expected alerting, analyze the permissions and remediate.

1.  Given a custom application which is not reporting its statistics, analyze the configuration and remediate.

1.  Review audit trails of system and user activity.

    * CloudTrail logs calls to the AWS APIs for most services. It does not log events such as SSH or RDP access to an EC2 instance in AWS. Logged data is metadata around API calls. For example, the identity of the API caller, the time, the source IP, the request parameters, and the response.

    * Event logs are sent to an S3 bucket every 5 minutes with up to a 15-minute delay. Notifications can be configured based on the log contents. The retention of the log files is managed in S3. Logging can be aggregated across regions and across accounts.

    * Log file integrity validation includes SHA-256 hashing and RSA for digital signing. Log files are delivered with a digest file that can be used to validate the integrity of the log file.

    * CloudTrail logs need to be secured as they may contain PII such as usernames and emails. Only security personnel should be granted administrator access to CloudTrail using IAM. Access to the S3 bucket containing the logs should be controlled using bucket policies, and MFA should be required for delete on those objects. Lifecycle rules should be used to move log files to Glacier or to delete them.

    * By default CloudTrail logs are encrypted by SSE-S3 even if there is no S3 bucket level encryption.

    * Auditors are given access to CloudTrail logs through the AWSCloudTrailReadOnlyAccess IAM Policy.

    * The format of VPC flow logs is shown below:
        <p align="center">
        <img src="/res/vpc_flow_log.JPG">
        </p>

    * Note that VPC flow logs excludes certain traffic such as DNS (unless you use your own DNS server), Windows license traffic, instance metadata traffic, DHCP traffic, and traffic to the reserved IP address for the default VPC router.

### Design and implement a logging solution.

1.  Analyze architecture and identify logging requirements and sources for log ingestion.

    * Log sources include:
        * **Account Level:** These log sources capture platform-wide activity. These should always be enabled. Examples include AWS CloudTrail and AWS Config.
        * **AWS Service Logs:** These represent log data that is generated by resources or the AWS service owning the resource. Decision on enablement is based on business need, regulatory requirement, or your internal company security policy. In general, these logs can be linked to an application or workload. Examples include ELB access logs, Amazon S3 access logs, and Amazon CloudFront access logs.
        * **Host-based Logs:** These refer to log sources that are not generated by AWS and commonly are generated from with-in a specific resource, such as an EC2 instance. Examples include syslog, service logs, event logs, application logs such as NGINX, Apache, or IIS logs.

1. Analyze requirements and implement durable and secure log storage according to AWS best practices.

    * AWS CloudTrail logs are delivered to an S3 bucket. As AWS customers often use many AWS accounts for running their workloads, best practice is to create and use an AWS account as a log archive account. All other AWS accounts will have AWS CloudTrail enabled and deliver log files to an S3 bucket in this log archive account. This provides several benefits:
        * By logging to a dedicated and centralized Amazon S3 bucket, you can enforce strict security controls, access, and segregation of duties.
        * You can capture logs from ephemeral AWS accounts, which are created and deleted repeatedly.
        * You can control access to log files. While AWS CloudTrail from other accounts delivers all the logs to the S3 bucket in the log archive account, by default, no principal (IAM user/role, etc.) in the accounts themselves have access to the log files in the log archive account. Access to log files can be enabled explicitly using IAM roles and IAM access policies by letting principals from other accounts call the AssumeRole API to assume a role, which can provide read-only access to the logs

    * By default, the log files delivered by AWS CloudTrail to your bucket are encrypted by Amazon server-side encryption with Amazon S3–managed encryption keys (SSE-S3). AWS CloudTrail also lets you use server-side encryption with AWS KMS (SSE-KMS) managed keys. To use this option, you first must create a CMK within the AWS KMS. Using SSE-KMS has several advantages:
        * You are in complete control of the customer master keys you create within AWS KMS. You can choose to rotate these CMKs at any point, which is considered a best practice.
        * You can control who can use the key for encrypting and decrypting AWS CloudTrail’s log files.
        * You can use a single CMK to encrypt and decrypt log files for multiple accounts across all regions.
        * You have enhanced security. A user must have S3 read permissions for the bucket that contains the log files, and the user must also have a policy or role applied that allows decrypt permissions by the CMK policy.

    * You should also ensure that you implement least privilege access to the S3 buckets that store the CloudTrail log files. This is done by reviewing the bucket policy and enabling MFA on any delete operation performed on an object within this bucket.

    * CloudTrail log file integrity validation is enabled by default.

1.  Analyze architecture to determine which AWS services can be used to automate log ingestion and analysis.

    * AWS logging services include:
        * **AWS CloudTrail:** The most commonly used and effective tool for security events. It logs commands issued through AWS services.
        * **Amazon CloudWatch Logs:** Monitors, stores, and provides access to logs from EC2 instances, Route 53, and other AWS resources.

    * AWS services for log analysis include:
        * **Amazon Athena:** Query your log files in S3 using standard SQL queries.
        * **Amazon EMR:** Processes large amounts of data quickly using open-source tools like Apache Spark and Apache Hive.
        * **Amazon Kinesis:** Allows you to easily collect, process, and analyse real-time data. This permits you to read your log data as it comes in to alert quickly on new information and gather timely insights.

    * AWS services for visualisation of your environment include:
        * **Amazon GuardDuty:** A threat detection service that will continuously monitor your accounts and resources for malicious activity and unauthorised behaviour by utilising machine learning, anomaly detection, and integrated threat intelligence. A good tool to give you a quick dashboard glance of any findings based on AWS CloudTrail Logs, Amazon VPC flow logs, and DNS logs.
        * **AWS Security Hub:** AWS Security Hub is considered a single pane-of-glass service and will give you a comprehensive view of high-priority security alerts, configuration, and compliance status across all of your AWS accounts. It can aggregate, organise, and prioritize security alerts and findings from services such as Amazon GuardDuty, Amazon Macie, Amazon Inspector, AWS IAM, AWS Firewall Manager, and even services offered by the AWS Partner Solutions. AWS Security Hub integrates with Amazon Detective to allow for further investigation into events and compliance alerts.
        * **Amazon Detective:** Amazon Detective allows you to easily analyze, investigate, and identify the RCA of a potential security event or suspicious activity. Detective collects log data from your AWS resources and, like GuardDuty, utilizes machine learning, statistical analysis, and graph theory to build a set of data for event investigations.
        * **Amazon Macie:** Amazon Macie is a service AWS offers that takes advantage of machine learning to discover and classify sensitive data in AWS. Macie can discover personally identifiable information (PII) or intellectual property. It provides you with a dashboard and alerts to give visibility into whether this data is being accessed or moved.

### Troubleshoot logging solutions.

1.  Given the absence of logs, determine the incorrect configuration and define remediation steps.

    * If CloudTrail logs are not appearing in S3, first check if CloudTrail is enabled. Also check that the correct S3 bucket name is provided and that the S3 Bucket Policy is correct.

    * S3 and Lambda Data Events are high volume, so they are not enabled by default as they also incur added costs.

1. Analyze logging access permissions to determine incorrect configuration and define remediation steps.

    * Always check that IAM users have the correct permissions to allow them to do what they need to do. This includes IAM permissions as well as resource level permissions.

    * CloudWatch Logs require an agent to be installed and running on an EC2 instance.

    * For EventBridge the Event Target needs the correct permissions to take whatever action it needs to. For example, if Lambda is expected to terminate unauthorised instances it will need the permission for termination.

1.  Based on the security policy requirements, determine the correct log level, type, and sources.

    * You can choose from OFF, ALL, ERROR, or FATAL. No event types log when set to OFF and all event types do when set to ALL. For ERROR and FATAL, see the following table.

## Infrastructure Security

### Design edge security on AWS.

1. For a given workload, assess and limit the attack surface.

    * Attack surface can be limited by minimising the number of components, libraries, and externally consumable services in use. You can find many hardening and security configuration guides for common operating systems and server software. 

    * In EC2 you can create your own patched and hardened AMIs to meet specific security requirements for your organisation. Note that these are effective at the point in time in which they were created, they would need to be dynamically updated with Systems Manager.

1. Reduce blast radius (e.g., by distributing applications across accounts and regions).

    * The blast radius is the maximum impact that may be sustained in the event of a system failure.

    * AWS provides fault isolation at the resource and request level as part of every AWS service. Fault isolation at the AZ level is achieved by deploying your services across multiple AZs, and fault isolation at the region level is achieved by deploying your services across multiple regions.

1.  Choose appropriate AWS and/or third-party edge services such as WAF, CloudFront and Route 53 to protect against DDoS or filter application-level attacks.

    * The attack surface can be minimised by restricting the number of entry points. A bastion host should be used with specific whitelisted IP addresses for onward connections to web servers, database servers etc.

    * The infrastructure can be setup to scale as needed.
    
    * Amazon CloudFront can block traffic based on specific countries (using whitelists or blacklists). You can also use Origin Access Identity to restrict access to your S3 bucket using CloudFront URLs. Route53 provides Alias Record Sets to redirect your traffic to an Amazon CloudFront distribution, or to a different Elastic Load Balancer with higher capacity E2 instances running WAFs or other security tools.

    * Alerts can be configured based on abnormal network traffic.

    * Amazon Shield provides a DDoS protection capability.

1.  Given a set of edge protection requirements for an application, evaluate the mechanisms to prevent and detect intrusions for compliance and recommend required changes.

1.  Test WAF rules to ensure they block malicious traffic.

### Design and implement a secure network infrastructure.

1. Disable any unnecessary network ports and protocols.

    * When you create a VPC, an Amazon DNS server is automatically created. This is used for hostname resolution for instances in your VPC. If preferred, you can disable this and create a new DHCP option to set your own DNS server.

    * VPCs can get complicated in large numbers, with VPC peering required for communication between them. A Transit Gateway is a solution to this problem, as any VPC connected to the gateway can communicate with any other VPC that is also connected.

    * Transitive VPC peering is not supported.

1. Given a set of edge protection requirements, evaluate the security groups and NACLs of an application for compliance and recommend required changes.

1.  Given security requirements, decide on network segmentation (e.g., security groups and NACLs) that allow the minimum ingress/egress access required.

    * For optimal use of EC2 resources, terminate TLS/SSL on the Elastic Load Balancer (ELB). If there is a requirement to ensure traffic is encrypted all the way to the ECT instance, terminate TLS/SSL on the EC2 instance. If you need to terminate traffic at the EC2 instances, then you will need to use the TCP protocol with a Network or Classic Load Balancer (Application Load Balancer is HTTP/HTTPS only).

1.  Determine the use case for VPN or Direct Connect.

    * AWS Direct Connect is a networking service that provides an alternative to using the internet to connect to AWS. Using Direct Connect, data that would have previously been transported over the internet is delivered through a private network connection between your facilities and AWS. A VPN connectivity option can be used if traffic going over the internet is not a constraint.

    * A VPC Gateway Endpoint enables you to privately connect your VPC to supported AWS services powered by PrivateLink without requiring an internet gateway, NAT device, VPN connection, or AWS Direct Connect connection.

1.  Determine the use case for enabling VPC Flow Logs.

    * VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. Flow log data is stored using Amazon CloudWatch Logs. After you have created a flow log, you can view and retrieve its data in Amazon CloudWatch Logs.

    * You cannot enable flow logs for VPCs that are peered with your VPC unless the peer VPC is in your account. You cannot tag a flow log. Once you have created a flow log, you cannot change its configuration.

    * Not all IP traffic is monitored. For example, instances contacting the Amazon DNS server (if you used your own DNS server that would be logged), DHCP traffic etc.

1.  Given a description of the network infrastructure for a VPC, analyze the use of subnets and gateways for secure operation.

    * A VPC is a logical datacentre in AWS. It consists of IGWs, Route Tables, Network Access Control Lists, Subnets, and Security Groups. 1 Subnet corresponds to 1 Availability Zone.

    * A NAT instance enables instances in a private subnet to initiate outbound IPv4 traffic to the internet or other AWS services but prevent the instances from receiving inbound traffic initiated on the internet.

    * When creating a NAT instance, you must disable the Source/Destination Check on the instance. NAT instances must be in a public subnet, and there must be a route out of the private subnet to the NAT instance. The amount of traffic that a NAT instance can support depends on the instance size. NAT instances also sit behind a security group.

    * NAT Gateways are much preferred to NAT instances. They automatically scale, are more secure, patch automatically (but no SSH access) etc. They are not associated with security groups.
    
    * A NAT is used to provide internet traffic to EC2 instances in private subnets. A Bastion is used to securely administer E2 instances (using SSH or RDP) in private subnets. In Australia they are called jump boxes.

    * An Internet Gateway allows instances with public IPs to access the internet. A NAT Gateway (or NAT instance) allows instances with no public IPs to access the internet.

    * Remember that a Security Group is the firewall of EC2 instances, and a NACL is the firewall of the VPC Subnets. An example architecture is shown below to illustrate this:
        <p align="center">
        <img src="/res/network.JPG">
        </p>

### Troubleshoot a secure network infrastructure.

1. Determine where network traffic flow is being denied.

    * Check routing tables, Security Groups, and NACLs. VPC Flow Logs will show allow and deny messages useful for troubleshooting.

    * Remember that NACLs are stateless so you need to configure both inbound and outbound rules. Security Groups are stateful, so you only need 1 rule. 

1. Given a configuration, confirm security groups and NACLs have been implemented correctly.

    * A VPC automatically comes with a default NACL, and by default it allows all inbound and outbound traffic. You can create custom NACLs. By default, each custom NACL denies all inbound and outbound traffic until you add rules.

    * Each subnet in your VPC must be associated with a NACL. If you do not explicitly associate a subnet with a NACL, the subnet is automatically associated with the default NACL.

    * You can associate a NACL with multiple subnets. However, a subnet can be associated with only one NACL at a time. When you associate a NACL with a subnet, the previous association is removed.

    * NACLs contain a numbered list of rules that is evaluated in order, starting with the lowest numbered rule. NACLs have separate inbound and outbound rules, and each rule can either allow or deny traffic. NACLs are stateless. Responses to allowed inbound traffic are subject to the rules for outbound traffic (and vice versa.).

    * IP addresses can be blocked using NACLs but not Security Groups.

### Design and implement host-based security.

1. Given security requirements, install and configure host-based protections including Inspector, SSM.

1. Decide when to use host-based firewall like iptables.

1. Recommend methods for host hardening and monitoring.

    * Dedicated instances and dedicated hosts have dedicated hardware. Dedicated instances are charged by the instance, and dedicate hosts are charged by the host. If you have specific regulatory requirements or licensing conditions, choose dedicated hosts. Dedicated instances may share the same hardware with other AWS instances from the same account that are not dedicated.

    * EC2 runs on a mixture of Nitro and Xen hypervisors. Eventually all EC2 will be based on Nitro. Both hypervisors can have guest operating systems running either as Paravirtualisation (PV) or using Hardware Virtual Machine (HVM).

    * HVM is preferred over PV where possible. PV is isolated by layers with the guest OS on layer 1 and applications on layer 3. Only AWS administrators have access to hypervisors. All storage memory and RAM is scrubbed before assigned to an EC2 instance.

   * Security products from third party vendors can be purchased on the AWS Marketplace. This includes firewalls, hardened operating systems, WAF's, antivirus, security monitoring etc. There are various revenue models for these products.

## Identity and Access Management

### Design and implement a scalable authorization and authentication system to access AWS resources.

1. Given a description of a workload, analyze the access control configuration for AWS services and make recommendations that reduce risk.

    * IAM Access Analyzer helps you identify the resources in your organization and accounts, such as Amazon S3 buckets or IAM roles, shared with an external entity. For each instance of a resource shared outside of your account, Access Analyzer generates a finding. Findings include information about the access and the external principal granted to it.

    * Access Analyzer analyzes only policies applied to resources in the same AWS Region where it is enabled. To monitor all resources in your AWS environment, you must create an analyzer to enable Access Analyzer in each Region where you are using supported AWS resources.

1. Given a description how an organization manages their AWS accounts, verify security of their root user.

    * The root user is the first and only identity that exists when you create an AWS account. You login by using the email address you signed up for that account with and the password you set. The root user has a password to access the console, and optionally access keys (access key IDs and secret access keys) for accessing the APIs. The AWS account root user has full access to everything in your account, and it can even close the account.

    * The following best practises are recommended for the root account:
        * Remove access keys (delete or deactivate). Access keys cannot have MFA devices linked to them, so if you were to leave them accidentally somewhere public then anyone can immediately use them.
        * A virtual or hardware (hardware is preferred) MFA device should be added to your root user to provide an additional layer of authentication. Note that if someone attempts to use the recovery process to gain access to the root account the security of the email address and phone number associated with the account becomes important.
        * Don't use the root user. Only a few tasks require using the root user. These tasks include closing your AWS account, viewing certain tax invoices, restoring IAM user permissions, changing or cancelling your AWS Support plan, registering as a seller in the Reserved Instance Marketplace, configuring an Amazon S3 bucket to enable MFA Delete, editing or deleting an Amazon S3 bucket policy that includes an invalid VPC ID, or to signing up for GovCloud.
        * Use either individual IAM users or a centralised identity provider (such as using IAM federation and AWS SSO) instead of root.
        * Configure AWS account alternate contacts.
        * Setup a CloudFormation SNS topic and CloudWatch event to send a notification based on root user logins.

    * If the root user has left, several tasks are required. A new root user password with a strong password policy should be created. The previous MFA should be deleted and recreated. Any root user Access Key ID and Secret Access Key should be deleted. Other user accounts should be checked and deleted if not legitimate.

1. Given your organization’s compliance requirements, determine when to apply user policies and resource policies.

    * A policy is an object in AWS that, when associated with an identity or resource, defines their permissions. When you create a permissions policy to restrict access to a resource, you can choose an identity-based policy or a resource-based policy.

    * Identity-based policies are attached to an IAM user, group, or role. These policies let you specify what that identity can do (its permissions).

    * Resource-based policies are attached to a resource. For example, you can attach resource-based policies to Amazon S3 buckets, Amazon SQS queues, VPC endpoints, and AWS Key Management Service encryption keys.

    * For a request to which only permissions policies apply, AWS first checks all policies for a Deny. If one exists, then the request is denied. Then AWS checks for each Allow. If **at least one policy** statement allows the action in the request, the request is allowed. It does not matter whether the Allow is in the identity-based policy or the resource-based policy.

    * This logic applies **only when** the request is made within a single AWS account. For requests made from one account to another, the requester in Account A must have an identity-based policy that allows them to make a request to the resource in Account B. Also, the resource-based policy in Account B must allow the requester in Account A to access the resource. There **must be policies in both accounts that allow** the operation, otherwise the request fails.

1. Within an organization’s policy, determine when to federate a directory services to IAM.

    * Identity federation is a system of trust between two parties for the purpose of authenticating users and conveying information needed to authorize their access to resources. In this system, an identity provider (IdP) is responsible for user authentication, and a service provider (SP), such as a service or an application, controls access to resources. By administrative agreement and configuration, the SP trusts the IdP to authenticate users and relies on the information provided by the IdP about them. After authenticating a user, the IdP sends the SP a message, called an assertion, containing the user's sign-in name and other attributes that the SP needs to establish a session with the user and to determine the scope of resource access that the SP should grant. Federation is a common approach to building access control systems which manage users centrally within a central IdP and govern their access to multiple applications and services acting as SPs.

    * You can use AWS SSO for identities in the AWS SSO’s user directory, your existing corporate directory, or external IdP. With AWS SSO, you can assign permissions based on the group membership in your IdP’s directory, and then control the access for your users by simply modifying users and groups in the IdP.

    * You can enable federated access to AWS accounts using AWS Identity and Access Management (IAM). The flexibility of the AWS IAM allows you to enable a separate SAML 2.0 or an Open ID Connect (OIDC) IdP for each AWS account and use federated user attributes for access control.

    * You can add federation support to your customer-facing web and mobile applications using Amazon Cognito. It helps you add user sign-up, sign-in, and access control to your mobile and web apps quickly and easily. Amazon Cognito scales to millions of users and supports sign-in with social identity providers, such as Apple, Facebook, Google, and Amazon, and enterprise identity providers via SAML 2.0.

    * After creating an Amazon Cognito user pool, in API Gateway, you must then create a COGNITO_USER_POOLS authoriser that uses the pool. The steps required are:
        * Create a new API or select an existing API in API Gateway.
        * From the main navigation pane, choose **Authorizers** under the specified API.
        * Under Authorizers, choose Create New Authorizer.
        * Configure the new authorizer to use the user pool. This requires selecting an authorizer name in **Name**, selecting the **Cognito** option, choosing a region under **Cognito User Pool**, selecting an available user pool from that region, selecting a **Token source** (type Authorization as the header name to pass the identity or access token that's returned by Amazon Cognito), and finally creating the authorizer using **Create**.

    * Once the authoriser is created the authoriser can be used on methods. The steps required are:
        * Choose (or create) a method on your API.
        * Choose **Method Request**.
        * Under **Settings**, choose the pencil icon next to **Authorization**.
        * Choose one of the available **Amazon Cognito user pool authorizers** from the drop-down list.
        * If using an identity token, leave the **OAuth Scopes** option unspecified. If needed choose **Integration Request** to add the `context.authorizer.claims` expressions in a body-mapping template to pass the specified identity claims property from the user pool to the backend.
        * If using an access token, type one or more full names of scope into **OAuth Scopes** that has been configured when the Amazon Cognito user pool was created.

    * With the COGNITO_USER_POOLS authorizer, if the OAuth Scopes option isn't specified, API Gateway treats the supplied token as an identity token and verifies the claimed identity against the one from the user pool. Otherwise, API Gateway treats the supplied token as an access token and verifies the access scopes that are claimed in the token against the authorization scopes declared on the method.

    * Instead of using the API Gateway console, you can also enable an Amazon Cognito user pool on a method by specifying an OpenAPI definition file and importing the API definition into API Gateway.

    * Within the context of federation, the AWS Security Toke Service (STS) provides a SAML token after authenticating against an LDAP directory (such as AD). Once we have the token, any attempt to access an AWS resource will go via IAM first to check the token.

1. Design a scalable authorization model that includes users, groups, roles, and policies.

    * You can combine Attribute-Based Access Control (ABAC) using AWS IAM with a standard Active Directory Federation Services (AD FS) connected to Microsoft Active Directory. With ABAC in conjunction with Amazon S3 policies, you can authorize users to read objects based on one or more tags that are applied to S3 objects and to the IAM role session of your users based on attributes in Active Directory.

    * The benefits of ABAC in this solution are that you need to provision fewer IAM roles and that your S3 objects can have different prefixes without the need to explicitly add all those prefixes to your IAM permissions policies like you would with RBAC.

    * Once configured, the authentication flow would be:
        * User authenticates to your IdP — AD FS in this case.
        * The IdP queries the identity store — Active Directory in this case — to retrieve the tag values for the authenticated user.
        * The identity store supplies the tag values to AWS — together with other information — in a SAML token.
        * IAM checks the trust policy to determine if the IdP is allowed to federate the user into the specified role.
        * Users can access the data directly or through another supported service using the credentials and in accordance with the permissions granted.

1. Identify and restrict individual users of data and AWS resources.

    * IAM is global and applies to all areas of AWS. IAM policies include:
        * **AWS Managed Policies:** Created and managed by AWS.
        * **Customer Managed Policies:** Customer managed policies that provide more precise control. 
        * **Inline Policies:** Policies that you can add directly to a single user, group, or role. These maintain a strict one-to-one relationship between a policy and an identity. They are deleted when you delete the identity.

    * S3 Bucket Policies are attached only to S3 buckets. They can be at the user level and specify what actions are allowed or denied on the bucket. They apply for S3 only.

    * S3 ACLs are a legacy access control mechanism that predates IAM. AWS recommend sticking to IAM policies and S3 bucket policies. However, if you need to apply policies on the objects themselves, then S3 ACLs can be used. These apply at the object level unlike bucket policies which apply at the bucket level.

    * To support the concept of least-privilege, a deny always overrides an allow where there are policy conflicts. A deny is also the default if there is no method specifying an allow.

    * The condition *aws:SecureTransport* can be used to ensure HTTPS is used when accessing an S3 bucket. Note that you do not need to use this when using cross-region replication as it uses HTTPS by default.

    * When using cross-region replication, delete markers are replicated but deleted versions of files are not. Versioning must be enabled on both buckets. It is possible to use cross-region replication between 2 AWS accounts. In this case, the IAM role must have permissions to replicate objects in the destination bucket. It is security best practise to have a separate AWS account with an S3 bucket and replicate CloudTrail buckets to that bucket with access only for auditors.

    * A pre-signed URL can be used to temporarily grant access an object. They are typically created via the SDK but can also be done using the CLI. The default length of time is 1 hour but it can be changed with the *--expires-in* argument followed by the number of seconds.

1. Review policies to establish that users/systems are restricted from performing functions beyond their responsibility and enforce proper separation of duties.

    * Separation of duties is a design principle where more than one person’s approval is required to conclude a critical task, and it is an important part of the AWS Well-Architected Framework.

    * As an example to show what is possible, an operator may require an approval for a shell session to an EC2 instance. An approval from AWS Systems Manager Change Manager is required and triggers an Automation runbook. This runbook adds a tag to the operator's IAM principal that allows it to start a shell in the specified targets and sends an SNS notification to the approver. By default, the operator needs to start the session within 10 minutes (although the period is configurable). After 10 minutes the tag is removed.

### Troubleshoot an authorization and authentication system to access AWS resources.

1. Investigate a user’s inability to access S3 bucket contents.

    * The following should be confirmed:
        * That the bucket policy is applied to the bucket as a permission.
        * That no overriding deny is occurring for the IAM policy.
        * That the policy allows access to all objects in the bucket by using the wildcard (e.g. `bucketname/*`).
        * That if the files have been uploaded by another AWS account then the account owner has provided a grant for your account to access the objects.
        * That KMS permissions are available if the bucket is encrypted.

1. Investigate a user’s inability to switch roles to a different account.

    * To use the AssumeRole API call with multiple accounts or cross-accounts, you must have a trust policy to grant permission to assume roles. As an example, user Bob_Account is required to assume a role Alice in Account_Alice.

    * The IAM policy for Bob_Account:
        ```JSON
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "PermissionToAssumeAlice",
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": "arn:aws:iam::Account_Alice:role/Alice"
                }
            ]
        }
        ```

    * The IAM policy for Alice_Account:
        ```JSON
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::ACCOUNT_Bob:user/Bob"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        ```

    * A similar concept applies for a Key Policy if requesting cross account access to KMS.

    * Note that if Account_Bob is part of an AWS Organizations, there might be a service control policy (SCP) restricting AssumeRole access with Account_Bob or Account_Alice. 

    * Note that if you are using role chaining (when you use a role to assume a second role), you might be using IAM credentials from a previous session.

1. Investigate an Amazon EC2 instance’s inability to access a given AWS resource.

    * If Lambda cannot perform an action (e.g., write to S3, log to CloudWatch), first check that the Lambda execution role has the correct permissions. If EventBridge or some other event source cannot invoke a Lambda function, double check that the Function policy allows it.

    * Some services have their own resource-based policies which can also impact who or what can access them (e.g., S3 Bucket Policies, Key Policies).

## Data Protection

### Design and implement key management and use.

1. Analyze a given scenario to determine an appropriate key management solution.

    * AWS Key Management Service (KMS) is a service for managing encryption keys that is used for both client side (optional) and server-side encryption with AWS. KMS only manages Customer Master Keys (CMKs) and it uses Hardware Security Modules (HSMs) to store the keys. A CMK is a representation (like a pointer) for the customer of the actual key material stored on the HSM devices. The CMK includes the alias, creation date, description, key state, and key material (either customer provided, or AWS provided). It can never be exported. 

    * Access to MKS CMKs is controlled using:
        * **Key Policy:** Add the root user, not the individual IAM users or roles.
        * **IAM Policies:** Define the allowed actions and the CMK ARN.

    * The key policy specifies who is allowed to use the CMK, and the IAM policy specifies if that user can make KMS API calls. Policy Conditions can be used to specify a condition within a Key Policy or IAM Policy for when a policy is in effect. KMS provides a set of predefined Condition Keys. Use `kms:ViaService` to allow or deny access to your CMK according to which service originated the request.

    * A Grant programmatically delegates the use of your CMK to a user in your own account or in another account. It provides temporary and granular permissions.

    * If you want to enable cross account access:
        * Enable access in the Key Policy for the account which owns the CMK.
        * Enable access to KMS in the IAM Policy for external account.

    * To setup a CMK:
        * Create an alias and description.
        * Choose material option.
        * Define key administrative permissions (IAM users/roles that can administer but not use the key through the KMS API).
        * Define key usage permissions (IAM users/roles that can use the key to encrypt and decrypt data).

    * To import your own key material:
        * Create a CMK with no material.
        * Download a public key (wrapping key) and import token.
        * Encrypt the key material.
        * Import the key material.

    * KMS supports symmetric and asymmetric keys. A symmetric key never leaves KMS unencrypted, so to use it you must call AWS KMS. For an asymmetric key pair, the private key never leaves KMS unencrypted, but the public key can be downloaded and used outside of KMS. The symmetric key is used for both encryption and decryption. The asymmetric public key is used for encryption, and the asymmetric private key is used for decryption. A symmetric key is recommended for most use cases as it is fast and efficient. An asymmetric key pair is required if you need users outside of AWS to encrypt data, as they can use the public key to encrypt. The private key of an asymmetric key pair can be used to sign messages and the public key can be used to verify signatures (using the 'Sign' and 'Verify' APIs).

    * Key types include:
        * **Customer-Managed CMKs:** CMKs in your account that you fully create, own, and manage. They can be used via the AWS KMS API directly to encrypt and decrypt data that is less than 4KB. Any data over 4KB must use what is called a data key. The data key is encrypted by the CMK but is exportable unlike the CMK.
        * **AWS-Managed CMKs:** CMKs in your account fully owned, managed, and used on your behalf by an AWS service integrated with AWS KMS. You do not have the ability to modify the key policy for these which means they cannot be used for cross-account access, and you do not have the ability to delete or rotate them.
        * **AWS-Owned CMKs:** a collection of CMKs that a particular service will create and own and are in use across many AWS accounts.

    * If you use your own key material you can delete key material without a 7-30 day wait. You will also have full control of the key. However, there is no automatic rotation.

    * Key rotation depends on the key types:
        * **Customer Managed CMKs:** Automatic rotation every 365 days but disabled by default. You can rotate manually. You need to update your applications or key alias to use the new CMK.
        * **Customer Managed (Imported Key Material):** No automatic rotation, you must rotate manually. You need to update your applications or key alias to use the new CMK.
        * **AWS Managed CMKs:** Automatically rotates every 3 years. You cannot rotate manually. AWS manages it and saves the old backing key.
    
    * You can use KMS to encrypt EBS volumes (including root device volumes), but you cannot use KMS to generate a public key and private key to log into EC2. You can import public keys into EC2 key pairs, but you cannot use EC2 key pairs to encrypt EBS volumes, you must use KMS or third-party applications or tools. You cannot use KMS with SSH for EC2 as you cannot export keys from KMS. You can do this with CloudHSM because you can export keys from CloudHSM.

    * You can copy AMIs from one region to another and make those copies encrypted, but you must use the keys in the destination region to do the encryption. You cannot copy KMS keys from one region to another.
 
    * To encrypt a root device volume, create an AMI. The initial AMI will be unencrypted, but you can then copy it and in doing so encrypt it. You can change encryption keys from Amazon managed to customer managed.

    * Multiple public keys can be attached to an EC2 instance. You can add roles to existing E2 instances.

    * You can view public keys in EC2 by going to `/home/ec2-users/.ssh/authorized_keys`. You can also view the public key using the E2 instance metadata. For example:
        ```shell
        curl http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key/
        ```

    * Deleting a key pair in the console will not delete it from the instance or the instances metadata. If you lose a key pair (public or private), simply take a snapshot of the EC2 instance, and then deploy it as a new instance. This will APPEND a new public key to `/home/ec2-users/.ssh/authorized_keys`. You can then go into that file and delete the outdated public keys.

    * A CMK alias can be used to change the CMK they are associated with at any time. These are useful in key rotation scenarios.

    * AWS KMS cannot utilise data keys directly to perform cryptographic operations via the API. A data key is created with the 'GenerateDataKey' API using the CMK specified in the API call. An encrypted version is returned using the 'GenerateDataKeyWithoutPlaintext' API call. The plaintext version of the data key will be used by an encryption algorithm specified by the service or library to convert plaintext data into ciphertext. Once the operation is complete, the plaintext data key is removed from memory. Decryption occurs using the encrypted data key.

    * KMS only manages CMKs, it does not manage data keys. A CMK never leaves the region that it was created and can only encrypt a maximum of 4kB of data. Data Keys can be used for larger object encryption.
    
    * A data key pair is similarly created using the 'GenerateDataKeyPair' API to provide a public key, plaintext private key, and encrypted private key. This should only be done when you are going to utilise the plaintext private key immediately, as having the private key in plaintext format is a security risk. You can use the 'GenerateDataKeyPairWithoutPlaintext' API to generate the public key and encrypted private key only. Data keys are protected using Key Encryption Key (KEK) to provide envelope encryption.

    * Many data keys can be generated from a CMK. These are not stored or managed in KMS. The plaintext data key is used to encrypt the data and is then deleted. This process is shown below:
        <p align="center">
        <img src="/res/keys.JPG">
        </p>

    * To decrypt, first call the KMS API with the encrypted data key to return the plaintext data key. The plaintext data key can be used to decrypt the encrypted data.

    * AWS CloudHSM is a cloud-based HSM that enables customers to create and manage encryption keys on a FIPS 140-2 Level 3–validated HSM, without the headache of managing one on-premises. It is easily managed and scalable, and you maintain full control of your encryption keys. AWS CloudHSM use cases include:
        * Offloading SSL/TLS processing. This is sometimes known as SSL acceleration and is when the HSML cluster handles some of the computational load of SSL/TLS.
        * Protecting private keys for Certificate Authorities (CAs).
        * Enabling Transparent Data Encryption (TDE) for Oracle databases.

    * All API calls made to your AWS CloudHSM cluster and HSMs are logged via AWS CloudTrail for auditing purposes to give you better insight into the management of your cluster. All audit logs gathered from your HSMs are sent to Amazon CloudWatch Logs so you can audit the creation and management of keys and users. You can monitor your CMKs using a combination of AWS CloudTrail and Amazon CloudWatch Alarms, Events, and Logs. These can all alert you when metrics gathered go above your determined baseline.

    * HSM users are and their permissions are shown below:
        <p align="center">
        <img src="/res/HSM_roles.JPG">
        </p>

    * AWS Secrets Manager is a service that enables you to securely store credentials, like passwords, which can be retrieved via an API call, removing the need to have these credentials hardcoded in applications or database clients. You can store any information inside AWS Secrets Manager, but the most common are database credentials and API/SSH keys.  It has built in integration with RDS and rotation of RDS secrets. For this service you pay per secret per month and per 10,000 API calls.

    * Parameter Store is typically used for passwords, database strings, license codes, configuration data, and parameter values. You can have user defined parameters and they can be encrypted. It is integrated with AWS Systems Manager. There is no additional charge for this service.

    * AWS Certificate Manager (ACM) is a service that will handle the complex nature of creating, storing, and renewing public/private SSL/TLS X.509 certificates and keys. This is typically referred to as a public key infrastructure (PKI) setup.

1. Given a set of data protection requirements, evaluate key usage and recommend required changes.

    * Knowing how a KMS key was used in the past might help you decide whether you will need it in the future. All AWS KMS API activity is recorded in AWS CloudTrail log files. If you have created a CloudTrail trail in the region where your KMS key is located, you can examine your CloudTrail log files to view a history of all AWS KMS API activity for a particular KMS key.
    
    * A symmetric key is recommended for most use cases as it is fast and efficient. An asymmetric key pair is required if you need users outside of AWS to encrypt data, as they can use the public key to encrypt. The private key of an asymmetric key pair can be used to sign messages and the public key can be used to verify signatures (using the 'Sign' and 'Verify' APIs).

1. Determine and control the blast radius of a key compromise event and design a solution to contain the same.

    * It is recommended to define classification levels and have at least one CMK per level. For example, you could define a CMK for data classified as “Confidential,” and so on. This ensures that authorized users only have permissions for the key material that they require to complete their job.

    * Creating KMS keys within each account that requires the ability to encrypt and decrypt sensitive data works best for most customers, but another option is to share the CMKs from a few centralized accounts. Maintaining the CMKs in the same account as most of the infrastructure using them helps users’ provision and run AWS services that use those keys.

    * Avoiding extensive reuse also lowers the blast radius. If your CMK is compromised your data will be compromised up to the point of the last rotation. Note that rotation of the key material effectively rotates the data keys used to encrypt your data. The old data key is still used for decryption for older data.

### Troubleshoot key management.

1. Break down the difference between a KMS key grant and IAM policy.

    * When authorising access to a KMS key, AWS KMS evaluates the following:
        * The key policy that is attached to the key. The key policy is always defined in the AWS account and Region that owns the KMS key. The Key Policy is a resource-based policy attached to the CMK, it defines key users and key administrators and trusted external accounts.
        * All IAM policies that are attached to the IAM user or role making the request. IAM policies that govern a principal's use of a KMS key are always defined in the principal's AWS account. The IAM Policy is assigned to a User, Group, or Role, and defines the allows actions e.g. kms:ListKeys.
        * All grants that apply to the KMS key. Grants are advanced mechanisms for specifying permissions that you or an AWS service integrated with AWS KMS can use to specify how and when a KMS key can be used. Grants are attached to a KMS key, and each grant contains the principal who receives permission to use the KMS key and a list of operations that are allowed. Grants are an alternative to the key policy and are useful for specific use cases.
        * Other types of policies that might apply to the request to use the KMS key, such as AWS Organizations service control policies and VPC endpoint policies. These policies are optional and allow all actions by default, but you can use them to restrict permissions otherwise given to principals.

1. Deduce the precedence given different conflicting policies for a given key.

    * AWS KMS evaluates the above policy mechanisms together to determine whether access to the KMS key is allowed or denied. This is illustrated below:
        <p align="center">
        <img src="/res/key_authorisation.JPG">
        </p>

    * The authorisation part determines whether you are permitted to use a KMS key based on its key policy, IAM policies, grants, and other applicable policies. The trust part determines whether you should trust a KMS key that you are permitted to use. In general, you trust the resources in your AWS account. But you can also feel confident about using KMS keys in a different AWS account if a grant or IAM policy in your account allows you to use the KMS key.

1. Determine when and how to revoke permissions for a user or service in the event of a compromise.

    * In the event of a compromise all root and IAM user access keys should be rotated. Once the key is rotated, disable the original keys, and update your applications to use the new keys. If there are no issues then you can delete the original keys.

    * If access is permitted with a long session duration time (such as 12 hours), their temporary credentials do not expire as quickly. You can immediately revoke all permissions to the role's credentials issued before a certain point in time if needed.

### Design and implement a data encryption solution for data at rest and data in transit.

1. Given a set of data protection requirements, evaluate the security of the data at rest in a workload and recommend required changes.

    * AWS KMS integrates seamlessly with many AWS services to make it easier for you to encrypt all your data at rest. For example, in Amazon S3 you can set default encryption on a bucket so that all new objects are automatically encrypted. Additionally, Amazon EC2 and Amazon S3 support the enforcement of encryption by setting default encryption. You can use AWS Managed Config Rules to check automatically that you are using encryption, for example, for EBS volumes, RDS instances, and S3 buckets.

    * AWS recommends following secure key management, enforcing encryption at rest, automating data at rest protection, enforcing access control, and keeping people away from data. Specific best practices include:
        * Enforce encryption at rest for Amazon S3.
        * Use AWS Secrets Manager to manage secrets.
        * Configure default encryption for new EBS volumes.
        * Configure encrypted AMIs. Copying an existing AMI with encryption enabled will automatically encrypt root volumes and snapshots.
        * Configure Amazon RDS encryption.
        * Configure encryption additional AWS services as used.
        * Separate data based on different classification levels. Use different AWS accounts for data classification levels managed by AWS Organizations.
        * Review the level of access granted in AWS KMS policies.
        * Review S3 bucket and object permissions. Do not have publicly readable or writeable buckets, unless necessary. Consider AWS Config to detect non-compliant buckets, and Amazon CloudFront to service content from Amazon S3.
        * Enable Amazon S3 versioning and object lock.
        * Review Amazon EBS and AMI sharing permissions. Sharing permissions can allow images and volumes to be shared to AWS accounts external to your workload.
        * Implement mechanisms to keep people away from data. Avoid use of bastion hosts or directly accessing EC2 instances.

1. Verify policy on a key such that it can only be used by specific AWS services.

    * Unlike IAM policies, which are global, key policies are Regional. Each key policy is effective only in the Region that hosts the KMS key. The components of the key policy are:
        * **Sid (Optional):** The Sid is a statement identifier, an arbitrary string you can use to identify the statement.
        * **Effect (Required):** The effect specifies whether to allow or deny the permissions in the policy statement. The Effect must be Allow or Deny. If you do not explicitly allow access to a KMS key, access is implicitly denied. You can also explicitly deny access to a KMS key. You might do this to make sure that a user cannot access it, even when a different policy allows access.
        * **Principal (Required):** The principal is the identity that gets the permissions specified in the policy statement. You can specify AWS accounts (root), IAM users, IAM roles, and some AWS services as principals in a key policy. IAM groups are not valid principals.
        * **Action (Required):** Actions specify the API operations to allow or deny. For example, the kms:Encrypt action corresponds to the AWS KMS Encrypt operation. You can list more than one action in a policy statement. For more information, see Permissions reference.
        * **Resource (Required):** In a key policy, the value of the Resource element is "*", which means "this KMS key." The asterisk ("*") identifies the KMS key to which the key policy is attached.
        * **Condition (Optional):** Conditions specify requirements that must be met for a key policy to take effect. With conditions, AWS can evaluate the context of an API request to determine whether the policy statement applies.

    * When the principal is another AWS account or its principals, the permissions are effective only when the account is enabled in the Region with the KMS key and key policy.

1. Distinguish the compliance state of data through tag-based data classifications and automate remediation.

    * Tags can be used on AWS resources based on a data classification framework to implement compliance with a data governance program. Tagging in this context can be used for automation such as enabling and validating data encryption, retention, and archiving.

1. Evaluate a number of transport encryption techniques and select the appropriate method (i.e., TLS, IPsec, client-side KMS encryption).

    * AWS recommends following secure key and certificate management, enforcing encryption in transit, automating detection of unintended data access, and authenticating network communications: Specific best practices include:
        * Implementing secure  protocols such as TLS or IPsec (relevant protocols depend on the services you are using).
        * Using HTTPS with Amazon CloudFront.
        * Using a VPN for external connectivity. Consider using an IPsec VPN for point-to-point or network-to-network connections.
        * Enabling a HTTPS listener for securing connections to load balancers.
        * Configuring HTTPS encryption on instances.
        * Configuring TLS to encrypt connections to database instances and clusters.
        * Using a tool or detection mechanism to automatically detect attempts to move data outside of defined boundaries.
        * Consider using Amazon Macie to monitor data access activity for anomalies.

## Appendix

### Key Tools and Technologies

1. AWS CLI

    * The AWS Command Line Interface (CLI) is a unified tool to manage your AWS services. With just one tool to download and configure, you can control multiple AWS services from the command line and automate them through scripts.

1. AWS SDK

    * The AWS SDK is a collection of tools to easily develop applications on AWS in the programming language of your choice.

1. AWS Management Console

    * The AWS Management Console is a browser-based GUI for Amazon Web Services (AWS). Through the console, a customer can manage their cloud computing, cloud storage and other resources running on the Amazon Web Services infrastructure.

1. Network analysis tools (packet capture and flow captures)

    * VPC Traffic Mirroring is an AWS feature used to copy network traffic from the elastic network interface of an EC2 instance to a target for analysis. This makes a variety of network-based monitoring and analytics solutions possible on AWS. By capturing the raw packet data required for content inspection, VPC Traffic Mirroring enables agentless methods for acquiring network traffic from/to Amazon Elastic Compute Cloud (EC2) instances. 

1. SSH/RDP

    * Session Manager is the AWS recommended approach for establishing interactive sessions with EC2. It can be used via the browser, CLI, or SDK. It provides TLS encryption without the need for any bastion hosts or ports. Logging is also provided for CloudTrail, CloudWatch, and S3.

1. Signature Version 4

    * Signature Version 4 (SigV4) is the process to add authentication information to AWS API requests sent by HTTP. For security, most requests to AWS must be signed with an access key. The access key consists of an access key ID and secret access key, which are commonly referred to as your security credentials.

1. TLS

    * Transport Layer Security, or TLS, is a widely adopted security protocol designed to facilitate privacy and data security for communications over the Internet. A primary use case of TLS is encrypting the communication between web applications and servers, such as web browsers loading a website. TLS can also be used to encrypt other communications such as email, messaging, and voice over IP (VoIP).

1. Certificate management

    * Certificate Management, or more specifically, X.509 certificate management, is the activity of monitoring, facilitating, and executing every certificate process necessary for uninterrupted network operations.

    * SSL certificates renew automatically, provided you purchased the domain name from Route53 and it is not for a private hosted zone. You can use Amazon SSL certificates with load balances and CloudFront, but you cannot export the certificates.

1. Infrastructure as Code (IaC)

    * IaC is the management of infrastructure (networks, virtual machines, load balancers, and connection topology) in a descriptive model, using the same versioning as DevOps team uses for source code.

### AWS Services and Features

1. AWS Audit Manager

    * AWS Audit Manager helps you continuously audit your AWS usage to simplify how you assess risk and compliance with regulations and industry standards. Audit Manager automates evidence collection to reduce the “all hands-on deck” manual effort that often happens for audits and enable you to scale your audit capability in the cloud as your business grows. With Audit Manager, it is easy to assess if your policies, procedures, and activities – also known as controls – are operating effectively. When it is time for an audit, AWS Audit Manager helps you manage stakeholder reviews of your controls and enables you to build audit-ready reports with much less manual effort.

1. AWS CloudTrail

    * CloudTrail logs calls to the AWS APIs for most services. It does not log events such as SSH or RDP access to an EC2 instance in AWS. Logged data is metadata around API calls. For example, the identity of the API caller, the time, the source IP, the request parameters, and the response.

1. Amazon CloudWatch

    * Amazon CloudWatch is a monitoring service for AWS cloud resources and the applications you run on AWS. CloudWatch can provide real time metrics, alarms, and notifications.

    * CloudWatch Logs are pushed from some AWS services and are stored internally indefinitely. EventBridge can provide a near real-time stream of system events.

1. AWS Config

    * AWS Config is a service that enables you to assess, audit, and evaluate the configurations of your AWS resources. Config continuously monitors and records your AWS resource configurations and allows you to automate the evaluation of recorded configurations against desired configurations.

    * Config requires an IAM role with read only permissions to the recorded resources, write access to the S3 logging bucket, and publish access to Simple Notification Service (SNS) if it is being used.

    * Access to Config is restricted by requiring authentication with AWS and having the appropriate permissions set via IAM policies. Only administrators needing to setup and manage Config require full access. Read only permissions for Config should be provided for day-to-day use.

    * CloudTrail can be used with Config to provide deeper insight into resources. CloudTrail can also be used to monitor access to Config, such as someone disabling Config.

1. AWS Organizations

    * AWS Organizations is an account management service which allows you to consolidate multiple AWS accounts into an Organization that you can manage directly.

1. AWS Systems Manager

    * Systems Manager can store confidential information in the Parameter Store such as passwords, database connection strings, and license codes. Values can be stored as plain text or encrypted. These values can then be referenced by using their names.

    * The SSM agent needs to be installed on your managed instances. Commands can then be issued using AWS console, AWS CLI, AWS Tools for Windows PowerShell, Systems Manager API or Amazon SDKs.

    * The Systems Manager Run Command lets you remotely and securely manage the configuration of your managed instances.

1. AWS Trusted Advisor

    * Trusted Advisor is an online resource to help your educe cost, increase performance, and improve security by optimising your AWS environment. The advice will cover cost optimisation, performance, security, and fault tolerance. To access all services within Trusted Advisor a business support plan is required.

1. Amazon Detective

    * Amazon Detective makes it easy to analyze, investigate, and quickly identify the root cause of potential security issues or suspicious activities. Amazon Detective automatically collects log data from your AWS resources and uses machine learning, statistical analysis, and graph theory to build a linked set of data that enables you to easily conduct faster and more efficient security investigations.

    * AWS security services like Amazon GuardDuty, Amazon Macie, and AWS Security Hub as well as partner security products can be used to identify potential security issues, or findings. These services are helpful in alerting you when something is wrong and pointing out where to go to fix it. But sometimes there might be a security finding where you need to dig a lot deeper and analyze more information to isolate the root cause and act. Determining the root cause of security findings can be a complex process that often involves collecting and combining logs from many separate data sources, using extract, transform, and load (ETL) tools or custom scripting to organize the data, and then security analysts having to analyze the data and conduct lengthy investigations.

    * Amazon Detective simplifies this process by enabling your security teams to easily investigate and quickly get to the root cause of a finding. Amazon Detective can analyze trillions of events from multiple data sources such as Virtual Private Cloud (VPC) Flow Logs, AWS CloudTrail, and Amazon GuardDuty, and automatically creates a unified, interactive view of your resources, users, and the interactions between them over time. With this unified view, you can visualize all the details and context in one place to identify the underlying reasons for the findings, drill down into relevant historical activities, and quickly determine the root cause.

1. AWS Firewall Manager

    * AWS Firewall Manager is a security management service which allows you to centrally configure and manage firewall rules across your accounts and applications in AWS Organizations. As new applications are created, Firewall Manager makes it easy to bring new applications and resources into compliance by enforcing a common set of security rules. Now you have a single service to build firewall rules, create security policies, and enforce them in a consistent, hierarchical manner across your entire infrastructure, from a central administrator account.

1. AWS Network Firewall

    * AWS WAF and host-based firewalls such as iptables and Windows firewall do not provide network packet inspection (IDS/IPS). To provide this capability third party software can be installed on EC2 from the AWS Marketplace.

1. AWS Security Hub

    * AWS Security Hub provides a single place to manage and aggregate the findings and alerts from key security service. It integrates with a lot of AWS security services. Automated ongoing security auditing and built-in checks for PCI-DSS and CIS are provided.

1. AWS Shield

    * AWS Shield is a managed DDoS protection service for ELB, CloudFront and Route 53 that safeguards applications running on AWS. Primarily protects against layer 3 and layer 4 attacks.
 
    * The advanced option costs $3000 per month and gives you an incident response team and in-depth reporting. You will not pay if you are the victim of an attack.

1. Amazon VPC

    * Amazon VPC is a foundational AWS service. Other AWS services, such as EC2, cannot be accessed without an underlying VPC network. A VPC behaves like a traditional TCP/IP network that can be expanded and scaled as needed. Typical data centre components (routers, switches, VLANS etc.) do not explicitly exist, but have been abstract and re-engineered into cloud software.

    * A VPC endpoint enables connections between a VPC and supported services, without requiring that you use an internet gateway, NAT device, VPN connection, or AWS Direct Connect connection. Therefore, your VPC is not exposed to the public internet.

    * A Network Access Control List (NACL) is an optional layer of security for your VPC that acts as a firewall for controlling traffic in and out of one or more subnets. The NACL might have rules like your security groups to add an additional layer of security to your VPC. The following are basic NACL concepts:
        * Your VPC automatically comes with a modifiable default network ACL. By default, it allows all inbound and outbound IPv4 traffic and, if applicable, IPv6 traffic.
        * You can create a custom network ACL and associate it with a subnet. By default, each custom network ACL denies all inbound and outbound traffic until you add rules.
        * Each subnet in your VPC must be associated with a network ACL. If you do not explicitly associate a subnet with a network ACL, the subnet is automatically associated with the default network ACL.
        * You can associate a network ACL with multiple subnets. However, a subnet can be associated with only one network ACL at a time. When you associate a network ACL with a subnet, the previous association is removed.
        * A network ACL contains a numbered list of rules. We evaluate the rules in order, starting with the lowest numbered rule, to determine whether traffic is allowed in or out of any subnet associated with the network ACL. The highest number that you can use for a rule is 32766. We recommend that you start by creating rules in increments (for example, increments of 10 or 100) so that you can insert new rules where you need to later on.
        * A network ACL has separate inbound and outbound rules, and each rule can either allow or deny traffic.
        * Network ACLs are stateless, which means that responses to allowed inbound traffic are subject to the rules for outbound traffic (and vice versa).
        * There are quotas (limits) for the number of network ACLs per VPC, and the number of rules per network ACL. 

    * A security group acts as a virtual firewall for your instance to control inbound and outbound traffic. When you launch an instance in a VPC, you can assign up to five security groups to the instance. Security groups act at the instance level, not the subnet level. Therefore, each instance in a subnet in your VPC can be assigned to a different set of security groups. The following are basic security group concepts:
        * You can specify allow rules, but not deny rules.
        * You can specify separate rules for inbound and outbound traffic.
        * Security group rules enable you to filter traffic based on protocols and port numbers.
        * Security groups are stateful — if you send a request from your instance, the response traffic for that request can flow in regardless of inbound security group rules. Responses to allowed inbound traffic can flow out, regardless of outbound rules.
        * When you first create a security group, it has no inbound rules. Therefore, no inbound traffic originating from another host to your instance is allowed until you add inbound rules to the security group.
        * By default, a security group includes an outbound rule that allows all outbound traffic. You can remove the rule and add outbound rules that allow specific outbound traffic only. If your security group has no outbound rules, no outbound traffic originating from your instance is allowed.
        * There are quotas on the number of security groups that you can create per VPC, the number of rules that you can add to each security group, and the number of security groups that you can associate with a network interface.
        * Instances associated with a security group can't talk to each other unless you add rules allowing the traffic (exception: the default security group has these rules by default).
        * Security groups are associated with network interfaces. After you launch an instance, you can change the security groups that are associated with the instance, which changes the security groups associated with the primary network interface (eth0). You can also specify or change the security groups associated with any other network interface. By default, when you create a network interface, it is associated with the default security group for the VPC, unless you specify a different security group.
        * When you create a security group, you must provide it with a name and a description. There are limits to the length (255 characters) and allowed characters. Security group names must be unique within the VPC.
        * A security group can only be used in the VPC that you specify when you create the security group.

1. AWS WAF

    * AWS Web Application Firewall (WAF) lets you monitor the HTTP and HTTPS requests that are forwarded to Amazon CloudFront or an application load balancer. It does not integrate with services like EC2 directly. You can configure conditions such as what IP addresses are allowed to make this request or what query string parameters need to be passed for the request to be allowed.

    * As a basic level WAF allows 3 different behaviours:
        * Allow all requests except the ones that you specify.
        * Block all requests except the ones that you specify.
        * Count the requests that match the properties that you specify.

    * Application load balancers integrate with WAF at a regional level, while CloudFront is at a global level.

    * You need to associate your rules to AWS resources in order to be able to make it work.

    * You can use AWS WAF to protect web sites not hosted in AWS via CloudFront. CloudFront supports custom origins outside of AWS.

    * WAF supports both IPv4 and IPv6 and IP's can be blocked at a /8, /16, /24, and /32 level.

1. AWS Certificate Manager (ACM)

    * AWS ACM lets you provision, manage, and deploy public and private certificates for use with AWS services. Supported services include:
        * ELB
        * CloudFront
        * Elastic Beanstalk
        * API Gateway
        * Nitro Enclaves
        * CloudFormation

1. AWS CloudHSM

    * AWS CloudHSM helps you meet corporate, contractual, and regulatory compliance requirements for data security by using dedicated Hardware Security Module (HSM) appliances within the AWS cloud. CloudHSM is provided in a single tenancy.

    * There are 4 type of CloudHSM users:
        * **Precrypto Officer (PRECO):** A temporary user with a default user name and password. They can only change their password (to become the Primary Crypto Officer) and perform read-only operations on the HSM.
        * **Crypto Officer (CO):** Performs user management operations. For example, creating and deleting users and changing user passwords
        * **Crypto Users (CU):** Performs key management operations. For example, creating, deleting, and importing cryptographic keys. Also uses cryptographic keys for encryption.
        * **Appliance User (AU):** Can perform cloning and synchronisation operations. The AU exists on all HSMs and has limited permissions.

1. AWS Directory Service

    * AWS Directory Service provides multiple ways to set up and run Microsoft Active Directory with other AWS services such as Amazon EC2, Amazon RDS for SQL Server, FSx for Windows File Server, and AWS Single Sign-On.

1. Amazon GuardDuty

    * GuardDuty is a threat detection service which uses machine learning to continuously monitor for malicious behaviour, particularly around EC2 instances. This includes unusual API calls or calls from a known malicious IP, attempts to disable CloudTrail logging, port scanning etc.

    * Alerts appear in the GuardDuty console and EventBridge. Automated responses can be setup using EventBridge and Lambda.

    * GuardDuty requires 7-14 days to set a baseline for what is normal behaviour on your account.

1. AWS Identity and Access Management (IAM)

    * AWS Identity and Access Management (IAM) provides fine-grained access control across all of AWS. With IAM, you can specify who can access which services and resources, and under which conditions. With IAM policies, you manage permissions to your workforce and systems to ensure least-privilege permissions.

1. Amazon Inspector

    * Amazon Inspector is an automated security assessment service that helps improve the security and compliance of applications deployed on AWS. Inspector automatically assesses applications for vulnerabilities or deviations from best practices. After performing an assessment, Inspector produces a detailed list of security findings prioritised by level of severity. These findings can be reviewed directly or as part of detailed assessment reports which are available via the Inspector console or API.

    * Inspector supports the following rules packages:
        * Common vulnerabilities and exposures
        * CIS operating system security configuration benchmarks
        * Security best practices
        * Runtime behaviour analysis

    * Inspector uses high, medium, low, and informational levels for rules.

1. AWS Key Management Service (AWS KMS)

	* AWS Key Management Service (KMS) is a service for managing encryption keys that is used for both client side (optional) and server-side encryption with AWS. KMS only manages Customer Master Keys (CMKs) and it uses Hardware Security Modules (HSMs) to store the keys.

1. Amazon Macie

    * Amazon Macie uses Machine Learning and Natural Language Processing to discover, classify, and protect sensitive data stored in S3. It provides dashboards, reporting, and alerts. Data is classified by content type, theme, file extension, and regular expression.

1. AWS Single Sign-On

    * AWS Single Sign-On (AWS SSO) is a cloud service that allows you to grant your users access to AWS resources, such as Amazon EC2 instances, across multiple AWS accounts. By default, AWS SSO now provides a directory that you can use to create users, organize them in groups, and set permissions across those groups.

### Out-of-scope Services and Features

1. Application development services

1. IoT services

1. Machine learning (ML) services

1. Media services

1. Migration and transfer services

## Practise Questions

### Incident Response

1. A security team is creating a response plan when an employee executes unauthorised actions on AWS infrastructure. They want to include steps to determine if the employee's IAM permissions changes as part of the incident. What steps should the team document in the plan?
    * AWS Config can be used to examine the employee's IAM permissions before the incident and compare them to the employee's current IAM permissions. AWS Macie is not applicable as it used for data security and data privacy. Amazon GuardDuty is not applicable as it is a threat detection service. AWS Trusted Advisor is not relevant as it helps optimise your AWS infrastructure.

1. A company hosts a critical web application on the AWS Cloud. This is a key revenue-generating application for the company. The IT Security team is worried about potential DDoS attacks against the website (this might affect the AWS services like Amazon CloudFront, Amazon Route 53, and AWS Global Accelerator). The senior management has also specified that immediate action needs to be taken in case of a potential DDoS attack. What should be done in this regard?
    * Consider using the AWS Shield Advanced Service.

1. A company has developed an incident response plan 18 months ago. Regular implementations of the response plan are carried out. No changes have been made to the response plan since its creation. Which of the following is the right statement about the plan?
    * The response plan does not cater to new services as the plan is not updated for 18 months.

1. You are trying to connect to a running EC2 instance using SSH. However, you are receiving an "unprotected private key file" error. What is the possible root cause of this issue?
    * Note that KMS does not manage public-key pairs for EC2 instances. It is likely that the private key file has the wrong file permissions and is not protected from read and write operations from other users. To fix the error run `chmod -400 .ssh/.pem`.

1. You have accidentally deleted the private key from an EBS-backed Amazon Linux EC2 instance. You want to regain access to your instance. What steps should you perform to resolve this issue?
    * A new key pair must be generated. The root volume can then be attached to another instance, and the authorized_keys file on the mounted volume can be updated with the new public key.

1. You have accidentally lost the administrator password for an EBS-backed Windows Server EC2 instance. The instance has the Systems Manager agent installed. You want to regain access to your instance. What is the easiest way to resolve the issue?
    * The Systems Manager Run Command can be used to run the `AWSSupport-RunEC2RescueForWIndowsTool` command.

1. You have requested that your development team do not provision any new EC2 instances over the next few weeks while you are completing a security audit of your development environment. Last weekend, many of the developers worked over time and most of them disregarded your request, which has invalidated a lot of the work you have completed so far. You have decided to take action to prevent this happening again and you have convinced the CTO to give you permission to automatically terminate any instances that the development team launches over the coming weeks. You want to accomplish this in the simplest way that will ensure any newly created EC2 instances are terminated as soon as possible to minimise the impact on your work. From the following choices, which two different approaches can be taken to address the situation?
    * Use CloudTrail to detect when a user launches a new instance. Configure a CloudWatch events rule to trigger on AWS API calls from CloudTrail and invoke a Lambda function to terminate EC2 instances. You can also use an AWS Config customer managed rule to invoke a Lambda function that automatically terminates any new instances.

1. Your CTO has asked you to monitor all S3 buckets in your account to ensure encryption aligns with company policy. You have also been asked to automatically remediate any violation by updating the S3 bucket properties and sending an SNS notification to the security team. Which of the following are valid configuration steps?
    * Enable AWS Config to monitor Amazon S3 buckets for compliance violations.
    * Create an IAM Role and Policy that grants a Lambda function permissions to read and modify the S3 bucket configuration settings and send alerts through SNS.
    * Configure a CloudWatch Events rule that triggers the Lambda function when AWS Config detects an S3 bucket not using server-side encryption.
    * Create a Lambda function which uses the IAM role to review the S3 bucket settings, correct them, and notify your team of out-of-compliance buckets.

1. You have discovered that your AWS account may have been compromised. What steps should you carry out immediately to secure your account?
    * Rotate all passwords and IAM access Keys.
    * Delete any resources in your account that you did not create yourself.

1. Your CTO has asked you to design an automated incident response system which needs to assess, audit, and evaluate deviations against desired configurations of your AWS resources, proactively remediating security weaknesses in your AWS account. Which of the following approaches meets the requirement?
    * Use AWS Config rules to monitor for deviations against your desired configurations, send alerts to CloudWatch events and use Lambda to automatically remediate security weaknesses.

1. One of your team has mistakenly leaked the access key and secret access key for their IAM User on GitHub. What should you do immediately to secure your account?
    * Disable any other potentially unauthorized IAM user credentials.
    * Disable and delete compromised AWS access keys.

1. Your Network team informs you that your application servers located in a particular subnet are being targeted by malicious actors attempting to intercept packets in your network. The activity is coming from a specific range of IP addresses. Which of the following steps can you take to quickly block this malicious activity?
    * Create a Network ACL to deny access to any traffic coming from this IP range.

1. You have been asked to help develop a process for monitoring and alerting staff when malicious or unauthorized activity occurs. Your Chief Security Officer is asking for a threat detection service that uses machine learning to help monitor malicious activity and unauthorized behaviour to protect your AWS accounts, workloads, and data stored in S3. Which option best fits these requirements?
    * Enable AWS GuardDuty to monitor for malicious and unauthorized behaviour. Configure a custom blocklist for the IPs which you have seen suspect activity in the past. Setup a Lambda function triggered from a CloudWatch event when anomalies are detected.

### Logging and Monitoring

1. Your company has an EC2 instance that is hosted in an AWS VPC. There is a requirement to ensure that log files from the EC2 instance are stored in a secure manner. The access should be limited to the log files. How can this be accomplished? Choose 2 answers from the options given below. Each answer forms part of the solution.
    * CloudTrail is not relevant here as it is for recording API activities. The log files should be streamed to a separate CloudWatch Log group and an IAM policy should be created to give access to the CloudWatch Log group.

1. A company has managed many AWS resources. The IT audit department has requested to get a list of resources in the AWS account. How can this be achieved efficiently?
    * AWS Config can be used to get a list of all resources. Methods such as using a bash or PowerShell script are less efficient.

1. A company uses CloudTrail to log all AWS API activity for all regions in all its accounts. The CISO has asked that additional steps be taken to protect the integrity of the log files. What combination of steps will protect the log files from intentional or unintentional alteration?
    * An S3 bucket should be created in a dedicated log account and other accounts should have write only access to this account. CloudTrail log file integrity validation should be enabled.

1. You have enabled CloudTrail logs for your company’s AWS account. In addition, the IT Security department has mentioned that the logs need to be encrypted. How can this be achieved?
    * By default all AWS CloudTrail event log files are encrypted using Amazon S3 Server-Side Encryption (SSE).

1. Which of the following is NOT a best practice for carrying out a security audit?
    * Audits should be conducted more frequently than yearly. Audits should be done on a periodic basis, if there are changes in your organisation, if you have stopped using one or more AWS services, if you have added or removed software in your accounts, and if you ever suspect unauthorised access.

1. A company has a legacy application that outputs all logs to a local text file. Logs from all applications running on AWS must be continually monitored for security-related messages. What can be done to allow the company to deploy the legacy application on Amazon EC2 and still meet the monitoring requirement?
    * The logs can be sent to CloudWatch logs. You can then specify metrics to search the logs for any specific values and create alarms based on these metrics.

1. As an AWS security specialist, you are working on applying AWS Config rules to all AWS accounts to ensure that AWS resources meet security requirements. One of the security checks is to inspect whether EC2 resources have appropriate Tags. If not, the rule will be non-compliant. There is an existing AWS Config rule called required-tags. However, it does not meet your needs. For example, you want the rule to check specific resources in certain availability zones. How should you implement the Config rule to perform custom checks?
    * An AWS Lambda function can be used to perform custom checks. A custom AWS Config rule can be used to invoke the Lambda function.

1. You are working in the IT security team in a big company. To perform security checks in AWS services, you have written dozens of custom AWS Config rules. One of them is to check if the S3 bucket policy contains certain explicit denies. This Config rule is supposed to be applied for all S3 buckets. Your manager has asked you how to trigger the custom Config rule. Which answers are correct?
    * The rule can be automatically triggered whenever there is a change for an S3 bucket. It can also be triggered periodically every 1, 3, 6, 12, or 24 hours. The rule could also be triggered manually.

1. Your company makes use of S3 buckets for storing data. There is a company policy that all services should have logging enabled. How can you ensure that logging is always enabled to create S3 buckets in the AWS Account?
    * AWS Config Rules can be used to check whether logging is enabled for buckets.

1. A security engineer must ensure that all infrastructure launched in the company AWS account be monitored for deviation from compliance rules. All EC2 instances must be launched from one of a specified list of AMIs with all attached EBS volumes being encrypted. The non-compliant infrastructure should be terminated. What steps should the engineer choose?
    * Compliance can be monitored with AWS Config Rules triggered by configuration changes. A Lambda function from the CloudWatch event rule for AWS Config "Compliance Rules Notification Change" to terminate the non-compliant infrastructure.

1. You are responsible for deploying a critical application onto AWS. Part of the requirements for this application is to ensure that the controls set for this application meet the PCI DSS. Which of the following services can be used to check if AWS is certified as a PCI DSS Service Provider?
    * AWS Artifact can provide the compliance documents.

1. Company policy requires that all EC2 servers are not exposed to common vulnerabilities and exposures (CVEs). The security team would like to regularly check all servers to ensure compliance with this requirement by using a scheduled CloudWatch event to trigger a review of the current infrastructure. What process will check compliance of the company's EC2 instances?
    * Run an Amazon Inspector assessment using the common vulnerabilities and exposures rules package against every EC2 instance.

1. You work as an administrator for a company. The company hosts several resources using AWS. There is an incident of suspicious API activity that occurred 11 days ago. The security admin has asked to get the API activity from that point in time. How can this be achieved?
    * Search the AWS CloudTrail event history on the API events which occurred 11 days ago. Up to 90 days of event history can be viewed in this manner. Note that this answer assumes the customer has enabled the CloudTrail service and that a trail has been manually configured.

1. You need to ensure that the CloudTrail logs which are being delivered to your AWS account are encrypted. How can this be achieved in the easiest way possible?
    * By default the log files are encrypted by SSE-S3.

1. As an AWS account administrator, you wish to perform an audit and create a report of all services that have not been used in the IAM role 'DevOps_Admin' in the past 6 months. Which AWS services would you use to accomplish this task?
    * AWS IAM Access Advisor provides permission guardrails to help control which services your developers and applications can access. By analysing the last accessed information, you can determine the services not used by IAM users and roles.

1. You are a compliance officer at a large life sciences company utilising numerous AWS accounts across multiple development teams. The AWS accounts are managed under an AWS Organisation. To ensure HIPAA compliance, you must ensure that the log file delivery of AWS CloudTrail is not suspended by any AWS account. What is the most efficient way to accomplish this task?
    * An SCP should be created with a deny rule on action 'cloudtrail:StopLogging' and applied to the related OUs.

1. A company is planning to run a number of admin related scripts using the AWS Lambda services. There is a need to understand if there are any errors encountered when the script runs. How can this be accomplished most effectively?
    * Reporting metrics for AWS Lambda are provided through Amazon CloudWatch. Lambda logs all requests handled by your function.

1. You are responsible for the security profile of a number of mission critical applications at a large global telecommunications company. Your team lead asks you to propose a solution to trace all changes made to the AWS infrastructure. You must also prevent any evidence from tampering or deletion by malicious actors attempting to conceal unauthorized activities. Which of the following approaches do you propose?
    * Only allow the Security Team permission to make changes in CloudTrail.
    * Enable CloudTrail in all AWS regions and send logs to a dedicated S3 bucket. Grant read only access to the Security Team members who need to review the logs.

1. You have multiple separate AWS accounts for each different project in your organization. You would like to enable CloudTrail logging for each of these accounts and consolidate all logs to the same S3 bucket. What are two possible approaches?
    * Turn on CloudTrail in the account where the destination bucket will belong, configure the bucket policy to allow cross-account permission. Turn on CloudTrail in the other accounts, configure all accounts to log to the destination bucket.
    * Use AWS CloudTrail and a user in a management account to create an organization trail that logs all events for all AWS accounts in that organization in the same Amazon S3 bucket.

1. You are trying to debug a Lambda function which writes S3 metadata to a DynamoDB table. All logs from the function should be going to CloudWatch Logs however the function never seems to be sending any logs. What could be the problem?
    * Your function does not have permission to write to CloudWatch. The function execution role needs to permission to write to CloudWatch.

1. You are supporting a number of EC2 instances located in a private subnet of your organization's VPC. The instances need to access resources that are stored in S3. After creating a VPC endpoint, the instances are still unable to access the buckets. Which of the following should do to fix this problem?
    * You need to ensure that a route is present in your route table which routes all requests to S3 via your endpoint. Note that it is not possible to configure a route that routes all request to S3 via Amazon PrivateLink.

1. You have developed a number of Lambda functions to run automated housekeeping tasks in your environment, however you suspect that some of these functions are failing to launch or not completing properly as a lot of the tasks have failed to run. Which of the following tools can you use to investigate this?
    * Check for errors in CloudWatch. Lambda logs errors to CloudWatch Metrics. The Errors metric measures the number of failed invocations Monitoring Lambda Functions.

1. You are trying to debug your Lambda function, however you noticed that data events for Lambda and S3 are not available in Amazon CloudWatch Events. What could be the reason for this?
    * Data events are not logged by default. To record CloudTrail data events, you must explicitly add the supported resources or resource types for which you want to collect activity to a trail.
    * Your Lambda function and S3 resources haven't been added to a CloudTrail trail. Data events provide visibility into the resource operations performed on or within a resource. Data events are not logged by default when you create a trail. To record CloudTrail data events, you must explicitly add the supported resources or resource types for which you want to collect activity to a trail.
    * Note that you do not need to enable data events in Lambda and S3. They are added to the trail.

1. Your CTO has asked you to monitor all S3 bucket ACLs and policies for violations which allow public read or public write access. You have also been asked to automatically remediate the violation and send a notification reporting the finding to the Security Team. Which of the following services can you use to do this?
    * Use AWS Config to monitor for policy violations, use CloudWatch Events to trigger a Lambda function to update S3 bucket policies and ACLs and send an SNS notification to the Security Team.

1. Your customer is currently logging all CloudTrail data and management events into a single S3 bucket. Due to a recent security incident, the customer now wants to log management events in a different S3 bucket but continue to use the existing bucket to log only data events. The current trail is using default encryption. From the AWS CloudTrail console, which of the below options is correct?
    * Edit the existing trail configuration and set the management events option to None. Then create a new trail that logs only management events but to a different S3 bucket with an appropriate bucket policy to capture the logs. Since a trail configuration can only reference a single S3 bucket, a new trail must be created. CloudTrail trail configurations do not inherit from other trails and editing a trail configuration is not against best practices.

1. You are working on a strictly confidential project and your Chief Information Security Officer has mandated that you must make sure that none of the EC2 instances, which are being used for your project, have a public IP address. You have been told that you are responsible for enforcing this and project funding will be withdrawn if the team does not comply. How can you enforce this?
    * Use CloudWatch Events to trigger a Lambda function to remove any public IP addresses.
    * Use IAM policies to deny your administrators the ability to add a public IP address.
    * Use AWS Config to monitor for compliance.

1. You are running your web application on a number of EC2 instances behind an Application Load Balancer. You have configured the application to send error logs and security logs to CloudWatch logs. Persistent data generated by the application is stored in DynamoDB and website images and static content is stored in S3. Over the weekend the application crashed a number of times, causing a serious system outage. The application support team managed to get the system back online, but on Monday morning when they tried to access the logs to analyze what went wrong, they discover that no logs exist for this application. What might be the problem?
    * The Instance role does not have permission to write to CloudWatch Logs.
    * The CloudWatch Logs agent is not installed.
    * The CloudWatch Logs agent is not running.

1. Your team suspects that one of your instances has been compromised and is attempting to communicate with a command and control server. Which services can you use to investigate this?
    * Amazon Inspector. You can use Amazon Inspector to assess your assessment targets (collections of AWS resources) for potential security issues and vulnerabilities. Amazon Inspector compares the behaviour and the security configuration of the assessment targets to selected security rules packages.
    * VPC Flow Logs.
    * GuardDuty. GuardDuty continuously analyzes VPC Flow Logs and DNS requests and responses to identify malicious, unauthorized, or unexpected behaviour in your AWS accounts and workloads.

1. You have multiple separate AWS accounts for each department in your company. You have enabled CloudTrail logging for each of these accounts and configured each one to send logs to the same S3 bucket. However some of your accounts have not been sending any logs. What do you think the problem is?
    * The accounts do not have permission to write to the S3 bucket.

1. To further enhance security and provide DNS related information for security audits, management has requested that you enable Route 53 DNS Query Logging. For which of the following configurations can DNS Query Logging be enabled?
    * DNS Query Logging can be enabled when using a public hosted zone and using Route 53 name servers.

### Infrastructure Security

1. A company hosts a popular web application that connects to an Amazon RDS MySQL DB instance running in a private VPC subnet created with default Network ACL settings. The IT Security department has a suspicion that a DoS attack is coming from a suspecting IP. How can you protect the subnets from this attack?
    * Change the inbound NACL to deny access from the suspecting IP. The NACL is responsible for controlling traffic in and out of a subnet. Security Groups work on the instance level and not the Subnet level, and you cannot configure a Security Group to deny access.

1. A company is hosting a website that must be accessible to users for HTTPS traffic. Also, port 22 should be open for administrative purposes. The administrator's workstation has static IP addresses of 203.0.113.1/32. Which of the following security group configurations is the MOST secure but still functional to support these requirements?
    * Port 443 from 0.0.0.0/0 (all addresses) should be open. Port 22 from 203.0.113.1/32 (the administrative workstation only) should be open.

1. You have a website that is sitting behind AWS CloudFront. You need to protect the website against threats such as SQL injection and Cross-site scripting attacks. Which services can help in such a scenario?
    * AWS Config is not relevant here as it is used to check configuration changes on your AWS account. AWS Inspector is not relevant here as it can be used to scan EC2 instances for vulnerabilities but not protect against the threats in this question. AWS Trusted Advisor is also not relevant here as that is to improve the security on your AWS account. AWS WAF allows you to create rules that can help to protect against common web exploits.

1. You have a 2-tier application hosted in AWS. It consists of a web server and database server (SQL Server) hosted on separate EC2 instances. You are devising the security groups for these EC2 instances. The Web tier needs to be accessed by users across the internet. You have created a web security group (wg-123) and a database security group (db-345). Which combination of the following security group rules will allow the application to be secure and functional?
    * In wg-123 allow access from ports 80 and 443 for HTTP and HTTPS traffic for all users from the internet. In db-345 allow port 1443 traffic from wg-123.

1. A company wants to have an Intrusion detection system available for their VPC in AWS. They want to have complete control over the system. What should they implement?
    * A custom solution from the AWS Marketplace should be used. AWS does not provide an intrusion detection system natively.

1. A security team must present a daily briefing to the CISO that includes a report of which of the company's thousands of EC2 instances and on-premises servers are missing the latest security patches. All instances/servers must be brought into compliance within 24 hours so that they do not show up on the next day's report. How can the security team fulfill these requirements?
    * Systems Manager Patch Manager can be used to generate the report of out of compliance instances and servers, and to install the missing patches. Deploy the latest AMIs is not correct as it will affect the applications running on these systems.

1. Your department oversees developing an Ecommerce website where customers can browse and purchase products online. The application is developed in the AWS platform. A wide range of AWS services is used, including EC2, Lambda, CloudFormation, etc. Recently, the internal security auditors asked you to provide a document to state that the related AWS services meet the Payment Card Industry (PCI) compliance. How should you provide the document?
    * A PCI compliance document can be downloaded from AWS Artifact.

1. You just joined a big IT company as an AWS security specialist. Your first assignment is to prepare for an external security audit next month. You need to understand how your company uses AWS services and whether they can meet security compliance. You know that AWS Artifact can help you provide security compliance evidence to the auditor. Which specific areas can AWS Artifact help you?
    * AWS Artifact can provide a Service Organisation Control (SOC) compliance report and AWS ISO certifications for the AWS infrastructure and services that the company has used.

1. An application running on EC2 instances in the public subnet in a VPC must call an external web service via HTTPS. Which of the below options would minimise the exposure of the instances?
    * The outbound rules on both the NACL and security group need to allow outbound traffic. The inbound traffic should be allowed on ephemeral ports for the OS on the instances to allow a connection to be established on any desired or available port.

1. A company is deploying a new web application on AWS. Based on their other web applications, they anticipate being the target of frequent DDoS attacks. Which steps can the company take to protect its applications?
    * An AWS Application Load Balancer and Auto Scaling group can be used to absorb malicious traffic. CloudFront and AWS WAF can prevent malicious traffic from reaching the application.

1. Your current setup in AWS consists of the following architecture. 2 public subnets, one subnet which has the EC2 web servers accessed by users across the internet and the other subnet for the EC2 database server. The application uses the HTTPs protocol. Which of the following changes to the architecture would add a better security boundary to the resources hosted in your setup?
    * The database server should be moved to a private subnet. Only port 443 should be allowed in for the webserver EC2 instances.

1. A company is planning to create private connections from on-premises AWS Infrastructure to the AWS Cloud. They need to have a solution that would give core benefits of traffic encryption and ensure latency is kept to a minimum. Which of the following would help fulfil this requirement?
    * An AWS VPN can be used to create an IPSec connection between your VPC and your remote network. AWS Direct Connect can be used to create a dedicated private connection between your VPC and your remote network.

1. You want to ensure that instance in a VPC does not use AWS DNS for routing DNS requests as you want to use your own managed DNS instance. How can this be achieved?
    * You can create a new Dynamic Host Configuration Protocol (DHCP) options set and replace the existing one. Note that you cannot change an existing DHCP options set.

1. A Windows machine in one VPC needs to join the AD domain in another VPC. VPC peering has been established but the domain join does not work. Which of the following steps would you check to ensure that the AD domain join can work as intended?
    * In addition to setting up VPC peering and the route tables, the security group of the AD EC2 instance needs to have the right rule to allow incoming traffic.

1. Your company manages thousands of EC2 instances. There is a mandate to ensure that all servers don't have any critical security flaws. What can be done to ensure this?
    * AWS Inspector automatically assesses applications for vulnerabilities or deviations from best practices. AWS Systems Manager Agent (SSM) can be used to patch servers.

1. You need to inspect the running processes on an EC2 instance that may have a security issue. Also, you need to ensure that the process does not interfere with the continuous running of the instance. How can you achieve this in the easiest way possible?
    * The SSM Run command can execute a command on the EC2 instance that sends the list of running processes information to an S3 bucket. AWS CloudTrail, AWS CloudWatch, and AWS Config are not relevant here.

1. You are trying to use the Systems Manager to patch a set of EC2 systems. Some of the systems are not getting covered in the patching process. Which of the following can be used to troubleshoot the issue?
    * Check to see if the right role has been assigned to the EC2 instances and that the SSM agent is installed and running on the instance. You can use the EC2 Health API to determine the version of the SSM agent and the last time the instance sent a heartbeat value.

1. Development teams in your organisation use S3 buckets to store the log files for various applications hosted in development environments in AWS. The developers want to keep the logs for one month for troubleshooting purposes and then remove the logs. What feature will enable this requirement?
    * Lifecycle configuration on the S3 bucket enables you to specify the lifecycle management objects in a bucket, including logs. An expiration action can be used to specify when the objects expire.

1. You have a set of applications, databases, and web servers hosted in AWS. The web servers are placed behind an ELB. There are separate security groups for the application, database, and web servers. The security groups have been defined accordingly. There is an issue with the communication between the application and database servers. In order to troubleshoot the issue between just the application and database server, what is the ideal set of minimal steps you would take?
    * As communication is usually from the application to the database, check the outbound rules for the application security group and the inbound rules for the database security group.

1. You have a highly sensitive application which you would like to protect from being overwhelmed by malicious traffic. You are running your own proprietary web application firewall which performs packet inspection and filtering on two EC2 instances behind an application load balancer. Once the traffic is deemed safe, it is sent to your application servers. However, a recent DDoS attack managed to overwhelm your infrastructure, causing legitimate requests to hang. How can you configure your infrastructure to be more scalable and resilient to this kind of attack?
    * Run the proprietary firewall software on an autoscaling group of EC2 instances behind an internet facing elastic load balancer. Place another load balancer in front of your application servers.

1. Your web application is running on an auto-scaling group of EC2 instances behind an Elastic Load Balancer. You are receiving reports of multiple malicious requests which are attempting to perform a SQL injection attack. The requests are coming from a group of IP addresses in the same range. Which of the following could you do to block these requests to prevent them from impacting your application?
    * Use AWS WAF to block SQL injection attacks from this IP address range. AWS WAF is a web application firewall that helps protect web applications from attacks by allowing you to configure rules that allow, block, or monitor web requests based on conditions that you define. These conditions include IP addresses, HTTP headers, HTTP body, URI strings, SQL injection and cross-site scripting. GuardDuty is a Threat Detection service and cannot be used to block traffic. Inspector assesses applications for exposure, vulnerabilities, and deviations from best practices, it cannot be used to block traffic.
    * Use a NACL to block traffic from this IP range.

1. You are designing an e-commerce application which will run on a number of EC2 instances behind an Application Load Balancer, storing product and customer data in DynamoDB and product images in S3. In your previous role at another company, your systems were frequently targeted by SQL injection and cross-site scripting attacks. Which of the following can be used to protect against this type of attack?
    * AWS WAF.

1. You are helping an IT organization meet some security audit requirements imposed on them by a prospective customer. The customer wants to ensure their vendors uphold the same security practices as they do before they can become authorized vendors. The organization's assets consist of around 50 EC2 instances all within a single private VPC. The VPC is only accessible via an OpenVPN connection to an OpenVPN server hosted on an EC2 instance in the VPC. The customer's audit requirements disallow any direct exposure to the public internet. Additionally, prospective vendors must demonstrate that they have a proactive method in place to ensure OS-level vulnerabilities are remediated as soon as possible. Which of the following AWS services will fulfill this requirement?
    * Employ Amazon Inspector to periodically assess applications for vulnerabilities or deviations from best practices. AWS Inspector will proactively monitor instances using a database of known vulnerabilities and suggest patches.

1. You are troubleshooting a CloudFront setup for a client. The client has an Apache web server that is configured for both HTTP and HTTPS. It has a valid TLS certificate acquired from LetsEncrypt.org. They have also configured the Apache server to redirect HTTP to HTTPS to ensure a safe connection. In front of that web server, they have created a CloudFront distribution with the web server as the origin. The distribution is set for GET and HEAD HTTP methods using an Origin Protocol Policy of HTTP only. When a web browser tries to connect to the CloudFront URL, the browser just spins and never reaches the web server. However, when a web browser points to the web server itself, we get the page properly. Which of the following if done by themselves would most likely fix the problem?
    * Change the CloudFront distribution origin protocol policy to use only HTTPS or remove the redirection policy on the origin server and allow it to accept HTTP. With CloudFront only configured for HTTP Only, we have a loop when the web server redirects HTTP to HTTPS. We can either enable HTTPS on CloudFront or disable the redirection policy on the Apache server.

1. Your Head of Security has asked you to recommend a solution to protect your website against DDoS attacks, SQL injection and cross-site scripting attacks. Which of the following services do you recommend?
    * Use AWS Shield to protect against DDoS attacks.
    * Use AWS WAF to protect against DDoS attacks.
    * Use AWS WAF to protect against SQL injection.
    * Use AWS WAF to protect against cross-site scripting.

1. Your manager has developed a penetration test plan that targets many of the services contained within the company's AWS infrastructure. The penetration test plan is implemented in two stages. The first stage targets AWS services that do not need prior AWS approval while the second stage targets services that do require prior AWS approval. Your manager requests that you review his test plan and identify any issues or inconsistencies. From the following services, select those services that do not need prior AWS approval.
    * Permitted services are EC2 instances, NAT Gateways, ELBs, RDS, CloudFront, Aurora, API Gateways, AWS Lambda and Lambda Edge functions, LightSail resources, and Elastic Beanstalk environments.

1. Which of the following services can AWS WAF be deployed with?
    * Application Load Balancer.
    * CloudFront.

1. You are working as a Security Architect at a large retail bank, designing a new secure website which will enable customers to apply for a personal loan online. You would like to protect your application from attacks such as SQL injection and cross-site scripting. Which of the following AWS services would you consider using when planning this website?
    * Application Load Balancer. WAF is closely integrated with CloudFront and Application Load Balancer.
    * AWS WAF.
    * CloudFront.

1. AWS provides a number of security related managed services to help protect your infrastructure and applications running in the cloud. Which of the following can be used to protect against SQL injection and cross-site scripting attacks?
    * AWS WAF.

1. You have been asked to design a solution to perform deep packet inspection, which of the following can you use?
    * AWS Network Firewall. You can filter network traffic at the perimeter of your VPC using AWS Network Firewall. Network Firewall is a stateful, managed, network firewall and intrusion detection and prevention service. Rule groups in AWS Network Firewall provide detailed criteria for packet inspection and specify what to do when a packet matches the criteria. When Network Firewall finds a match between the criteria and a packet, the packet matches the rule group.

1. You are working for a charity which is working to monitor global climate change. You have created a VPC which has a private subnet and a public subnet with a NAT Gateway. You have been asked to provision a number of EC2 instances which will run an application which needs to download publicly available climate statistics from a government website. Which of the following options is the most secure way to configure this?
    * Launch the EC2 instances in the private subnet, route internet-bound traffic to the NAT Gateway in the public subnet to access the government website.

1. You have been asked to design an IPS/IDS solution to protect your AWS infrastructure from possible incidents, violations and threats. Which of the following do you recommend?
    * Search for a third-party solution in the AWS Marketplace digital catalogue. AWS acknowledge that they do not provide IPS/IDS. Instead, they suggest that third-party software can be used to provide additional functionality such as deep packet inspection, IPS/IDS, or network threat protection.

### Identity and Access Management

1.  You are designing a custom IAM policy that would allow users to list buckets in S3 only if they are MFA authenticated. Which of the following would best match this requirement?
    * The actions for ListAllMyBuckets and GetBucketLocation are required, and the type for the condition is also required. The policy should be:
    ```JSON
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation"
            ],
            "Resource": "arn:aws:s3:::*",
            "Condition": {
                "Bool": {
                    "aws:MutliFactorAuthPresent": true
                }
            }
        }
    }
    ```

1. A Lambda function reads metadata from an S3 object and stores the metadata in a DynamoDB table. The function is triggered whenever an object is stored within the S3 bucket. How should the Lambda function be given access to the DynamoDB table?
    * An IAM service role with permissions to write to the DynamoDB table should be created, and the role should be associated with the Lambda function.

1. Your company has defined privileged users for their AWS Account. These users are administrators for key resources defined in the company. There is now a mandate to enhance the security authentication for these users. How can this be accomplished?
    * MFA should be enabled for these users.

1. An application running on EC2 instances must use a username and password to access a database. The developer has stored these secrets in the SSM Parameter Store with type SecureString using the customer managed KMS CMK. Which combination of configuration steps will allow the application to access the secrets via the API? Select 2 answers from the options below.
    * The EC2 instance role needs permission to read the SSM parameter. The kms:Decrypt permission needs to be in the EC2 instance role so that the EC2 instances can use the KMS key. A sample policy that would be required is shown below:
    ```JSON
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ssm:GetParameter*"
                ],
                "Resource": "arn:aws:ssm:us-west-2:111122223333:parameter/ITParameters/*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "kms:Decrypt"
                ],
                "Resource": "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
            }
        ]
    }
    ```

1. You are creating a policy to allow users to have the ability to access objects in a bucket called appbucket. When you try to apply the policy, you get the error "Action does not apply to any resource(s) in statement". What should be done to rectify the error?
    ```JSON
    {
        "ID": "Policy1502987489630",
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Stmt1502987487640",
                "Action": [
                    "s3:GetObject",
                    "s3:GetObjectVersion"
                ],
                "Effect": "Allow",
                "Resource": "arn:aws:s3:::appbucket",
                "Principal": "*"
            }
        ]
    }
    ```
    * The Resource tag should be `arn:aws:s3:::appbucket/*`.

1. Your company is performing a security audit of your AWS environment. The security specialist asked you to provide a document that contained the status of all IAM users in the AWS account. The document should include information such as when users were created, when passwords were used or changed, whether MFA was enabled, etc. What is the best way to provide this documentation?
    * A credential report can be download through the AWS Management Console every 4 hours. AWS Config cannot provide the documentation required. The IAM CLI will only provide limited information in a JSON file.

1. The security team in your company will start a new security audit for all AWS accounts, and your manager asked you to present him with a document stating the IAM usage status in your AWS account. You have downloaded a recent credential report in IAM and replied to your manager. However, which information does NOT exist in the report?
    * IAM role information and SAML IAM identity provider information is not shown in the credential report.

1. In your AWS account A, there is an S3 bucket that contains artifacts that need to be fetched by an IAM user in another AWS account B. The S3 bucket has the below bucket policy:
    ```JSON
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::AccountB:user/AccountBUserName"
                },
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:PutObjectAcl"
                ],
                "Resource": [
                    "arn:aws:s3:::AccountABucketName/*"
                ]
            }
        ]
    }
    ```    
However, the IAM user in account B still cannot get objects in the S3 bucket. Which one may cause the failure?
    * The IAM user in account B may not have IAM permissions to get an object in the S3 bucket. 

1. You have maintained an AWS account A containing an S3 bucket that another AWS account B needs to upload files to. In the S3 bucket policy, s3:PutObject is allowed for the IAM user in account B. And the IAM user in account B can use `aws s3api put-object` to upload objects to the S3 bucket successfully. However, it has been found that users in AWS account A cannot open the new uploaded objects. How should you fix this issue?
    * The problem is that once account B has uploaded objects to the bucket in account A, the objects are still owned by account B, and account A does not have access to it. The option `--acl bucket-owner-full-control` should be added to the command `aws s3api put-object` to give permissions to the bucket owner for the objects.

1. Which of the following is used as a secure way to log into an EC2 Linux instance?
    * SSH key pairs are used to login to EC2 instance. IAM credentials are not relevant as they are of the AWS console. AWS Access Keys are not relevant as they are used to log into the AWS console and services using the command line.

1. Your company owns many AWS accounts managed by AWS Organizations. To meet security compliance, the CloudTrail should always be enabled in all AWS accounts. However, during the last couple of weeks, it was noticed that IAM users in certain AWS accounts disabled the CloudTrail feature. You need to add a restriction rule to prevent such actions. What is the best way to achieve that?
    * A Service Control Policy (SCP) can be configured to deny the CloudTrail StopLogging action and add the policy to the relevant OUs in the organisation. Configuring policies at the user level would be an inefficient method in this scenario.

1. You are working in the cloud security team in a big company. To meet security compliance, you oversee applying AWS Config rules to AWS accounts in other organizational units (OUs). However, it has been found that the Config rules may be deleted by IAM users accidentally in these AWS accounts. You need to prevent such actions from happening again. How should you implement this?
    * An SCP should be implemented that denies the DeleteConfigRule action. The new SCP should be applied to organisational units in the AWS Organization. Permission boundaries are not relevant in SCP.

1. Every application in a company's portfolio has a separate AWS account for development and production. The security team wants to prevent the root user and all IAM users in the production accounts from accessing a specific set of unneeded services. How can they control this functionality?
    * An SCP that denies access to the services can be created. If all production accounts are in the same OU, the SCP can be applied to that OU.

1. You are developing a mobile application utilising third-party social network IdP. What pieces of information below are required to configure a social IdP correctly?
    * The App Client ID, App Client Secret, and List of scopes are required for the social IdP. SAML assertions, OIDC tokens and claims are not relevant to setup the social IdP.

1. You are building a large-scale confidential documentation webserver on AWS, and all of the documentation for it will be stored on S3. One of the requirements is that it cannot be publicly accessible from S3 directly. You will need to use CloudFront to accomplish this. Which of the methods listed below would satisfy the requirements as outlined?
    * An Origin Access Identity (OAI) for CloudFront needs to be created and granted access to the objects in your S3 bucket.

1. A company has external vendors that must deliver files to the company. These vendors have cross-account permission to upload objects to one of the company's S3 buckets. Which step is required by the vendor to allow company users to access the files?
    * The key here is that the objects uploaded are not owned by the bucket owner. The object owner must first grant permissions via an ACL. A grant to the object's ACL should be added giving full permissions to the bucket owner. The bucket owner can then delegate these permissions via a bucket policy.

1. You have a paid service providing custom digital art that is hosted on AWS using S3. To promote your service, you wish to provide a limited sample of artwork to unauthenticated guest users for free. Which combination of steps will enable guest users to view your free subset of artwork?
    * An IAM role with appropriate S3 access permissions must be assigned, and unauthenticated identities in Amazon Cognito Identity Pools must be enabled.

1. You have built a tiered application with backend services hosted on AWS and user front end built as an Android native mobile application. You wish to expand your user pool and have decided to build an iOS native application. What is the recommended approach to ensure your user's data is synchronised across various user devices?
    * AWS AppSync enables subscriptions to synchronise data across devices.

1. Your application backend services are hosted on AWS and provide several REST API methods managed via AWS API Gateway. You have decided to start using AWS Cognito for your application's user management. What combination of steps is required to properly authorise a call to one of the REST API methods using an access token?
    * A COGNITO_USER_POOLS authoriser must be created. A single-space separated list of OAuth Scopes on the API method must be configured.

1. Your company CSO has directed you to enhance the security of a critical application by implementing a CAPTCHA as part of the user sign-in process. What is the most efficient method to implement this capability?
    * An Auth Challenge Lambda Trigger should be created. AWS Lambda functions can be created and then triggered during user pool operations such as user sign-up, confirmation, and authentication.

1. You are a security admin for an organisational unit named ‘DataAnalyticsTeam’. You wish to streamline some of the security processes and delegate some security tasks to the development team. To this end, you wish to enable the development team to create roles and policies that can be attached to the various AWS services they are using. However, the services that they create should be able to access S3 buckets restricted to only the "us-west-1" region. The development team members have the ‘DeveloperRole’ IAM role assigned to them. What combination of steps will accomplish this task?
    * The correct solution is to use permission boundaries. Firstly, create an IAM policy to allow access to S3 buckets in the desired region. Then create an IAM policy that will allow the creation of roles with a permission boundary. This will enable developers to create new roles and policies that have restrictions. Finally, attach the IAM policy to the developer's team role. The use of SCP and OU is not applicable in this scenario because limiting access to a specific region via SCP will also affect other members of the OU and not just the development team.

1. A company wishes to enable SSO so that its employees can log in to the AWS management console using their corporate directory identity. Which of the following step is required as part of the process?
    * Creating an IAM role that establishes a trust relationship between IAM and the corporate directory IdP is a necessary step.

1. A web application runs in a VPC on EC2 instances behind an ELB Application Load Balancer. The application stores data in an RDS MySQL DB instance. A Linux bastion host is used to apply schema updates to the database (administrators connect to the host via SSH from a corporate workstation). The following security groups are applied to the infrastructure:
    * **sgLB:** Associated with the ELB.
    * **sgWeb:** Associated with the EC2 instances.
    * **sgDB:** Associated with the database.
    * **sgBastion:** Associated with the bastion host.
What security group configuration will allow the application to be secure and functional?
    * On sgLB allow ports 80 and 443 from 0.0.0.0/0 (all internet traffic). On sgWeb allow ports 80 and 443 from sgLB (accessed only from ELB). On sgDB allow port 3306 from sgWeb and sgBastion (accessed by application and bastion). On sgBastion allow port 22 from the corporate IP address range.

1. Your financial services organisation is using the AWS S3 service to store highly sensitive data. What is the correct IAM policy that must be applied to ensure that all objects uploaded to the S3 bucket are encrypted?
    * The policy is shown below:
        ```JSON
        {
            "Version": "2012-10-17",
            "Id": "PutObjPolicy",
            "Statement": [
                {
                    "Sid": "DenyUnEncryptedObjectUploads",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:PutObject",
                    "Resource": "arn:aws:s3:::SensitiveDataBuket/*",
                    "Condition": {
                        "StringNotEquals": {
                            "s3:x-amz-server-side-encryption": "AES256"
                        }
                    }
                }
            ]
        }
        ```

1. You are trying to use the AWS Systems Manager run command on a set of Amazon Linux AMI instances. The run command is not working on a set of instances. What can you do to diagnose the issue?
    * Confirm that the SSM agent is running on the target machine. The SSM agent stores logs in `/var/log/amazon/ssm/error.log` that can assist troubleshooting problems. Note that port 22 is not used by the SSM agent.

1. You are working for a company and have been allocated to ensure that there is a federated authentication mechanism setup between AWS and their on-premises AD. Which of the following are important steps that need to be covered?
    * Determining how you will create and delineate your AD groups and IAM roles in AWS is crucial. SAML assertions to the AWS environment and the respective IAM role access will be managed through regex matching between your on-premises AD group name to an AWS IAM role. One approach is to select a common group naming convention. For example, your AD groups could start with an 'AWS-' identifier, then the 12-digit AWS account number, and finally the matching role name within the AWS account. AWS also needs to be configured as the relying party in AD FS.

1. Which technique can be used to integrate AWS IAM with an on-premises LDAP directory service for SSO access to the AWS console?
    * You can use SAML to provide your users with federated SSO to the AWS Management Console or federated access to call AWS API operations.

1. You are building a system to distribute confidential training videos to employees. Using CloudFront, what method could be used to serve content stored in S3, but not publicly accessible from S3 directly?
    * Create an Origin Access Identity (OAI) for CloudFront and grant access to the objects in your S3 bucket to that OAI. An OAI is a special CloudFront user who is assigned permission to read the objects in your bucket.

1. In order to meet data residency compliance requirements for a large bank, you must ensure that all S3 buckets are created in the eu-west-2 region. You plan to use SCP to enforce this rule. Which SCP will accomplish this?
    * Note that an explicit deny should be used so that another policy does not allow the creation of S3 buckets in this region. The SCP policy should be:
        ```JSON
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DataGovernancePolicy",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": [
                        "s3:CreateBucket"
                    ],
                    "Resource": "arn:aws:s3:::*",
                    "Condition": {
                        "StringNotLike": {
                            "s3:LocationConstraint": "eu-west-2"
                        }
                    }
                }
            ]
        }
        ```

1. You are designing a data lake for the analysis of financial data. The system consists of a data ingestion component utilising AWS Kinesis and a storage component utilising AWS S3. The data in Kinesis is encrypted by a CMK managed using AWS KMS. What is the best way to ensure that the CMK is only used by the AWS Kinesis service?
    * The key policy should be updated to include the condition:
        ```JSON
        "StringEquals": {
            "kms:ViaService": "kinesis_AWS_region.amazonaws.com"
        }
        ```

1. You currently have an S3 bucket hosted in an AWS account. It holds information that needs to be accessed by a partner account. Which is the MOST secure way to allow the partner account to access the S3 bucket in your account?
    * An IAM role should be created which can be assumed by the partner account, the ARN for the role should be provided to the partner account, and the partner should use an external id when making the request.

1. You have designed a travel website which allows users to share their photos from their trip and subscribe to receive notifications every time another member uploads a photo of one of their favourite destinations. Users upload their images to the website, which stores them in S3 and writes metadata about each photo in a DynamoDB table. When a photo is uploaded, a Lambda function will read the metadata from DynamoDB and send a notification to an SNS topic which notifies the subscribed users. During testing, you notice users are not being notified after a photo has been successfully uploaded, however when you test the Lambda function in isolation, it works perfectly. What might be causing this?
    * S3 does not have permission to invoke the Lambda function. The S3 bucket needs to invoke your Lambda function, therefore you need to grant the event source the necessary permissions to invoke Lambda using a resource-based policy. The Lambda function works fine in isolation, so it does not require any additional permissions to read S3 or DynamoDB.

1. You have developed an on-demand video website that allows paying customers to download instructional videos. The videos are stored in an S3 bucket, and access to the videos is implemented using pre-signed URLs. Management has just informed you that some customers are having issues downloading videos. You analyze the matter and determine that the pre-signed URLs are expiring before the URL expiration time that was specified when creating the pre-signed URL. Which of the following choices is the likely cause for this issue?
    * The pre-signed URL was created using a role. It is not recommended to generate pre-signed URLs using roles. Roles use temporary access credentials that can expire before the specified URL expiry. Pre-signed URLs do not use bucket policies. Identity Federation allows external sources to provide authorization to gain access to AWS resources and services but is not used to create pre-signed URLs. IAM users have long term credentials and can be used to create pre-signed URLs eliminating the problem associated with roles.

1. Your Chief Security Officer has mandated that all software license keys for your application running on EC2 instances must be stored centrally, in an encrypted format, in SSM Parameter Store. It is now time to upgrade the software, and in order to get access to the free upgrade, your application needs to access the license key string. You scheduled the upgrade for last weekend; however, most of the upgrades failed. What do you suspect the problem could be?
    * The EC2 instance role does not have permission to use KMS to decrypt the parameter.
    * The EC2 instance role does not have permission to read the parameter in SSM Parameter Store.

1. You are the Head of Security for the Gaming division of a large software company responsible for developing augmented reality games that users can play on their smartphones. Due to the popularity of your latest release, your organization is growing rapidly and as the infrastructure grows, you want to ensure that all new projects have complete segregation between Development, Testing and Production environments, to avoid sharing resources across different environments. Which of the following is the best option to achieve this?
    * Create one AWS account for production services, one for development, and one for testing. Account-level separation is strongly recommended for isolating production environments from development and test environments, or providing a strong logical boundary between workloads that process data of different sensitivity levels.

1. You are designing a pet supplies website, which allows customers to purchase treats and toys for their pets as well as book them in for routine events like grooming, puppy training and health checks. Your application code runs as a number of different Lambda functions, with static web content stored in S3 and persistent customer and product data in DynamoDB tables. During testing, you notice that customers are not able to update their contact details in your application, what could be the reason for this?
    * The Lambda execution role does not have permission to write to the DynamoDB table. The Lambda function will need permissions to read and write to the DynamoDB table. This should be done using an IAM role.

1. You are working as the lead Security Architect for a large retail bank and you have an external auditor visiting from your regulating body. The auditor will be spending the next two weeks with your team and needs access to read your CloudTrail logs in order to complete their assessment and they already have their own AWS account. How can you configure access for the Auditor to complete their assessment?
    * Create an IAM role in your account with an access policy allowing read-only access to the log files. Configure a trust policy in your account allowing the Auditor's AWS account to assume the role. You need to configure cross account access for the Auditor to enable them to have read only access to the relevant resources in your account - i.e. CloudTrail and the relevant S3 bucket. A trust policy is also required to enable the external account to assume the role.

1. You need to develop functionality that provides temporary security credentials for cross-account access from your development account to your production account. Which of the following is a valid Security Token Service (STS) action is typically used for cross-account delegation?
    * The AssumeRole action is typically used for cross-account delegation. The AssumeRoleWithSAML action obtains credentials through a SAML authentication response used to associate an organization's IdP to role-based AWS access. The AssumeRoleWithWebIdentity obtains credentials when authenticated by a web identity provider

1. You are developing a web application that requires user authentication. In the first six months, you expect the web application to have six thousand users, and shortly after that, up to a million users. Which of the following options are best suited to support these requirements?
    * Web Identity Federation and Amazon Cognito. Web Identity Federation allows external trusted ID providers (IdP), such as Amazon or Google, to authenticate and identify an unlimited number of users requesting access to AWS resources. Additionally, AWS recommends using Amazon Cognito in most scenarios because it acts as an identity broker and reduces the amount of federation work that would need to be performed.

1. You have a number of AWS accounts, one for each department in your company. Your Head of Security has asked you to make sure that nobody has access to disable CloudTrail in any of your accounts. How should you do this?
    * Create a new AWS Organization, group the accounts under a single OU and use a Service Control Policy to restrict any account in the OU from stopping CloudTrail. Service control policies (SCPs) are one type of policy that you can use to manage your organization. SCPs offer central control over the maximum available permissions for all accounts in your organization, allowing you to ensure your accounts stay within your organization’s access control guidelines.

1. Consider the below IAM policy statement: What does the following snippet from an IAM policy statement do?
    ```JSON
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": [
                    "arn:aws:s3:::my_bucket",
                    "arn:aws:s3:::my_bucket/*"
                ]
            }
        ]
    }
    ```
    * It allows user, group or roles with the IAM policy attached any S3 actions to ‘my_bucket’.

1. What is the recommended approach to configuring a mobile application to allow users to sign-in and sign-up to your application via Facebook?
    * Use Cognito as an Identity Broker between your application and the Web Identity Provider. Cognito is the preferred Web ID Federation mechanism in AWS Cognito For Mobile Apps.

1. You are working on a project to build an online fashion retail website. The application is running on an auto-scaling group of EC2 instances behind an Elastic Load Balancer. The application needs to access a DynamoDB table to find product information, including sizing measurements, fabric content and care instructions. Promotional images and videos of models wearing the products are stored in S3. How can you give the EC2 instances access to the product data, promotional images and videos?
    * Create an IAM role and assign read only permission to the DynamoDB table and the S3 bucket. Attach the role to the EC2 instance. An IAM role lets you define a set of permissions to access the resources that a user or service needs, but the permissions are not attached to a specific IAM user or group. Instead, IAM users, mobile and EC2-based applications, or AWS services like EC2 can programmatically assume the role. Distributing long-term IAM credentials to each instance is challenging to manage and a potential security risk.

1. Your manager has tasked you with developing a solution to allow a new customer, having an external account, to store objects into an S3 bucket in your production account. Your manager requires that all objects stored in the S3 bucket by the customer must be owned by the production account and not the customer. Which of the following solutions is best suited to address this requirement?
    * Create an IAM role in the production account that allows the customer to assume this role that provides the necessary permissions to store objects in the production account bucket. Three different approaches can be used to allow the external account to gain access to the S3 bucket in the production account. This can be achieved by using either the bucket's ACL, the bucket's policy, or creating an IAM role in the production account that the customer from the external account can assume. Implementing a solution using either the bucket's ACL or creating a bucket policy to allow the external account access to the production account's S3 bucket results in the copied object being owned by the external account and not the production account. The best-suited approach is to have the customer assume a role that provides the necessary permissions to copy objects to the S3 bucket. When the customer assumes the IAM role, the customer temporarily becomes an identity in the production account, which results in the copied object in the S3 bucket being owned by the production account.

### Data Protection

1. In your organisation, a customer-managed key named TestCMK has been created for a new project. This key is supposed to be used only by related AWS services in this project including EC2 and RDS in region us-west-2. For security concerns, you need to make sure that no other services can encrypt or decrypt using this CMK. In the meantime, EC2 and RDS should use the key without issues. How should you implement this?
    * An IAM policy is insufficient as it cannot restrict based on EC2 or RDS. A service role is also insufficient as other services could use the key if the role is attached to them. the key policy should be:
        ```JSON
        {
            "Condition": {
                "ForAnyValue:StringEquals": {
                    "kms:ViaService": [
                        "ec2.us-west-2.amazonaws.com",
                        "rds.us-west-2.amazonaws.com"
                    ]
                }
            }
        }
        ```

1. As a Cloud Security Engineer, you perform a security audit of AWS services that your company is using. You have found that for CMKs in KMS, the key policies are too open, allowing almost all services or users to use them. What condition can be added to the key policy to ensure that the grant should only be created by integrated AWS services rather than the user himself?
    * ViaService is not relevant here as that is to limit the use of a CMK to requests from specified AWS services. KeyOrigin is not relevant as that is used to control access to the CreateKey action, values can be AWS_KMS, AWS_CLOUDHSM, and external. GranteePrincipal is also not relevant here as that is used to restrict who can create grants based on the ARN. The condition in the policy should be:
        ```JSON
        "Condition": {
            "Bool": {
                "kms:GrantIsForAWSResource": "true"
            }
        }
        ```

1. Your team is developing a web application and EC2 instances are used. To be compliant with security requirements, EBS volumes need to be encrypted with a CMK. A new CMK was already created by you. You also enabled automatic key rotation for this key through the AWS console to avoid manually rotating the key. Which benefits can this configuration bring?
    * Key rotation only changes the KMS key's key material, which is the cryptographic material used in encryption operations. It has no effect on the data. It does not rotate the data keys that the KMS key generated or re-encrypt any data protected by the KMS key, and so will not mitigate the effect of a compromised data key. Rotation of a CMK will occur yearly automatically and result in an increase in cost by $1/month. The ARN of the key will not change after the automatic rotation.

1. A company wants to have a secure way of generating, storing, and managing cryptographic keys, but they want to have exclusive access to the management of the keys. Which of the following can be used for this purpose?
    * KMS cannot be used as the management of the keys will be within AWS. S3 Server Side encryption is not applicable as it does not generate or manage cryptographic keys. CloudHSM allows you to securely generate, store, and manage cryptographic keys.

1. You have an EC2 instance in a private subnet that needs to access the KMS service privately within the AWS network. Which of the following methods can help to fulfil this requirement, keeping security in perspective?
    * An Internet Gateway should not be used because if it is a private subnet the intention is that it cannot access the internet. An AWS VPN is not relevant as that is for connecting on-premises environments to AWS. VPC Peering is also not relevant as that is used for communication between several VPCs and would not help in this scenario. A VPC endpoint should be used to establish communication between your VPC and AWS KMS.

1. You are working as an AWS administrator of your company. As part of code deployment, you have provisioned EC2 instances with EBS volumes being encrypted using customer-managed CMK. The automatic key rotation is enabled. When will the KMS key be rotated automatically?
    * The customer-managed CMK gets rotated automatically every 365 days (only if it is enabled, which it is).

1. The cloud monitoring team is using AWS Config to perform security checks. One Config rule is to check if S3 buckets are encrypted using KMS. After the rule was executed, several S3 buckets were found to be non-compliant because they were not encrypted. To fix the non-compliance of these buckets, you have enabled the Default Encryption to be KMS using AWS Managed Key aws/s3. Your manager asked you how to manage the key rotation for this key. How should you answer this question?
    * For AWS managed keys, the key is automatically rotated every 3 years, and this cannot be changed.

1. You have a cron job that will run on the EC2 instance. The job calls a bash script that will encrypt a file whose size is about 2kB. You prefer that the encryption is performed through a CMK in MKS. So, you have created a CMK for this task. The script uses AWS CLI to do the encryption. How do you encrypt the file using the CMK in the bash script?
    * Use the command `aws kms encrypt` to encrypt the file. The encrypted KMS key is provided with the command as an argument. Envelope encryption refers to the practice of encrypting plaintext data with a data key, and then encrypting the data key under another key. This is used with CMKs. The `GenerateDataKey` and `GenerateDataKeyPair` operations return a plaintext data key and an encrypted copy of that data key.

1. As a DevOps engineer, you need to maintain Jenkins pipelines. Recently, you have created a new pipeline for a migration project. In one stage, you encrypted a file with the below command:
    ```bash
    aws kms encrypt \
        --key-id 1234abcd-fa85-46b5-56ef-123456789ab \
        --plaintext fileb://ExamplePlaintextFile \
        --output text \
        --query CiphertextBlob | base64 \
        --decode > ExampleEncrypted File
    ```
A CMK was used in the encryption operation. Then in another stage, the encrypted file needs to be decrypted with `aws kms decrypt`. What is true regarding the decryption command?
    * The key information does not need to be added to the command (assuming it was encrypted under a symmetric KMS key).

1. In your organisation, the security team requires that the key material of CMKs should be generated and maintained in your own infrastructure. Therefore, you have created key material in local servers and got it imported. Then the CMKs are used for encryption/decryption with various AWS services. Which configurations or operations can you perform on these CMKs?
    * Key rotation is not an option for CMKs with imported key material. The key material also cannot be exported outside of KMS, and a different key material cannot be imported into the same CMK. Key deletion can be done after a waiting period of 7 to 30 days, and key material can be manually deleted.

1. You are working in a financial company as a DevOps engineer. Your organisation is CMK in KMS for several AWS services. For the CMK, the key material was imported as the key material needs to be maintained on-premises instead of AWS. According to the company rule, the key material must be rotated every year. How should you rotate the CMK?
    * There is no automatic rotation of key material and you cannot reimport different key material. You also should not delete the old CMK and create a new one, as KMS needs to decrypt data that the original CMK encrypted, or it would be lost. You can create a new CMK with new key material and then change the key alias using the AWS CLI.

1. You have a Jenkins server deployed in EC2. One Jenkins pipeline is used to build artifacts. It needs to fetch some source files from an S3 bucket which is encrypted with a CUMK in KMS. The pipeline was working fine. However, it suddenly stopped working early this week. You have found that the Jenkins task failed to decrypt the S3 data using the CMK. What may be the cause of the failure?
    * It is likely that the key policy of the CMK was recently modified with a deny for the IAM role that the Jenkins EC2 instance is using.

1. As a DevOps engineer, you are helping the team to build up AWS services for a new project. Applications are deployed in two EC2 instances EC2A and EC2B. Both instances need to encrypt dozens of files using a CMK in KMS. The CMK has a key policy allowing both roles to access the key. EC2RoleB is the role used by EC2B and has an explicit deny. Which instances can use the CMK?
    * EC2A can use the CMK for encryption, EC2B cannot.

1. You want to launch an EC2 instance with your own key pair in AWS. After you generate the key pair through OpenSSL, how would you configure the key pair in EC2?
    * In the AWS Console, use "import key pair" to import the public key to the EC2 service.

1. You have a set of Keys defined using the AWS KSM service. You want to stop using a couple of keys but are not sure of which services are currently using the keys. Which of the following would be a safe option to stop using the keys from further usage?
    * The keys can be disabled to identify which services use the key.

1. A company has several CMK, some of which have imported key material. What could be done by the security team for the key rotation?
    * Automatic rotation is not possible for CMKs that have imported key material. New key material cannot be imported to an existing CMK and deleting an existing CMK will not automatically create one. New key material should be imported for a new CMK and the key alias of the old CMK should be pointed to the new CMK. The key can then be rotated manually through the CLI or AWS console. 

1. A company continuously generates sensitive records that it stores in an S3 bucket. All objects in the bucket are encrypted using SSE-KMS using one of the company's CMKs. Company compliance policies require that no more than one month of data be encrypted using the same encryption key. What solution will meet the company's requirement?
    * Do not delete the old key. Rotating the key material is not possible. Trigger a Lambda function with a monthly CloudWatch event that creates a new CMK and updates the S3 bucket to use the new CMK.

1. You need to have a cloud security device that would allow generating encryption keys based on the FIPS 140-2 Cryptographic Module Validation Program. Which of the following can be used for this purpose?
    * AWS KMS and AWS Cloud HSM can generate the required encryption keys.

1. A company stores critical data in an S3 bucket. There is a requirement to ensure that an extra level of security is added to the S3 bucket. In addition, it should be ensured that objects are available in a secondary region if the primary one goes down. Which of the following can help fulfill these requirements?
    * Bucket versioning and cross-region replication should be enabled. A condition should be added to the bucket policy to enable MFA using `aws:MultiFactorAuthAge`.

1. You have an EBS volume attached to a running EC2 instance that uses KMS for encryption. Someone has deleted the CMK which was used for the EBS encryption. Which of the following options is needed so that the EC2 instance can still use the EBS volume?
    * The deletion of the CMK has no immediate effect on the EC2 instance or the EBS volume because EC2 uses the plaintext data key (not the CMK) to encrypt the disk.

1. Your application currently uses customer keys which are generated via AMS KMS in the US east region. You now want to use the same set of keys from the EU-Central region. How can this be accomplished?
    * AMS KMS supports multi-region keys, which are AWS KMS keys in different AWS regions that can be used interchangeably. Multi-region keys are not global, you create a multi-region primary key and then replicate it into regions that you select within an AWS partition, then you can manage the key in each region independently.

1. Your company has created a set of keys using the AWS KMS service. They need to ensure that each key is only used for certain services. For example, they want one key to be used only by the S3 service. How can this be achieved?
    * The `kms:ViaService` condition key limits the use of a CMK to requests from particular AWS services.

1. You have a set of CMKs created using the AWS KMS service. These keys have been used for around 6 months. Recently there are some new KMS features, and the default key policy is updated to include certain new permissions. How would you update the key policies of the existing CMKs?
    * The key policies of existing CMKs are not updated automatically. Follow the AWS console alert in KMS and upgrade the key policies.

1. A company is using S3 to store data in the cloud, and they want to ensure that all the data in the bucket is encrypted. Which option meets this requirement with the least overhead?
    * Server sid encryption is the easiest. Use SSE-E3 with a CMK to allow managing the key policy and its rotation.

1. You are building a distributed HPC system that will process large multi-GB files. The sensitive nature of the data in these files requires them to be encrypted. What steps are the best approach to use AWS KMS to satisfy the encryption requirement?
    * The Encrypt API can encrypt up to 4 kB of data, which is not large enough for this question. You will need to use the GenerateDataKeyWithoutPlaintext API to generate a data key, and then distribute the key to the components of the system. The Decrypt API can be used to decrypt the data key, and the plaintext key can be used to encrypt the data.

1. A company is using a Redshift cluster as its data warehouse solution. There is a requirement from the internal IT security team to ensure that data gets encrypted at rest for the Redshift database. How can this be achieved?
    * The Redshift cluster can be encrypted with either AWS KMS or HSM.

1. You serve as a KMS Key Administrator for your company department. A KMS CMK with imported key material is about to expire. You need to use the same key material in the CMK and the application should use the same CMK. Which option should be used to rectify this situation?
    * You should encrypt the same key material and reimport the key material to the same CMK.

1. You serve as a KMS Key Administrator for your company department. You've created a new KMS CMK with imported key material. You're importing the key material into the KMS CMK. The import operation is failing. What are the possible causes of the problem?
    * The key material must be a 256-bit symmetric key. The import token has a 24-hour expiration time and must be imported before 24 hours.

1. Your company is using S3 for the storage of data in the cloud. They want to ensure that all data in the bucket is encrypted. Compliance policy specifies that the encryption key must be rotated every year. Which option meets this requirement with the least overhead?
    * S3 is not encrypted by default. AWS-KMS SSE should be enabled and key rotation for the CMK. AWS KMS rotates every year.

1. You are using a KMS key with imported key material. You have been asked by the head of Security to start rotating your key on an annual basis. The key has already been in use for over a year and you have been asked to perform the first rotation this week. How should you do this?
    * Keep the original KMS key enabled so that AWS KMS can decrypt data that the original KMS key encrypted. When you begin using the new KMS key, be sure to keep the original KMS key enabled so that AWS KMS can decrypt data that the original KMS key encrypted.
    * Create a new KMS key and use it in place of the original KMS key. When the new KMS key has different cryptographic material than the current KMS key, using the new KMS key has the same effect as changing the key material in an existing KMS key. This is known as manual key rotation.
    * Note that automatic key rotation is not supported for imported keys, asymmetric keys, or keys generated in an AWS CloudHSM cluster using the AWS KMS custom key store feature.

1. You are working for an investment bank which is designing a new application to analyse historical trading data, and use machine learning to predict stock market performance. The application is running in AWS and needs to access the historical data stored in a proprietary time series database located in your data centre. This information is highly confidential and could cause serious repercussions if any data was ever leaked to the public or your competitors. The application itself is extremely sensitive to network inconsistencies and during testing it frequently crashes if the network is not reliable. How should you configure the network connectivity for this application?
    * Configure a VPN between your VPC and the data centre over a Direct Connect connection. With AWS Direct Connect plus VPN, you can combine one or more AWS Direct Connect dedicated network connections with the Amazon VPC VPN. This combination provides an IPsec-encrypted private connection that also reduces network costs, increases bandwidth throughput, and provides a more consistent network experience than internet-based VPN connections.

1. You are about to begin using KMS to encrypt data in your AWS account. Your CTO asks you to create a key which can be automatically rotated once per year. Which type of key should you use?
    * Use a CMK managed by you. A customer managed CMK supports automatic key rotation once per year. AWS managed keys automatically rotate once every three years. Automatic key rotation is not available for CMKs that have imported key material.

1. You have given a new system administrator the ability to administer CMKs but not permission to perform cryptographic operations. Which of the following CMK operations can the new employee perform?
    * They can perform the DescribeKey, EnableKey, and CreateKey operations. CMK administrative actions include CreateKey, EnableKey, DescribeKey, and others as well. However, the actions, Encrypt, Decrypt, and GenerateKey are required to perform cryptographic operations. Structuring permissions between the administration of the key and the cryptographic usage of that key adds a layer of security consistent with the principle of least privilege.

1. You are using a CMK with imported key material. One of your administrators accidentally deleted the CMK key material and you can now no longer access any of your encrypted files. You still have the same key material that was originally imported into the CMK. What can you do to fix this?
    * Re-import the same key material to your CMK. If you delete the key material, the CMK's key state changes to pending import, and the CMK becomes unusable. To use the CMK again, you must reimport the same key material. You cannot import the key material into a different key or import different key material, this will not work.

1. Although you have recommended using SSE-KMS encryption, your new client insists that you use SSE-S3 to encrypt and store highly sensitive information into an S3 bucket. You have created a bucket policy that references the header s3:x-amz-server-side-encryption key, which is used to test against a specific value that corresponds to SSE-S3 encryption. Which statement below is most closely suited to signal that SSE-S3 encryption is to be used?
    * StringEquals: s3:x-amz-server-side-encryption: AES256. The only other valid option is aws:kms which is for specifying KMS encryption.

1. Which statements about Amazon Macie are true?
    * It uses NLP methods to understand data.
    * It can detect when large quantities of business-critical documents are shared - both internally and externally.
    * It can identify PII in S3 buckets.

1. Per the requirements of a government contract which your company recently won, you must encrypt all data at rest. Additionally, the material used to generate the encryption key cannot be produced by a third-party because that could result in a vulnerability. You are making use of S3, EBS and RDS as data stores, so these must be encrypted. Which of the following will meet the requirements at the least cost?
    * Use AMS KMS to create a customer-managed CMK. Create a random 256-bit key and encrypt it with the wrapping key. Import the encrypted key with the import token. When creating S3 buckets, EBS volumes or RDS instances, select the CMK from the dropdown list.

1. Which of the following AWS services allow native encryption of data, while at rest?
    * EBS, S3 and EFS all allow the user to configure encryption at rest using either the AWS Key Management Service (KMS) or, in some cases, using customer provided keys. The exception on the list is ElastiCache for Memcached which does not offer a native encryption service, although ElastiCache for Redis does.

1. You are planning to use KMS to encrypt data in your AWS account. According to company policy, you need to be able to rotate the CMK every three months. Which type of key should you use?
    * Use a CMK managed by you. You can rotate keys according to your own schedule using a customer managed CMK. An AWS managed or AWS owned CMK does not give you the option to rotate according to your own schedule. AWS managed keys automatically rotate once every three years.

1. You need to temporarily delegate access to your internal auditor to decrypt encrypted files stored in S3. How can you do this in AWS?
    * Use a KMS Grant to grant access to use the CMK. With grants you can programmatically delegate the use of KMS CMK to other AWS principals. You can use them to allow access, but not deny it. Grants are typically used to provide temporary permissions or more granular permissions.

1. A number of users are trying to access objects in your S3 bucket, however they are receiving the error : HTTP 403: Access Denied. You have already checked the bucket ACLs and bucket policy and they look fine. You checked the IAM permissions of the users and they all have read access to the bucket. What else could be the problem?
    * To troubleshoot HTTP 403: Access Denied errors from Amazon S3, check the following: Permissions for bucket and object owners across AWS accounts, Issues in bucket policy or AWS Identity and Access Management (IAM) user policies, User credentials to access Amazon S3, VPC endpoint policy, Missing object, Object encryption by AWS Key Management Service (AWS KMS), Requester Pays enabled on bucket, AWS Organizations service control policy.

1. Your CEO asks you to design a proactive approach to protect against unauthorized data access in the event that one of the company's CMKs becomes compromised. What is your recommendation?
    * Avoid using a single key for everything and implement an appropriate key rotation schedule. Many organizations rotate CMKs yearly, however the frequency of key rotation is highly dependent upon local laws, regulations, and corporate policies. You can minimize the blast radius of a compromised key by using different keys for different purposes rather than a single key for everything. Deleting a key must be very carefully thought out. Data can’t be decrypted if the corresponding CMK has been deleted. Once a CMK is deleted, it’s gone forever.

1. You are working for an online retail company selling bathroom accessories. Your applications store a lot of data in S3 including customer related data, marketing preferences as well as supplier contact details and credit referencing data. Your Head of Security has asked you to prepare a presentation to the leadership team explaining the controls you have in place for storing PII, including a list of all S3 buckets which include files containing PII. How will you approach this?
    * Use Macie to identify files containing PII in your S3 buckets.

1. You are designing a workflow that will handle very confidential healthcare information. You are designing a loosely coupled system comprised of different services. One service handles a decryption activity using a CMK stored in AWS KMS. To meet very strict audit requirements, you must demonstrate that you are following the Principle of Least Privilege dynamically--meaning that processes should only have the minimal amount of access and only precisely when they need it. Given this requirement and AWS limitations, what method is the most efficient to secure the Decryption service?
    * In the step right before the Decryption step, programmatically apply a grant to the CMK that allows the service access to the CMK key. In the step immediately after the decryption, explicitly revoke the grant.
