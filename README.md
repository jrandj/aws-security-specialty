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

    * The AWS Trust & Safety Team may send an abuse report to the security contact on your account. The notice should be reviewed to see what content or activity was reported. Logs that implicate abuse are included along with the abuse report.

    * You need to reply to the report to explain how you're preventing the abusing activity from recurring. You can also reply to obtain more information.

    * The following steps are recommended if notified of a potential security anomaly on an EC2 instance:
        * Capture  the  metadata  from  the  Amazon  EC2  instance,  before  you  make  any  changes  to  your environment.
        * Protect  the  Amazon  EC2  instance  from  accidental  termination  by  enabling  termination  protection  for the  instance.
        * Isolate  the  Amazon  EC2  instance  by  switching  the  VPC  Security  Group.  However,  be  aware  of  VPC connection  tracking  and  other  containment  techniques.
        * Detach  the  Amazon  EC2  instance  from  any  AWS  Auto  Scaling  groups.
        * Deregister  the  Amazon  EC2  instance  from  any  related  Elastic Load Balancing  service.
        * Snapshot  the  Amazon  EBS  data  volumes  that  are  attached  to  the  EC2  instance  for  preservation  and follow-up  investigations.
        * Tag  the  Amazon  EC2  instance  as  quarantined  for  investigation,  and  add  any  pertinent  metadata,  such as  the  trouble  ticket  associated  with  the  investigation.

1. Analyze logs relevant to a reported instance to verify a breach, and collect relevant data.

    * Before logs can be analysed your workloads must be configured to log. This includes application logs, resource logs, and AWS service logs. AWS CloudTrail, Amazon CloudWatch Logs, Amazon GuardDuty, and AWS Security Hub should all be enabled.

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

    * The AWS Security Incident Response Guide contains additional details on this topic.

1. Recommend services, processes, procedures to remediate gaps.

    * The AWS Security Incident Response Guide contains additional details on this topic.

### Evaluate the configuration of automated alerting, and execute possible remediation of security-related incidents and emerging issues.

1. Automate evaluation of conformance with rules for new/changed/removed resources.

    * A custom AWS Config rule can be created. The rule can be set to trigger based on configuration changes, such as whether a resource is created, changed, or deleted. For example, the rule can require that EC2 volumes are encrypted.

1. Apply rule-based alerts for common infrastructure misconfigurations.

    * An AWS Lambda function can provide an alert based on an AWS Config rule.

1. Review previous security incidents and recommend improvements to existing systems.

    * The AWS Security Incident Response Guide contains additional details on this topic.

## Logging and Monitoring

### Design and implement security monitoring and alerting.

1. Analyze architecture and identify monitoring requirements and sources for monitoring statistics.

    * AWS CloudWatch is a monitoring service for AWS cloud resources and the applications you run on AWS.

    * CloudWatch can provide real time metrics, alarms, and notifications. CloudWatch Logs are pushed from some AWS services and are stored internally indefinitely. EventBridge can provide a near real-time stream of system events.

1. Analyze architecture to determine which AWS services can be used to automate monitoring and alerting.

    * AWS provides additional instance status data than the state (pending, running, stopping etc.) of an instance. This data can troubleshoot network connectivity, system power, software, and hardware issues on the host. These checks can be viewed in the console or using the CLI.

    * A CloudWatch alarm can be created from the Status Checks tab of the instance. The action can be set to send a notification to AWS SNS.

    * AWS EventBridge (previously called CloudWatch Events) can automate AWS services and respond automatically to system events.

1.  Analyze the requirements for custom application monitoring, and determine how this could be achieved.

1.  Set up automated tools/scripts to perform regular audits.

    * CloudWatch can be used to create notifications. A metric filter is created, and then an alarm is defined including the notification action that needs to occur.

### Troubleshoot security monitoring and alerting.

1. Given an occurrence of a known event without the expected alerting, analyze the service functionality and configuration and remediate.

1. Given an occurrence of a known event without the expected alerting, analyze the permissions and remediate.

1.  Given a custom application which is not reporting its statistics, analyze the configuration and remediate.

1.  Review audit trails of system and user activity.

    * CloudTrail logs calls to the AWS APIs for most services. It does not log events such as SSH or RDP access to an EC2 instance in AWS.

    * Logged data is metadata around API calls. For example, the identity of the API caller, the time, the source IP, the request parameters, and the response.

    * Event logs are sent to an S3 bucket every 5 minutes with up to a 15-minute delay. Notifications can be configured based on the log contents. The retention of the log files is managed in S3. Logging can be aggregated across regions and across accounts.

    * Log file integrity validation includes SHA-256 hashing and RSA for digital signing. Log files are delivered with a digest file that can be used to validate the integrity of the log file.

    * CloudTrail logs need to be secured as they may contain PII such as usernames and emails. Only security personnel should be granted administrator access to CloudTrail using IAM. Access to the S3 bucket containing the logs should be controlled using bucket policies, and MFA should be required for delete on those objects. Lifecycle rules should be used to move log files to Glacier or to delete them.

    * By default CloudTrail logs are encrypted by SSE-S3 even if there is no S3 bucket level encryption.

    * Auditors are given access to CloudTrail logs through the AWSCloudTrailReadOnlyAccess IAM Policy.

### Design and implement a logging solution.

1.  Analyze architecture and identify logging requirements and sources for log ingestion.

1. Analyze requirements and implement durable and secure log storage according to AWS best practices.

1.  Analyze architecture to determine which AWS services can be used to automate log ingestion and analysis.

### Troubleshoot logging solutions.

1.  Given the absence of logs, determine the incorrect configuration and define remediation steps.

    * If CloudTrail logs are not appearing in S3, first check if CloudTrail is enabled. Also check that the correct S3 bucket name is provided and that the S3 Bucket Policy is correct.

    * S3 and Lambda Data Events are high volume, so they are not enabled by default as they also incur added costs.

1. Analyze logging access permissions to determine incorrect configuration and define remediation steps.

    * Always check that IAM users have the correct permissions to allow them to do what they need to do. This includes IAM permissions as well as resource level permissions.

    * CloudWatch Logs require an agent to be installed and running on an EC2 instance.

    * For EventBridge the Event Target needs the correct permissions to take whatever action it needs to. For example, if Lambda is expected to terminate unauthorised instances it will need the permission for termination.

1.  Based on the security policy requirements, determine the correct log level, type, and sources.

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

    * VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. Flow log data is stored using Amazon CloudWatch Logs. After you've created a flow log, you can view and retrieve its data in Amazon CloudWatch Logs.

    * You cannot enable flow logs for VPCs that are peered with your VPC unless the peer VPC is in your account. You cannot tag a flow log. Once you've created a flow log, you cannot change its configuration.

    * Not all IP traffic is monitored. For example, instances contacting the Amazon DNS server (if you used your own DNS server that would be logged), DHCP traffic etc.

1.  Given a description of the network infrastructure for a VPC, analyze the use of subnets and gateways for secure operation.

    * A VPC is a logical datacentre in AWS. It consists of IGWs, Route Tables, Network Access Control Lists, Subnets, and Security Groups. 1 Subnet corresponds to 1 Availability Zone.

    * A NAT instance enables instances in a private subnet to initiate outbound IPv4 traffic to the internet or other AWS services, but prevent the instances from receiving inbound traffic initiated on the internet.

    * When creating a NAT instance, you must disable the Source/Destination Check on the instance. NAT instances must be in a public subnet, and there must be a route out of the private subnet to the NAT instance. The amount of traffic that a NAT instance can support depends on the instance size. NAT instances also sit behind a security group.

    * NAT Gateways are much preferred to NAT instances. They automatically scale, are more secure, patch automatically (but no SSH access) etc. They are not associated with security groups.
    
    * A NAT is used to provide internet traffic to EC2 instances in private subnets. A Bastion is used to securely administer E2 instances (using SSH or RDP) in private subnets. In Australia they are called jump boxes.

    * An Internet Gateway allows instances with public IPs to access the internet. A NAT Gateway (or NAT instance) allows instances with no public IPs to access the internet.

    * Remember that a Security Group is the firewall of EC2 Instances, and a NACL is the firewall of the VPC Subnets. An example architecture is shown below to illustrate this:
        <p align="center">
        <img src="/res/network.JPG">
        </p>

### Troubleshoot a secure network infrastructure.

1. Determine where network traffic flow is being denied.

    * Check routing tables, Security Groups, and NACLs. VPC Flow Logs will show allow and deny messages useful for troubleshooting.

    * Remember that NACLs are stateless so you need to configure both inbound and outbound rules. Security Groups are stateful, so you only need 1 rule. 

1. Given a configuration, confirm security groups and NACLs have been implemented correctly.

    * A VPC automatically comes with a default NACL, and by default it allows all inbound and outbound traffic. You can create custom NACLs. By default, each custom NACL denies all inbound and outbound traffic until you add rules.

    * Each subnet in your VPC must be associated with a NACL. If you don't explicitly associate a subnet with a NACL, the subnet is automatically associated with the default NACL.

    * You can associate a NACL with multiple subnets. However, a subnet can be associated with only one NACL at a time. When you associate a NACL with a subnet, the previous association is removed.

    * NACLs contain a numbered list of rules that is evaluated in order, starting with the lowest numbered rule. NACLs have separate inbound and outbound rules, and each rule can either allow or deny traffic. NACLs are stateless. Responses to allowed inbound traffic are subject to the rules for outbound traffic (and vice versa.).

    * IP addresses can be blocked using NACLs but not Security Groups.

### Design and implement host-based security.

1. Given security requirements, install and configure host-based protections including Inspector, SSM.

1. Decide when to use host-based firewall like iptables.

1. Recommend methods for host hardening and monitoring.

    * Dedicated instances and dedicated hosts have dedicated hardware. Dedicated instances are charged y the instance, and dedicate hosts are charged by the host. If you have specific regulatory requirements or licensing conditions, choose dedicated hosts. Dedicated instances may share the same hardware with other AWS instances from the same account that are not dedicated.

    * EC2 runs on a mixture of Nitro and Xen hypervisors. Eventually all EC2 will be based on Nitro. Both hypervisors can have guest operating systems running either as Paravirtualisation (PV) or using Hardware Virtual Machine (HVM).

    * HVM is preferred over PV where possible. PV is isolated by layers with the guest OS on layer 1 and applications on layer 3. Only AWS administrators have access to hypervisors. All storage memory and RAM is scrubbed before assigned to an EC2 instance.

## Identity and Access Management

### Design and implement a scalable authorization and authentication system to access AWS resources.

1. Given a description of a workload, analyze the access control configuration for AWS services and make recommendations that reduce risk.

1. Given a description how an organization manages their AWS accounts, verify security of their root user.

    * If the root user has left, several tasks are required. A new root user password with a strong password policy should be created. The previous MFA should be deleted and recreated. Any root user Access Key ID and Secret Access Key should be deleted. Other user accounts should be checked and deleted if not legitimate.

1. Given your organization’s compliance requirements, determine when to apply user policies and resource policies.

1. Within an organization’s policy, determine when to federate a directory services to IAM.

    * The AWS Security Toke Service (STS) provides a SAML token after authenticating against an LDAP directory (such as AD). Once we have the token, any attempt to access an AWS resource will go via IAM first to check the token.
 
1. Design a scalable authorization model that includes users, groups, roles, and policies.

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

### Troubleshoot an authorization and authentication system to access AWS resources.

1. Investigate a user’s inability to access S3 bucket contents.

1. Investigate a user’s inability to switch roles to a different account.

    * For cross account access to S3:
        * The IAM policy in the external account needs to allow the user to call STS:AssumeRole.
        * The IAM policy in the trusting account needs to allow the action.

    * For cross account access to KMS:
        * The Key Policy must allow access to the external account as well as the IAM policy in the local account.

1. Investigate an Amazon EC2 instance’s inability to access a given AWS resource.

    * If Lambda cannot perform an action (e.g., write to S3, log to CloudWatch), first check that the Lambda execution role has the correct permissions. If EventBridge or some other event source cannot invoke a Lambda function, double check that the Function policy allows it.

    * Some services have their own resource-based policies which can also impact who or what can access them (e.g., S3 Bucket Policies, Key Policies).

## Data Protection

### Design and implement key management and use.

1. Analyze a given scenario to determine an appropriate key management solution.

    * AWS Key Managemnet Service (KMS) is a service for managing encrytion keys that is used for both client side (optional) and server-side encryption with AWS. KMS only manages Customer Master Keys (CMKs) and it uses Hardware Security Modules (HSMs) to store the keys.

    * KMS supports symmetric and asymmetric keys. A symmetric key never leaves KMS unencrypted, so to use it you must call AWS KMS. For an asymmetric key pair, the private key never leaves KMS unencrypted, but the public key can be downloaded and used outside of KMS. A symmetric key is recommended for most use cases as it is fast and efficient. An asymmetric key pair is required if you need users outside of AWS to encrypt data, as they can use the public key to encrypt. The public key of an asymmetric key pair can be used to sign messages and verify signatures.

    * KMS only manages CMKs, it does not manage data keys. A CMK never leaves the region that it was created and can only encrypt a maximum of 4kB of data. Data Keys can be used for larger object encryption.

    * Many data keys can be generated from a CMK. These are not stored or managed in KMS. The plaintext data key is used to encrypt the data and is then deleted. This process is shown below:
        <p align="center">
        <img src="/res/keys.JPG">
        </p>

    * To decrypt, first call the KMS API with the encrypted data key to return the plaintext data key. The plaintext data key can be used to decrypt the encrypted data.

1. Given a set of data protection requirements, evaluate key usage and recommend required changes.

    * Knowing how a KMS key was used in the past might help you decide whether you will need it in the future. All AWS KMS API activity is recorded in AWS CloudTrail log files. If you have created a CloudTrail trail in the region where your KMS key is located, you can examine your CloudTrail log files to view a history of all AWS KMS API activity for a particular KMS key.

1. Determine and control the blast radius of a key compromise event and design a solution to contain the same.

    * It is recommended to define classification levels and have at least one CMK per level. For example, you could define a CMK for data classified as “Confidential,” and so on. This ensures that authorized users only have permissions for the key material that they require to complete their job.

    * Creating KMS keys within each account that requires the ability to encrypt and decrypt sensitive data works best for most customers, but another option is to share the CMKs from a few centralized accounts. Maintaining the CMKs in the same account as the majority of the infrastructure using them helps users’ provision and run AWS services that use those keys

### Troubleshoot key management.

1. Break down the difference between a KMS key grant and IAM policy.

    * When authorising access to a KMS key, AWS KMS evaluates the following:
        * The key policy that is attached to the key. The key policy is always defined in the AWS account and Region that owns the KMS key. The Key Policy is a resource based policy attached to the CMK, it defines key users and key administrators and trusted external accounts.
        * All IAM policies that are attached to the IAM user or role making the request. IAM policies that govern a principal's use of a KMS key are always defined in the principal's AWS account. The IAM Policy is assigned to a User, Group, or Role, and defines the allows actions e.g. kms:ListKeys.
        * All grants that apply to the KMS key. Grants are advanced mechanisms for specifying permissions that you or an AWS service integrated with AWS KMS can use to specify how and when a KMS key can be used. Grants are attached to a KMS key, and each grant contains the principal who receives permission to use the KMS key and a list of operations that are allowed. Grants are an alternative to the key policy, and are useful for specific use cases.
        * Other types of policies that might apply to the request to use the KMS key, such as AWS Organizations service control policies and VPC endpoint policies. These policies are optional and allow all actions by default, but you can use them to restrict permissions otherwise given to principals.

1. Deduce the precedence given different conflicting policies for a given key.

    * AWS KMS evaluates the above policy mechanisms together to to determine whether access to the KMS key is allowed or denied. This is illustrated below:
        <p align="center">
        <img src="/res/key_authorisation.JPG">
        </p>

    * The authorisation part determines whether you are permitted to use a KMS key based on its key policy, IAM policies, grants, and other applicable policies. The trust part determines whether you should trust a KMS key that you are permitted to use. In general, you trust the resources in your AWS account. But you can also feel confident about using KMS keys in a different AWS account if a grant or IAM policy in your account allows you to use the KMS key.

1. Determine when and how to revoke permissions for a user or service in the event of a compromise.

    * In the event of a compromise all root and IAM user access keys should be rotated. Once the key is rotated, disable the original keys and update your applications to use the new keys. If there are no issues then you can delete the original keys.

    * If access is permitted with a long session duration time (such as 12 hours), their temporary credentials do not expire as quickly. You can immediately revoke all permissions to the role's credentals issuesd before a certain point in time if needed.

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
        * **Effect (Required):** The effect specifies whether to allow or deny the permissions in the policy statement. The Effect must be Allow or Deny. If you don't explicitly allow access to a KMS key, access is implicitly denied. You can also explicitly deny access to a KMS key. You might do this to make sure that a user cannot access it, even when a different policy allows access.
        * **Principal (Required):** The principal is the identity that gets the permissions specified in the policy statement. You can specify AWS accounts (root), IAM users, IAM roles, and some AWS services as principals in a key policy. IAM groups are not valid principals.
        * **Action (Required):** Actions specify the API operations to allow or deny. For example, the kms:Encrypt action corresponds to the AWS KMS Encrypt operation. You can list more than one action in a policy statement. For more information, see Permissions reference.
        * **Resource (Required):** In a key policy, the value of the Resource element is "*", which means "this KMS key." The asterisk ("*") identifies the KMS key to which the key policy is attached.
        * **Condition (Optional):** Conditions specify requirements that must be met for a key policy to take effect. With conditions, AWS can evaluate the context of an API request to determine whether or not the policy statement applies.

When the principal is another AWS account or its principals, the permissions are effective only when the account is enabled in the Region with the KMS key and key policy.

1. Distinguish the compliance state of data through tag-based data classifications and automate remediation.

1. Evaluate a number of transport encryption techniques and select the appropriate method (i.e., TLS, IPsec, client-side KMS encryption).

## Appendix

### Key Tools and Technologies

1. AWS CLI

1. AWS SDK

1. AWS Management Console

1. Network analysis tools (packet capture and flow captures)

1. SSH/RDP

    * Session Manager is the AWS recommended approach for establishing interactive sessions with EC2. It can be used via the browser, CLI, or SDK. It provides TLS encryption without the need for any bastion hosts or ports. Logging is also provided for CloudTrail, CloudWatch, and S3.

1. Signature Version 4

1. TLS

1. Certificate management

    * SSL certificates renew automatically, provided you purchased the domain name from Route53 and it's not for a private hosted zone. You can use Amazon SSL certificates with load balances and CloudFront, but you cannot export the certificates.

1. Infrastructure as code (IaC)

### AWS Services and Features

1. AWS Audit Manager

1. AWS CloudTrail

1. Amazon CloudWatch

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

1. AWS Firewall Manager

1. AWS Network Firewall

    * AWS WAF and host-based firewalls such as iptables and Windows firewall do not provide network packet inspection (IDS/IPS). To provide this capability third party software can be installed on EC2 from the AWS Marketplace.

1. AWS Security Hub

    * Security Hub provides a single place to manage and aggregate the findings and alerts from key security service. It integrates with a lot of AWS security services. Automated ongoing security auditing and built-in checks for PCI-DSS and CIS are provided.

1. AWS Shield

    * Shield is a managed DDoS protection service for ELB, CloudFront and Route 53 that safeguards applications running on AWS. Primarily protects against layer 3 and layer 4 attacks.
 
    * The advanced option costs $3000 per month and gives you an incident response team and in-depth reporting. You won't pay if you are the victim of an attack.

1. Amazon VPC
    * VPC endpoints

    * Network ACLs

    * Security groups

1. AWS WAF

    * Web Application Firewall (WAF) lets you monitor the HTTP and HTTPS requests that are forwarded to Amazon CloudFront or an application load balancer. It does not integrate with services like EC2 directly. You can configure conditions such as what IP addresses are allowed to make this request or what query string parameters need to be passed for the request to be allowed.

    * As a basic level WAF allows 3 different behaviours:
        * Allow all requests except the ones that you specify.
        * Block all requests except the ones that you specify.
        * Count the requests that match the properties that you specify.

    * Application load balancers integrate with WAF at a regional level, while CloudFront is at a global level.

    * You need to associate your rules to AWS resources in order to be able to make it work.

    * You can use AWS WAF to protect web sites not hosted in AWS via CloudFront. CloudFront supports custom origins outside of AWS.

    * WAF supports both IPv4 and IPv6 and IP's can be blocked at a /8, /16, /24, and /32 level.

1. AWS Certificate Manager (ACM)

    * ACM lets you provision, manage, and deploy public and private certificates for use with AWS services. Supported services include:
        * ELB
        * CloudFront
        * Elastic Beanstalk
        * API Gateway
        * Nitro Enclaves
        * CloudFormation

1. AWS CloudHSM

    * CloudHSM helps you meet corporate, contractual, and regulatory compliance requirements for data security by using dedicated Hardware Security Module (HSM) appliances within the AWS cloud. CloudHSM is provided in a single tenancy.

    * There are 4 type of CloudHSM users:
        * **Precrypto Officer (PRECO):** A temporary user with a default user name and password. They can only change their password (to become the Primary Crypto Officer) and perform read-only operations on the HSM.
        * **Crypto Officer (CO):** Performs user management operations. For example, creating and deleting users and changing user passwords
        * **Crypto Users (CU):** Performs key management operations. For example, creating, deleting, and importing cryptographic keys. Also uses cryptographic keys for encryption.
        * **Appliance User (AU):** Can perform cloning and synchronisation operations. The AU exists on all HSMs and has limited permissions.

1. AWS Directory Service

1. Amazon GuardDuty

    * GuardDuty is a threat detection service which uses ML to continuously monitor for malicious behaviour, particularly around EC2 instances. This includes unusual API calls or calls from a known malicious IP, attempts to disable CloudTrail logging, port scanning etc.

    * Alerts appear in the GuardDuty console and EventBridge. Automated responses can be setup using EventBridge and Lambda.

    * GuardDuty requires 7-14 days to set a baseline for what is normal behaviour on your account.

1. AWS Identity and Access Management (IAM)

1. Amazon Inspector

    * Inspector is an automated security assessment service that helps improve the security and compliance of applications deployed on AWS. Inspector automatically assesses applications for vulnerabilities or deviations from best practices. After performing an assessment, Inspector produces a detailed list of security findings prioritised by level of severity. These findings can be reviewed directly or as part of detailed assessment reports which are available via the Inspector console or API.

    * Inspector supports the following rules packages:
        * Common vulnerabilities and exposures
        * CIS operating system security configuration benchmarks
        * Security best practices
        * Runtime behaviour analysis

    * Inspector uses high, medium, low, and informational levels for rules.

1. AWS Key Management Service (AWS KMS)

    * KMS is a managed service that makes it easy for you to create and control the encryption keys used to encrypt your data and uses Hardware Security Modules (HSMs) to protect the security of your keys.

    * The Customer Master Key (CMK) includes the alias, creation date, description, key state, and key material (either customer provided, or AWS provided). It can never be exported.

    * To setup a CMK:
        * Create an alias and description.
        * Choose material option.
        * Define key administrative permissions (IAM users/roles that can administer but not use the key through the KMS API).
        * Define key usage permissions (IAM users/roles that can use the key to encrypt and decrypt data).

    * If you use your own key material you can delete key material without a 7-30 day wait. You will also have full control of the key. However, there is no automatic rotation.

    * To import your own key material:
        * Create a CMK with no material.
        * Download a public key (wrapping key) and import token.
        * Encrypt the key material.
        * Import the key material.

    * Key rotation depends on the key types:
        * **AWS Managed:** Automatically rotates every 3 years. You cannot rotate manually. AWS manages it and saves the old backing key.
        * **Customer Managed:** Automatic rotation every 365 days but disabled by default. You can rotate manually. You need to update your applications or key alias to use the new CMK.
        * **Customer Managed (Imported Key Material):** No automatic rotation, you must rotate manually. You need to update your applications or key alias to use the new CMK.

    * You can use KMS to encrypt EBS volumes, but you cannot use KMS to generate a public key/private key to log into EC2. You can import public keys into EC2 key pairs, but you cannot use EC2 key pairs to encrypt EBS volumes, you must use KMS or third-party applications/tools.

    * You can use KMS to encrypt EBS volumes and it is possible to encrypt root device volumes. To encrypt a root device volume, create an AMI. The initial AMI will be unencrypted, but you can then copy it and in doing so encrypt it. You can change encryption keys from amazon managed to customer managed.

    * You can copy AMIs from one region to another and make those copies encrypted, but you must use the keys in the destination region to do the encryption. You cannot copy KMS keys from one region to another.

    * You can view public keys in EC2 by going to `/home/ec2-users/.ssh/authorized_keys`. You can also view the public key using the E2 instance metadata. For example:
        ```shell
        curl http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key/
        ```

    * Multiple public keys can be attached to an EC2 instance. You can add roles to existing E2 instances.

    * Deleting a key pair in the console will not delete it from the instance or the instances metadata. If you lose a key pair (public or private), simply take a snapshot of the EC2 instance, and then deploy it as a new instance. This will APPEND a new public key to `/home/ec2-users/.ssh/authorized_keys`. You can then go into that file and delete the outdated public keys.

    * You cannot use KMS with SSH for EC2 as you cannot export keys from KMS. You can do this with CloudHSM because you can export keys from CloudHSM.

    * Security products from third party vendors can be purchased on the AWS Marketplace. This includes firewalls, hardened operating systems, WAF's, antivirus, security monitoring etc. There are various revenue models for these products.

    * A Grant programmatically delegates the use of your CMK to a user in your own account or in another account. It provides temporary and granular permissions.

    * Policy Conditions can be used to specify a condition within a Key Policy or IAM Policy for when a policy is in effect. KMS provides a set of predefined Condition Keys. Use `kms:ViaService` to allow or deny access to your CMK according to which service originated the request.

    * Access to MKS CMKs is controlled using:
        * **Key Policy:** Add the root user, not the individual IAM users or roles.
        * **IAM Policies:** Define the allowed actions and the CMK ARN.

    * If you want to enable cross account access:
        * Enable access in the Key Policy for the account which owns the CMK.
        * Enable access to KMS in the IAM Policy for external account.

    * Secrets Manager is typically used for database credentials and API/SSH keys. It has built in integration with RDS and rotation of RDS secrets. For this service you pay per secret per month and per 10,000 API calls.

    * Parameter Store is typically used for passwords, database strings, license codes, configuration data, and parameter values. You can have user defined parameters and they can be encrypted. It is integrated with AWS Systems Manager. There is no additional charge for this service.

1. Amazon Macie

    * Macie uses Machine Learning and Natural Language Processing to discover, classify, and protect sensitive data stored in S3. It provides dashboards, reporting, and alerts. Data is classified by content type, theme, file extension, and regular expression.

1. AWS Single Sign-On

### Out-of-scope Services and Features

1. Application development services

1. IoT services

1. Machine learning (ML) services

1. Media services

1. Migration and transfer services

## Practise Questions

### Infrastructure Security

1. A company hosts a popular web application that connects to an Amazon RDS MySQL DB instance running in a private VPC subnet created with default Network ACL settings. The IT Security department has a suspicion that a DoS attack is coming from a suspecting IP. How can you protect the subnets from this attack?
    * Change the inbound NACL to deny access from the suspecting IP. The NACL is responsible for controlling traffic in and out of a subnet. Security Groups work on the Instance level and not the Subnet level, and you cannot configure a Security Group to deny access.

1. A company is hosting a website that must be accessible to users for HTTPS traffic. Also, port 22 should be open for administrative purposes. The administrator's workstation has static IP addresses of 203.0.113.1/32. Which of the following security group configurations is the MOST secure but still functional to support these requirements?
    * Port 443 from 0.0.0.0/0 (all addresses) should be open. Port 22 from 203.0.113.1/32 (the administrative workstation only) should be open.

1. You have a website that is sitting behind AWS CloudFront. You need to protect the website against threats such as SQL injection and Cross-site scripting attacks. Which services can help in such a scenario?
    * AWS Config is not relevant here as it is used to check configuration changes on your AWS account. AWS Inspector is not relevant here as it can be used to scan EC2 Instances for vulnerabilities but not protect against the threats in this question. AWS Trusted Advisor is also not relevant here as that is to improve the security on your AWS account. AWS WAF allows you to create rules that can help to protect against common web exploits.

1. You have a 2-tier application hosted in AWS. It consists of a web server and database server (SQL Server) hosted on separate EC2 instances. You are devising the security groups for these EC2 Instances. The Web tier needs to be accessed by users across the internet. You have created a web security group (wg-123) and a database security group (db-345). Which combination of the following security group rules will allow the application to be secure and functional?
    * In wg-123 allow access from ports 80 and 443 for HTTP and HTTPS traffic for all users from the internet. In db-345 allow port 1443 traffic from wg-123.

1. A company wants to have an Intrusion detection system available for their VPC in AWS. They want to have complete control over the system. What should they implement?
    * A custom solution from the AWS Marketplace should be used. AWS does not provide an intrusion detection system natively.

### Logging and Monitoring
1. Your company has an EC2 Instance that is hosted in an AWS VPC. There is a requirement to ensure that log files from the EC2 Instance are stored in a secure manner. The access should be limited to the log files. How can this be accomplished? Choose 2 answers from the options given below. Each answer forms part of the solution.
    * CloudTrail is not relevant here as it is for recording API activities. The log files should be streamed to a separate Cloudwatch Log group and an IAM policy should be created to give access to the Cloudwatch Log group.

1. A company has managed many AWS resources. The IT audit department has requested to get a list of resources in the AWS account. How can this be achieved efficiently?
    * AWS Config can be used to get a list of all resources. Methods such as using a bash or PowerShell script are less efficient.

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

1. You have an EC2 Instance in a private subnet that needs to access the KMS service privately within the AWS network. Which of the following methods can help to fulfil this requirement, keeping security in perspective?
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
