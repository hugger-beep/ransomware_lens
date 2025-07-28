``` json

{
  "schemaVersion": "2021-11-01",
  "name": "Ransomware Resilience Lens",
  "description": "Evaluate your workload against ransomware resilience best practices",
  "pillars": [
    {
      "id": "security",
      "name": "Security",
      "questions": [
        {
          "id": "sec_ransomware_1",
          "category": "Identity and Access Management",
          "title": "How do you protect your AWS environment from unauthorized access that could lead to ransomware deployment?",
          "description": "Implement strong identity controls, least privilege access, and MFA to prevent unauthorized access that could lead to ransomware deployment.",
          "choices": [
            {
              "id": "sec_ransomware_1_a",
              "title": "We implement MFA for all users with AWS console access and programmatic access where supported.",
              "description": "Multi-factor authentication provides an additional layer of security to prevent unauthorized access even if credentials are compromised.",
              "helpfulResource": {
                "displayText": "Learn how to enable MFA for AWS users and implement strong authentication controls.",
                "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"
              },
              "improvementPlan": {
                "displayText": "Enable MFA for all AWS console and programmatic access."
              }
            },
            {
              "id": "sec_ransomware_1_b",
              "title": "We implement strict IAM policies following least privilege principles.",
              "description": "Least privilege ensures users and services have only the permissions necessary to perform their tasks, limiting the potential impact of compromised credentials.",
              "helpfulResource": {
                "displayText": "Best practices for implementing least privilege access in AWS IAM.",
                "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
              },
              "improvementPlan": {
                "displayText": "Review and implement least privilege IAM policies."
              }
            },
            {
              "id": "sec_ransomware_1_c",
              "title": "We use AWS Organizations SCPs to establish preventative guardrails.",
              "description": "Service Control Policies provide account-level restrictions that can prevent actions commonly used in ransomware attacks.",
              "helpfulResource": {
                "displayText": "Guide to implementing Service Control Policies for security guardrails.",
                "url": "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html"
              },
              "improvementPlan": {
                "displayText": "Implement AWS Organizations SCPs for preventative controls."
              }
            },
            {
              "id": "sec_ransomware_1_d",
              "title": "We implement just-in-time access and temporary elevated permissions.",
              "description": "Just-in-time access reduces the window of opportunity for attackers by only granting elevated permissions when needed and for limited duration.",
              "helpfulResource": {
                "displayText": "Implementing just-in-time access with AWS Systems Manager Session Manager and temporary credentials.",
                "url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html"
              },
              "improvementPlan": {
                "displayText": "Implement just-in-time access for administrative functions."
              }
            },
            {
              "id": "sec_ransomware_1_e",
              "title": "We are not following any of the above best practices.",
              "description": "We are not following any of the above best practices.",
              "improvementPlan": {
                "displayText": "Begin implementing basic security controls starting with MFA and least privilege access."
              }
            }
          ],
          "riskLevel": "HIGH",
          "pillar": "security",
          "improvementPlan": {
            "displayText": "Implement MFA for all users, enforce least privilege through IAM policies, use SCPs to establish guardrails, and implement just-in-time access for administrative functions."
          },
          "riskRules": [
            {
              "condition": "default",
              "risk": "HIGH_RISK"
            }
          ]
        },
        {
          "id": "sec_ransomware_2",
          "category": "Ransomware Detection & Monitoring",
          "title": "How do you detect potential ransomware activity in your AWS environment?",
          "description": "Implement comprehensive monitoring and detection capabilities to identify ransomware activity early in the attack lifecycle.",
          "choices": [
            {
              "id": "sec_ransomware_2_a",
              "title": "We use Amazon GuardDuty to detect suspicious activity.",
              "description": "GuardDuty provides threat detection that can identify unusual API calls, potentially unauthorized deployments, and suspicious network activity.",
              "helpfulResource": {
                "displayText": "Getting started with Amazon GuardDuty for threat detection and ransomware protection.",
                "url": "https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html"
              },
              "improvementPlan": {
                "displayText": "Enable Amazon GuardDuty in all regions."
              }
            },
            {
              "id": "sec_ransomware_2_b",
              "title": "We use AWS Security Hub to aggregate and prioritize security findings.",
              "description": "Security Hub provides a comprehensive view of security alerts and compliance status across AWS accounts.",
              "helpfulResource": {
                "displayText": "Setting up AWS Security Hub for centralized security findings management.",
                "url": "https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html"
              },
              "improvementPlan": {
                "displayText": "Enable AWS Security Hub for centralized security findings."
              }
            },
            {
              "id": "sec_ransomware_2_c",
              "title": "We monitor CloudTrail for suspicious administrative actions.",
              "description": "CloudTrail logs provide an audit trail of actions taken in your AWS account that can be monitored for suspicious activity.",
              "helpfulResource": {
                "displayText": "Best practices for AWS CloudTrail logging and monitoring for security events.",
                "url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html"
              },
              "improvementPlan": {
                "displayText": "Implement CloudTrail monitoring with alerting."
              }
            },
            {
              "id": "sec_ransomware_2_d",
              "title": "We use Amazon Macie to detect sensitive data access patterns.",
              "description": "Macie can identify unusual access patterns to sensitive data that might indicate exfiltration before encryption.",
              "helpfulResource": {
                "displayText": "Getting started with Amazon Macie for data security and privacy protection.",
                "url": "https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html"
              },
              "improvementPlan": {
                "displayText": "Enable Amazon Macie for data access monitoring."
              }
            },
            {
              "id": "sec_ransomware_2_e",
              "title": "We are not following any of the above best practices.",
              "description": "We are not following any of the above best practices.",
              "improvementPlan": {
                "displayText": "Begin implementing basic monitoring and detection capabilities starting with GuardDuty."
              }
            }
          ],
          "riskLevel": "HIGH",
          "pillar": "security",
          "improvementPlan": {
            "displayText": "Enable GuardDuty in all regions, centralize findings in Security Hub, implement CloudTrail monitoring with alerting for suspicious actions, and use Macie to detect potential data exfiltration."
          },
          "riskRules": [
            {
              "condition": "default",
              "risk": "HIGH_RISK"
            }
          ]
        },
        {
          "id": "sec_ransomware_3",
          "category": "Serverless Architecture",
          "title": "How do you protect your serverless architecture from ransomware attacks?",
          "description": "Implement security controls specific to serverless architectures to prevent ransomware deployment and limit blast radius.",
          "choices": [
            {
              "id": "sec_ransomware_3_a",
              "title": "We configure Lambda functions with minimal permissions following least privilege.",
              "description": "Limiting Lambda function permissions reduces the potential impact if a function is compromised.",
              "helpfulResource": {
                "displayText": "AWS Lambda security best practices and least privilege implementation.",
                "url": "https://docs.aws.amazon.com/lambda/latest/dg/lambda-security.html"
              },
              "improvementPlan": {
                "displayText": "configure Lambda functions with minimal permissions following least privilege."
              }
            },
            {
              "id": "sec_ransomware_3_b",
              "title": "We secure API Gateway endpoints with appropriate authentication and authorization.",
              "description": "Properly secured API Gateway endpoints prevent unauthorized access that could lead to ransomware deployment.",
              "helpfulResource": {
                "displayText": "API Gateway security best practices and authentication methods.",
                "url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/security.html"
              },
              "improvementPlan": {
                "displayText": "secure API Gateway endpoints with appropriate authentication and authorization."
              }
            },
            {
              "id": "sec_ransomware_3_c",
              "title": "We implement runtime protection for serverless functions.",
              "description": "Runtime protection helps detect and prevent malicious code execution within serverless functions.",
              "helpfulResource": {
                "displayText": "Serverless security best practices and runtime protection strategies.",
                "url": "https://aws.amazon.com/blogs/compute/building-well-architected-serverless-applications-security-part-1/"
              },
              "improvementPlan": {
                "displayText": "implement runtime protection for serverless functions."
              }
            },
            {
              "id": "sec_ransomware_3_d",
              "title": "We monitor serverless event sources for unusual patterns that might indicate compromise.",
              "description": "Monitoring event sources helps detect potential ransomware activity targeting serverless architectures.",
              "helpfulResource": {
                "displayText": "Monitoring and observability best practices for serverless applications.",
                "url": "https://docs.aws.amazon.com/lambda/latest/dg/lambda-monitoring.html"
              },
              "improvementPlan": {
                "displayText": "monitor serverless event sources for unusual patterns that might indicate compromise."
              }
            },
            {
              "id": "sec_ransomware_3_e",
              "title": "We are not following any of the above best practices.",
              "description": "We are not following any of the above best practices.",
              "improvementPlan": {
                "displayText": "Begin implementing serverless security controls starting with least privilege Lambda permissions."
              }
            }
          ],
          "riskLevel": "HIGH",
          "pillar": "security",
          "improvementPlan": {
            "displayText": "Configure Lambda functions with minimal permissions, secure API Gateway endpoints, implement runtime protection, and monitor serverless event sources for unusual patterns."
          },
          "riskRules": [
            {
              "condition": "default",
              "risk": "HIGH_RISK"
            }
          ]
        },
        {
          "id": "sec_ransomware_4",
          "category": "Network Security and Segmentation",
          "title": "How do you implement network segmentation to contain potential ransomware spread?",
          "description": "Implement network segmentation and isolation to limit lateral movement and contain potential ransomware spread.",
          "choices": [
            {
              "id": "sec_ransomware_4_a",
              "title": "We segment our VPCs and subnets based on security requirements and data sensitivity.",
              "description": "Network segmentation limits lateral movement and contains potential ransomware spread.",
              "helpfulResource": {
                "displayText": "VPC security best practices and network segmentation strategies.",
                "url": "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-best-practices.html"
              },
              "improvementPlan": {
                "displayText": "segment our VPCs and subnets based on security requirements and data sensitivity."
              }
            },
            {
              "id": "sec_ransomware_4_b",
              "title": "We implement security groups and NACLs with least privilege access.",
              "description": "Properly configured security groups and NACLs limit network connectivity to only what is required.",
              "helpfulResource": {
                "displayText": "Security groups and network ACLs configuration best practices.",
                "url": "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Security.html"
              },
              "improvementPlan": {
                "displayText": "implement security groups and NACLs with least privilege access."
              }
            },
            {
              "id": "sec_ransomware_4_c",
              "title": "We use AWS Network Firewall or third-party solutions for advanced traffic filtering.",
              "description": "Advanced traffic filtering helps detect and block command-and-control traffic and other malicious network activity.",
              "helpfulResource": {
                "displayText": "AWS Network Firewall deployment and configuration guide.",
                "url": "https://docs.aws.amazon.com/network-firewall/latest/developerguide/what-is-aws-network-firewall.html"
              },
              "improvementPlan": {
                "displayText": "use AWS Network Firewall or third-party solutions for advanced traffic filtering."
              }
            },
            {
              "id": "sec_ransomware_4_d",
              "title": "We implement zero trust principles for network access.",
              "description": "Zero trust principles ensure that all network access is authenticated, authorized, and encrypted regardless of source location.",
              "helpfulResource": {
                "displayText": "Zero Trust architecture principles and AWS implementation strategies.",
                "url": "https://aws.amazon.com/blogs/publicsector/how-to-think-about-zero-trust-architectures-on-aws/"
              },
              "improvementPlan": {
                "displayText": "implement zero trust principles for network access."
              }
            },
            {
              "id": "sec_ransomware_4_e",
              "title": "We are not following any of the above best practices.",
              "description": "We are not following any of the above best practices.",
              "improvementPlan": {
                "displayText": "Begin implementing network segmentation starting with VPC and subnet isolation."
              }
            }
          ],
          "riskLevel": "HIGH",
          "pillar": "security",
          "improvementPlan": {
            "displayText": "Segment VPCs and subnets, implement security groups and NACLs with least privilege, use AWS Network Firewall for advanced traffic filtering, and implement zero trust principles."
          },
          "riskRules": [
            {
              "condition": "default",
              "risk": "HIGH_RISK"
            }
          ]
        },
        {
          "id": "sec_ransomware_5",
          "category": "Third-Party SaaS Integration",
          "title": "How do you secure third-party SaaS integrations against ransomware risks?",
          "description": "Implement security controls for third-party SaaS integrations to prevent them from becoming ransomware attack vectors.",
          "choices": [
            {
              "id": "sec_ransomware_5_a",
              "title": "We conduct security assessments of SaaS providers before integration.",
              "description": "Security assessments help identify potential risks before integrating third-party services.",
              "helpfulResource": {
                "displayText": "Third-party risk management and vendor security assessment frameworks.",
                "url": "https://www.nist.gov/cyberframework/online-learning/components-framework"
              },
              "improvementPlan": {
                "displayText": "conduct security assessments of SaaS providers before integration."
              }
            },
            {
              "id": "sec_ransomware_5_b",
              "title": "We implement least privilege access for third-party integrations.",
              "description": "Least privilege access limits the potential impact if a third-party integration is compromised.",
              "helpfulResource": {
                "displayText": "AWS IAM cross-account access and external ID best practices.",
                "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html"
              },
              "improvementPlan": {
                "displayText": "implement least privilege access for third-party integrations."
              }
            },
            {
              "id": "sec_ransomware_5_c",
              "title": "We monitor third-party access and activities within our environment.",
              "description": "Monitoring helps detect suspicious activities from third-party integrations.",
              "helpfulResource": {
                "displayText": "CloudTrail logging and monitoring for third-party access patterns.",
                "url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html"
              },
              "improvementPlan": {
                "displayText": "monitor third-party access and activities within our environment."
              }
            },
            {
              "id": "sec_ransomware_5_d",
              "title": "We maintain the ability to quickly disconnect compromised integrations.",
              "description": "Quick disconnection capabilities limit the impact of compromised third-party services.",
              "helpfulResource": {
                "displayText": "Incident response automation and AWS Systems Manager for rapid remediation.",
                "url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-automation.html"
              },
              "improvementPlan": {
                "displayText": "maintain the ability to quickly disconnect compromised integrations."
              }
            },
            {
              "id": "sec_ransomware_5_e",
              "title": "We are not following any of the above best practices.",
              "description": "We are not following any of the above best practices.",
              "improvementPlan": {
                "displayText": "Begin implementing third-party security assessments and least privilege access controls."
              }
            }
          ],
          "riskLevel": "HIGH",
          "pillar": "security",
          "improvementPlan": {
            "displayText": "Conduct security assessments of SaaS providers, implement least privilege access for integrations, monitor third-party access, and maintain the ability to quickly disconnect compromised integrations."
          },
          "riskRules": [
            {
              "condition": "default",
              "risk": "HIGH_RISK"
            }
          ]
        },
        {
          "id": "sec_ransomware_6",
          "category": "Multi-Cloud Environment",
          "title": "How do you secure your multi-cloud environment against ransomware?",
          "description": "Implement consistent security controls across multi-cloud environments to prevent ransomware spread.",
          "choices": [
            {
              "id": "sec_ransomware_6_a",
              "title": "We implement consistent identity and access management across cloud platforms.",
              "description": "Consistent IAM prevents credential-based attacks from spreading across cloud environments.",
              "helpfulResource": {
                "displayText": "Multi-cloud identity federation and AWS SSO implementation strategies.",
                "url": "https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html"
              },
              "improvementPlan": {
                "displayText": "implement consistent identity and access management across cloud platforms."
              }
            },
            {
              "id": "sec_ransomware_6_b",
              "title": "We segment network connections between cloud environments.",
              "description": "Network segmentation prevents lateral movement between cloud platforms.",
              "helpfulResource": {
                "displayText": "Multi-cloud network architecture and segmentation best practices.",
                "url": "https://docs.aws.amazon.com/whitepapers/latest/hybrid-connectivity/network-to-amazon-vpc-connectivity-options.html"
              },
              "improvementPlan": {
                "displayText": "segment network connections between cloud environments."
              }
            },
            {
              "id": "sec_ransomware_6_c",
              "title": "We correlate security alerts across cloud platforms for comprehensive visibility.",
              "description": "Alert correlation provides visibility into attacks that span multiple cloud environments.",
              "helpfulResource": {
                "displayText": "SIEM integration and multi-cloud security monitoring strategies.",
                "url": "https://aws.amazon.com/blogs/security/how-to-integrate-aws-security-hub-custom-insights-with-amazon-quicksight/"
              },
              "improvementPlan": {
                "displayText": "correlate security alerts across cloud platforms for comprehensive visibility."
              }
            },
            {
              "id": "sec_ransomware_6_d",
              "title": "We implement consistent encryption standards across cloud platforms.",
              "description": "Consistent encryption standards protect data regardless of where it resides.",
              "helpfulResource": {
                "displayText": "AWS encryption services and multi-cloud encryption strategy guidance.",
                "url": "https://docs.aws.amazon.com/crypto/latest/userguide/awscryp-overview.html"
              },
              "improvementPlan": {
                "displayText": "implement consistent encryption standards across cloud platforms."
              }
            },
            {
              "id": "sec_ransomware_6_e",
              "title": "We are not following any of the above best practices.",
              "description": "We are not following any of the above best practices.",
              "improvementPlan": {
                "displayText": "Begin implementing consistent identity management and network segmentation across cloud platforms."
              }
            }
          ],
          "riskLevel": "HIGH",
          "pillar": "security",
          "improvementPlan": {
            "displayText": "Implement consistent identity management, segment network connections between clouds, correlate security alerts across platforms, and maintain consistent encryption standards."
          },
          "riskRules": [
            {
              "condition": "default",
              "risk": "HIGH_RISK"
            }
          ]
        },
        {
          "id": "sec_ransomware_7",
          "category": "Infrastructure as Code",
          "title": "How do you secure your Infrastructure as Code (IaC) pipeline against ransomware?",
          "description": "Implement security controls for IaC pipelines to prevent them from becoming ransomware deployment vectors.",
          "choices": [
            {
              "id": "sec_ransomware_7_a",
              "title": "We implement security scanning for IaC templates before deployment.",
              "description": "Security scanning identifies misconfigurations and vulnerabilities in infrastructure code.",
              "helpfulResource": {
                "displayText": "CloudFormation security best practices and template validation tools.",
                "url": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/security-best-practices.html"
              },
              "improvementPlan": {
                "displayText": "implement security scanning for IaC templates before deployment."
              }
            },
            {
              "id": "sec_ransomware_7_b",
              "title": "We protect IaC repositories with strong access controls and MFA.",
              "description": "Strong access controls prevent unauthorized modifications to infrastructure code.",
              "helpfulResource": {
                "displayText": "Git repository security and AWS CodeCommit access control best practices.",
                "url": "https://docs.aws.amazon.com/codecommit/latest/userguide/security-best-practices.html"
              },
              "improvementPlan": {
                "displayText": "protect IaC repositories with strong access controls and MFA."
              }
            },
            {
              "id": "sec_ransomware_7_c",
              "title": "We implement approval workflows for infrastructure changes.",
              "description": "Approval workflows prevent unauthorized or malicious infrastructure changes.",
              "helpfulResource": {
                "displayText": "AWS CodePipeline approval actions and change management workflows.",
                "url": "https://docs.aws.amazon.com/codepipeline/latest/userguide/approvals.html"
              },
              "improvementPlan": {
                "displayText": "implement approval workflows for infrastructure changes."
              }
            },
            {
              "id": "sec_ransomware_7_d",
              "title": "We use secure secret management for IaC pipelines.",
              "description": "Secure secret management prevents credentials from being exposed in infrastructure code.",
              "helpfulResource": {
                "displayText": "AWS Secrets Manager and Systems Manager Parameter Store for secure credential management.",
                "url": "https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html"
              },
              "improvementPlan": {
                "displayText": "use secure secret management for IaC pipelines."
              }
            },
            {
              "id": "sec_ransomware_7_e",
              "title": "We are not following any of the above best practices.",
              "description": "We are not following any of the above best practices.",
              "improvementPlan": {
                "displayText": "Begin implementing IaC security scanning and repository access controls."
              }
            }
          ],
          "riskLevel": "HIGH",
          "pillar": "security",
          "improvementPlan": {
            "displayText": "Implement security scanning for IaC templates, protect repositories with strong access controls, implement approval workflows, and use secure secret management."
          },
          "riskRules": [
            {
              "condition": "default",
              "risk": "HIGH_RISK"
            }
          ]
        },
        {
          "id": "sec_ransomware_8",
          "category": "Generative AI Considerations",
          "title": "How do you protect against AI-assisted ransomware attacks?",
          "description": "Implement security controls to protect against increasingly sophisticated AI-assisted ransomware attacks.",
          "choices": [
            {
              "id": "sec_ransomware_8_a",
              "title": "We implement advanced behavioral analytics to detect AI-assisted attacks.",
              "description": "Behavioral analytics can identify sophisticated attack patterns that might evade traditional detection.",
              "helpfulResource": {
                "displayText": "Amazon Detective and behavioral analysis for advanced threat detection.",
                "url": "https://docs.aws.amazon.com/detective/latest/userguide/what-is-detective.html"
              },
              "improvementPlan": {
                "displayText": "implement advanced behavioral analytics to detect AI-assisted attacks."
              }
            },
            {
              "id": "sec_ransomware_8_b",
              "title": "We protect our generative AI systems from prompt injection and poisoning attacks.",
              "description": "Protecting AI systems prevents them from being weaponized against our environment.",
              "helpfulResource": {
                "displayText": "Amazon Bedrock Guardrails for AI safety and prompt injection protection.",
                "url": "https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html"
              },
              "improvementPlan": {
                "displayText": "protect our generative AI systems from prompt injection and poisoning attacks."
              }
            },
            {
              "id": "sec_ransomware_8_c",
              "title": "We use AI-enhanced security tools to counter AI-assisted threats.",
              "description": "AI-enhanced security tools can better detect and respond to AI-assisted attacks.",
              "helpfulResource": {
                "displayText": "AI/ML security services and machine learning for threat detection on AWS.",
                "url": "https://aws.amazon.com/machine-learning/ai-services/security/"
              },
              "improvementPlan": {
                "displayText": "use AI-enhanced security tools to counter AI-assisted threats."
              }
            },
            {
              "id": "sec_ransomware_8_d",
              "title": "We implement strict access controls for AI systems and sensitive data.",
              "description": "Access controls prevent AI systems from being used to identify security vulnerabilities for malicious purposes.",
              "helpfulResource": {
                "displayText": "Amazon Bedrock security and access control best practices for AI workloads.",
                "url": "https://docs.aws.amazon.com/bedrock/latest/userguide/security.html"
              },
              "improvementPlan": {
                "displayText": "implement strict access controls for AI systems and sensitive data."
              }
            },
            {
              "id": "sec_ransomware_8_e",
              "title": "We are not following any of the above best practices.",
              "description": "We are not following any of the above best practices.",
              "improvementPlan": {
                "displayText": "Begin implementing AI security controls starting with behavioral analytics and access controls."
              }
            }
          ],
          "riskLevel": "MEDIUM",
          "pillar": "security",
          "improvementPlan": {
            "displayText": "Implement advanced behavioral analytics, protect generative AI systems from attacks, use AI-enhanced security tools, and implement strict access controls for AI systems."
          },
          "riskRules": [
            {
              "condition": "default",
              "risk": "MEDIUM_RISK"
            }
          ]
        }
      ]
    },
    {
      "id": "reliability",
      "name": "Reliability",
      "questions": [
        {
          "id": "rel_ransomware_1",
          "category": "Backup Strategy",
          "title": "How do you ensure your backups are protected from ransomware?",
          "description": "Implement backup strategies that protect against ransomware encryption or deletion.",
          "choices": [
            {
              "id": "rel_ransomware_1_a",
              "title": "We use AWS Backup with immutable backups and time-based retention.",
              "description": "Immutable backups cannot be altered or deleted during their retention period, protecting them from ransomware.",
              "helpfulResource": {
                "displayText": "Learn how to implement AWS Backup with immutable storage for ransomware protection.",
                "url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/backup-vault-lock.html"
              },
              "improvementPlan": {
                "displayText": "use AWS Backup with immutable backups and time-based retention."
              }
            },
            {
              "id": "rel_ransomware_1_b",
              "title": "We implement cross-region and cross-account backup strategies.",
              "description": "Storing backups in separate regions and accounts provides isolation from the primary environment.",
              "helpfulResource": {
                "displayText": "Cross-region and cross-account backup strategies for disaster recovery.",
                "url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/cross-region-backup.html"
              },
              "improvementPlan": {
                "displayText": "implement cross-region and cross-account backup strategies."
              }
            },
            {
              "id": "rel_ransomware_1_c",
              "title": "We regularly test backup restoration in isolated environments.",
              "description": "Regular testing ensures backups can be successfully restored when needed.",
              "helpfulResource": {
                "displayText": "Disaster recovery testing best practices and AWS backup restoration procedures.",
                "url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/recovery-testing.html"
              },
              "improvementPlan": {
                "displayText": "regularly test backup restoration in isolated environments."
              }
            },
            {
              "id": "rel_ransomware_1_d",
              "title": "We implement separate access controls for backup administration.",
              "description": "Separate access controls ensure that compromise of primary environment credentials does not compromise backup systems.",
              "helpfulResource": {
                "displayText": "AWS Backup access control and cross-account backup management strategies.",
                "url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/security-considerations.html"
              },
              "improvementPlan": {
                "displayText": "implement separate access controls for backup administration."
              }
            },
            {
              "id": "rel_ransomware_1_e",
              "title": "We are not following any of the above best practices.",
              "description": "We are not following any of the above best practices.",
              "improvementPlan": {
                "displayText": "Begin implementing basic backup protection starting with AWS Backup and immutable storage."
              }
            }
          ],
          "riskLevel": "HIGH",
          "pillar": "reliability",
          "improvementPlan": {
            "displayText": "Implement AWS Backup with immutable storage and appropriate retention periods, store backups in separate regions and accounts, regularly test restoration procedures, and implement separate access controls for backup systems."
          },
          "riskRules": [
            {
              "condition": "default",
              "risk": "HIGH_RISK"
            }
          ]
        },
        {
          "id": "rel_ransomware_2",
          "category": "Serverless Architecture",
          "title": "How do you ensure your serverless architecture can recover from ransomware?",
          "description": "Design serverless architectures with ransomware resilience in mind.",
          "choices": [
            {
              "id": "rel_ransomware_2_a",
              "title": "We version and immutably store all Lambda function code.",
              "description": "Versioning Lambda functions allows for quick rollback to known-good versions.",
              "helpfulResource": {
                "displayText": "Lambda function versioning and alias management for deployment safety.",
                "url": "https://docs.aws.amazon.com/lambda/latest/dg/configuration-versions.html"
              },
              "improvementPlan": {
                "displayText": "version and immutably store all Lambda function code."
              }
            },
            {
              "id": "rel_ransomware_2_b",
              "title": "We implement strict S3 bucket policies and versioning for function dependencies.",
              "description": "S3 bucket policies and versioning protect function dependencies from tampering.",
              "helpfulResource": {
                "displayText": "S3 bucket security best practices and versioning configuration for data protection.",
                "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html"
              },
              "improvementPlan": {
                "displayText": "implement strict S3 bucket policies and versioning for function dependencies."
              }
            },
            {
              "id": "rel_ransomware_2_c",
              "title": "We use infrastructure as code with version control for all serverless resources.",
              "description": "Infrastructure as code with version control enables rapid reconstruction of serverless resources.",
              "helpfulResource": {
                "displayText": "AWS SAM and CloudFormation for serverless infrastructure as code best practices.",
                "url": "https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/what-is-sam.html"
              },
              "improvementPlan": {
                "displayText": "use infrastructure as code with version control for all serverless resources."
              }
            },
            {
              "id": "rel_ransomware_2_d",
              "title": "We implement function isolation and least privilege for each serverless component.",
              "description": "Function isolation and least privilege limit the blast radius of a compromise.",
              "helpfulResource": {
                "displayText": "Serverless security patterns and function isolation strategies for AWS Lambda.",
                "url": "https://aws.amazon.com/blogs/compute/building-well-architected-serverless-applications-security-part-2/"
              },
              "improvementPlan": {
                "displayText": "implement function isolation and least privilege for each serverless component."
              }
            },
            {
              "id": "rel_ransomware_2_e",
              "title": "We are not following any of the above best practices.",
              "description": "We are not following any of the above best practices.",
              "improvementPlan": {
                "displayText": "Begin implementing serverless resilience starting with Lambda function versioning."
              }
            }
          ],
          "riskLevel": "MEDIUM",
          "pillar": "reliability",
          "improvementPlan": {
            "displayText": "Implement versioning for Lambda functions, use S3 bucket policies and versioning for dependencies, manage serverless resources with infrastructure as code, and implement function isolation with least privilege."
          },
          "riskRules": [
            {
              "condition": "default",
              "risk": "MEDIUM_RISK"
            }
          ]
        },
        {
          "id": "rel_ransomware_3",
          "category": "Disaster Recovery",
          "title": "How do you validate that your recovery procedures are effective against ransomware?",
          "description": "Regularly test and validate recovery procedures to ensure they are effective against ransomware scenarios.",
          "choices": [
            {
              "id": "rel_ransomware_3_a",
              "title": "We conduct regular ransomware-specific recovery exercises.",
              "description": "Regular exercises ensure that recovery procedures are effective and that teams are prepared to respond to ransomware incidents.",
              "helpfulResource": {
                "displayText": "Disaster recovery planning and testing methodologies for ransomware scenarios.",
                "url": "https://www.cisa.gov/sites/default/files/publications/CISA_MS-ISAC_Ransomware%20Guide_S508C.pdf"
              },
              "improvementPlan": {
                "displayText": "conduct regular ransomware-specific recovery exercises."
              }
            },
            {
              "id": "rel_ransomware_3_b",
              "title": "We validate that backups are free from ransomware before restoration.",
              "description": "Validation prevents restoring infected backups that could reintroduce ransomware into the environment.",
              "helpfulResource": {
                "displayText": "Backup validation and malware scanning best practices for secure restoration.",
                "url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/point-in-time-recovery.html"
              },
              "improvementPlan": {
                "displayText": "validate that backups are free from ransomware before restoration."
              }
            },
            {
              "id": "rel_ransomware_3_c",
              "title": "We test recovery in isolated environments before restoring to production.",
              "description": "Testing in isolated environments ensures that recovery procedures are effective and do not introduce additional risks.",
              "helpfulResource": {
                "displayText": "AWS disaster recovery testing in isolated environments and sandbox strategies.",
                "url": "https://docs.aws.amazon.com/whitepapers/latest/disaster-recovery-workloads-on-aws/disaster-recovery-options-in-the-cloud.html"
              },
              "improvementPlan": {
                "displayText": "test recovery in isolated environments before restoring to production."
              }
            },
            {
              "id": "rel_ransomware_3_d",
              "title": "We document and measure RTO/RPO achievement in recovery exercises.",
              "description": "Measuring RTO/RPO achievement ensures that recovery objectives can be met in actual ransomware scenarios.",
              "helpfulResource": {
                "displayText": "RTO and RPO planning and measurement for business continuity and disaster recovery.",
                "url": "https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/plan-for-disaster-recovery-dr.html"
              },
              "improvementPlan": {
                "displayText": "document and measure RTO/RPO achievement in recovery exercises."
              }
            },
            {
              "id": "rel_ransomware_3_e",
              "title": "We are not following any of the above best practices.",
              "description": "We are not following any of the above best practices.",
              "improvementPlan": {
                "displayText": "Begin implementing disaster recovery validation starting with basic recovery exercises."
              }
            }
          ],
          "riskLevel": "HIGH",
          "pillar": "reliability",
          "improvementPlan": {
            "displayText": "Conduct regular ransomware-specific recovery exercises, validate backups before restoration, test recovery in isolated environments, and measure RTO/RPO achievement."
          },
          "riskRules": [
            {
              "condition": "default",
              "risk": "HIGH_RISK"
            }
          ]
        },
        {
          "id": "rel_ransomware_4",
          "category": "Payment Processing Protection",
          "title": "How do you protect payment processing systems from ransomware?",
          "description": "Implement specialized controls to protect payment processing systems from ransomware attacks.",
          "choices": [
            {
              "id": "rel_ransomware_4_a",
              "title": "We isolate payment processing systems from other infrastructure.",
              "description": "Isolation prevents ransomware from spreading to payment systems from other parts of the infrastructure.",
              "helpfulResource": {
                "displayText": "PCI DSS compliance and payment system isolation best practices on AWS.",
                "url": "https://docs.aws.amazon.com/whitepapers/latest/pci-dss-scoping-aws/pci-dss-scoping-aws.html"
              },
              "improvementPlan": {
                "displayText": "isolate payment processing systems from other infrastructure."
              }
            },
            {
              "id": "rel_ransomware_4_b",
              "title": "We implement tokenization or point-to-point encryption for payment data.",
              "description": "Tokenization and encryption minimize payment data exposure and reduce the impact of ransomware.",
              "helpfulResource": {
                "displayText": "Payment data tokenization and encryption strategies for PCI compliance.",
                "url": "https://www.pcisecuritystandards.org/documents/Tokenization_Guidelines_Info_Supplement.pdf"
              },
              "improvementPlan": {
                "displayText": "implement tokenization or point-to-point encryption for payment data."
              }
            },
            {
              "id": "rel_ransomware_4_c",
              "title": "We maintain alternative payment processing capabilities.",
              "description": "Alternative capabilities ensure business continuity if primary payment systems are compromised.",
              "helpfulResource": {
                "displayText": "Business continuity planning and redundant payment processing architecture.",
                "url": "https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/design-your-workload-to-withstand-component-failures.html"
              },
              "improvementPlan": {
                "displayText": "maintain alternative payment processing capabilities."
              }
            },
            {
              "id": "rel_ransomware_4_d",
              "title": "We implement enhanced monitoring for payment processing systems.",
              "description": "Enhanced monitoring enables early detection of ransomware targeting payment systems.",
              "helpfulResource": {
                "displayText": "Payment system monitoring and fraud detection using AWS security services.",
                "url": "https://aws.amazon.com/financial-services/security-compliance/"
              },
              "improvementPlan": {
                "displayText": "implement enhanced monitoring for payment processing systems."
              }
            },
            {
              "id": "rel_ransomware_4_e",
              "title": "We are not following any of the above best practices.",
              "description": "We are not following any of the above best practices.",
              "improvementPlan": {
                "displayText": "Begin implementing payment system protection starting with isolation and encryption."
              }
            }
          ],
          "riskLevel": "HIGH",
          "pillar": "reliability",
          "improvementPlan": {
            "displayText": "Isolate payment processing systems, implement tokenization or encryption, maintain alternative payment capabilities, and implement enhanced monitoring."
          },
          "riskRules": [
            {
              "condition": "default",
              "risk": "HIGH_RISK"
            }
          ]
        },
        {
          "id": "rel_ransomware_5",
          "category": "Supply Chain Security",
          "title": "How do you ensure supply chain security against ransomware?",
          "description": "Implement controls to protect against ransomware introduced through the supply chain.",
          "choices": [
            {
              "id": "rel_ransomware_5_a",
              "title": "We assess ransomware risks from our technology supply chain.",
              "description": "Risk assessments identify potential ransomware vectors in the supply chain.",
              "helpfulResource": {
                "displayText": "Supply chain risk management framework and third-party security assessment.",
                "url": "https://www.nist.gov/itl/executive-order-improving-nations-cybersecurity/enhancing-software-supply-chain-security"
              },
              "improvementPlan": {
                "displayText": "assess ransomware risks from our technology supply chain."
              }
            },
            {
              "id": "rel_ransomware_5_b",
              "title": "We include security requirements in vendor contracts.",
              "description": "Contractual requirements establish security expectations for vendors.",
              "helpfulResource": {
                "displayText": "Vendor contract security requirements and third-party risk management templates.",
                "url": "https://www.cisa.gov/sites/default/files/publications/Supply_Chain_Risk_Management_Practices_for_Federal_Information_Systems_and_Organizations_SP_800-161.pdf"
              },
              "improvementPlan": {
                "displayText": "include security requirements in vendor contracts."
              }
            },
            {
              "id": "rel_ransomware_5_c",
              "title": "We verify software dependencies and components before use.",
              "description": "Verification prevents the introduction of compromised components.",
              "helpfulResource": {
                "displayText": "Software composition analysis and dependency scanning with Amazon Inspector.",
                "url": "https://docs.aws.amazon.com/inspector/latest/user/sbom-export.html"
              },
              "improvementPlan": {
                "displayText": "verify software dependencies and components before use."
              }
            },
            {
              "id": "rel_ransomware_5_d",
              "title": "We maintain contingency plans for critical supplier compromise.",
              "description": "Contingency plans ensure business continuity if a critical supplier is compromised.",
              "helpfulResource": {
                "displayText": "Business continuity planning and supplier contingency strategies.",
                "url": "https://www.ready.gov/business-continuity-planning"
              },
              "improvementPlan": {
                "displayText": "maintain contingency plans for critical supplier compromise."
              }
            },
            {
              "id": "rel_ransomware_5_e",
              "title": "We are not following any of the above best practices.",
              "description": "We are not following any of the above best practices.",
              "improvementPlan": {
                "displayText": "Begin implementing supply chain security starting with vendor risk assessments."
              }
            }
          ],
          "riskLevel": "HIGH",
          "pillar": "reliability",
          "improvementPlan": {
            "displayText": "Assess supply chain risks, include security requirements in contracts, verify software components, and maintain contingency plans for supplier compromise."
          },
          "riskRules": [
            {
              "condition": "default",
              "risk": "HIGH_RISK"
            }
          ]
        }
      ]
    },
    {
      "id": "operational_excellence",
      "name": "Operational Excellence",
      "questions": [
        {
          "id": "ops_ransomware_1",
          "category": "Incident Response & Recovery",
          "title": "How do you prepare your team to respond to ransomware incidents?",
          "description": "Develop and test ransomware-specific incident response procedures.",
          "choices": [
            {
              "id": "ops_ransomware_1_a",
              "title": "We have documented ransomware-specific incident response procedures.",
              "description": "Documented procedures ensure consistent and effective response to ransomware incidents.",
              "helpfulResource": {
                "displayText": "NIST Cybersecurity Framework and incident response planning guidance.",
                "url": "https://www.nist.gov/cyberframework/online-learning/components-framework"
              },
              "improvementPlan": {
                "displayText": "have documented ransomware-specific incident response procedures."
              }
            },
            {
              "id": "ops_ransomware_1_b",
              "title": "We regularly conduct tabletop exercises for ransomware scenarios.",
              "description": "Tabletop exercises help teams practice response procedures and identify gaps.",
              "helpfulResource": {
                "displayText": "CISA tabletop exercise guidance and ransomware scenario planning.",
                "url": "https://www.cisa.gov/sites/default/files/publications/CISA_MS-ISAC_Ransomware%20Guide_S508C.pdf"
              },
              "improvementPlan": {
                "displayText": "regularly conduct tabletop exercises for ransomware scenarios."
              }
            },
            {
              "id": "ops_ransomware_1_c",
              "title": "We maintain offline copies of incident response procedures and contact information.",
              "description": "Offline copies ensure access to procedures even if systems are compromised.",
              "helpfulResource": {
                "displayText": "Incident response playbook development and offline documentation best practices.",
                "url": "https://www.sans.org/white-papers/33901/"
              },
              "improvementPlan": {
                "displayText": "maintain offline copies of incident response procedures and contact information."
              }
            },
            {
              "id": "ops_ransomware_1_d",
              "title": "We have pre-established relationships with forensic and incident response specialists.",
              "description": "Pre-established relationships ensure rapid access to specialized expertise when needed.",
              "helpfulResource": {
                "displayText": "Building incident response teams and external forensic specialist partnerships.",
                "url": "https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf"
              },
              "improvementPlan": {
                "displayText": "have pre-established relationships with forensic and incident response specialists."
              }
            },
            {
              "id": "ops_ransomware_1_e",
              "title": "We are not following any of the above best practices.",
              "description": "We are not following any of the above best practices.",
              "improvementPlan": {
                "displayText": "Begin developing incident response procedures and conducting basic tabletop exercises."
              }
            }
          ],
          "riskLevel": "HIGH",
          "pillar": "operational_excellence",
          "improvementPlan": {
            "displayText": "Document ransomware-specific incident response procedures, conduct regular tabletop exercises, maintain offline copies of critical information, and establish relationships with incident response specialists."
          },
          "riskRules": [
            {
              "condition": "default",
              "risk": "HIGH_RISK"
            }
          ]
        },
        {
          "id": "ops_ransomware_2",
          "category": "Patching and Vulnerability Management",
          "title": "How do you manage vulnerabilities that could be exploited by ransomware?",
          "description": "Implement comprehensive vulnerability management to reduce ransomware risk.",
          "choices": [
            {
              "id": "ops_ransomware_2_a",
              "title": "We use Amazon Inspector and other tools to continuously scan for vulnerabilities.",
              "description": "Continuous scanning identifies vulnerabilities that could be exploited by ransomware.",
              "helpfulResource": {
                "displayText": "Setting up Amazon Inspector for continuous vulnerability assessment and management.",
                "url": "https://docs.aws.amazon.com/inspector/latest/user/what-is-inspector.html"
              },
              "improvementPlan": {
                "displayText": "use Amazon Inspector and other tools to continuously scan for vulnerabilities."
              }
            },
            {
              "id": "ops_ransomware_2_b",
              "title": "We have defined SLAs for patching based on vulnerability severity.",
              "description": "Defined SLAs ensure timely remediation of vulnerabilities based on risk.",
              "helpfulResource": {
                "displayText": "CVSS scoring system and vulnerability management best practices.",
                "url": "https://www.first.org/cvss/user-guide"
              },
              "improvementPlan": {
                "displayText": "have defined SLAs for patching based on vulnerability severity."
              }
            },
            {
              "id": "ops_ransomware_2_c",
              "title": "We use infrastructure as code to ensure consistent and rapid patching.",
              "description": "Infrastructure as code enables consistent and rapid deployment of patches.",
              "helpfulResource": {
                "displayText": "AWS Systems Manager Patch Manager and infrastructure as code for automated patching.",
                "url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-patch.html"
              },
              "improvementPlan": {
                "displayText": "use infrastructure as code to ensure consistent and rapid patching."
              }
            },
            {
              "id": "ops_ransomware_2_d",
              "title": "We implement compensating controls when patches cannot be immediately applied.",
              "description": "Compensating controls mitigate risk when patches cannot be immediately applied.",
              "helpfulResource": {
                "displayText": "Compensating security controls and risk mitigation strategies for unpatched systems.",
                "url": "https://www.nist.gov/cyberframework/online-learning/components-framework"
              },
              "improvementPlan": {
                "displayText": "implement compensating controls when patches cannot be immediately applied."
              }
            },
            {
              "id": "ops_ransomware_2_e",
              "title": "We are not following any of the above best practices.",
              "description": "We are not following any of the above best practices.",
              "improvementPlan": {
                "displayText": "Begin implementing vulnerability management starting with Amazon Inspector scanning."
              }
            }
          ],
          "riskLevel": "HIGH",
          "pillar": "operational_excellence",
          "improvementPlan": {
            "displayText": "Implement continuous vulnerability scanning with Amazon Inspector, define and enforce patching SLAs, use infrastructure as code for consistent patching, and implement compensating controls when needed."
          },
          "riskRules": [
            {
              "condition": "default",
              "risk": "HIGH_RISK"
            }
          ]
        },
        {
          "id": "ops_ransomware_3",
          "category": "Ransomware Alerts, Notifications and Communication",
          "title": "How do you ensure effective communication during a ransomware incident?",
          "description": "Establish communication procedures and channels that remain available during a ransomware incident.",
          "choices": [
            {
              "id": "ops_ransomware_3_a",
              "title": "We maintain out-of-band communication channels for incident response.",
              "description": "Out-of-band channels ensure communication capability even if primary systems are compromised.",
              "helpfulResource": {
                "displayText": "Emergency communication planning and out-of-band communication strategies.",
                "url": "https://www.ready.gov/business-emergency-communication-plan"
              },
              "improvementPlan": {
                "displayText": "maintain out-of-band communication channels for incident response."
              }
            },
            {
              "id": "ops_ransomware_3_b",
              "title": "We have prepared notification templates for different stakeholders and scenarios.",
              "description": "Prepared templates ensure clear and consistent communication during incidents.",
              "helpfulResource": {
                "displayText": "Crisis communication templates and stakeholder notification best practices.",
                "url": "https://www.fema.gov/emergency-managers/risk-management/communications"
              },
              "improvementPlan": {
                "displayText": "have prepared notification templates for different stakeholders and scenarios."
              }
            },
            {
              "id": "ops_ransomware_3_c",
              "title": "We maintain current contact lists for all relevant parties including third parties.",
              "description": "Current contact lists ensure that all necessary parties can be reached during an incident.",
              "helpfulResource": {
                "displayText": "Emergency contact management and stakeholder communication directory maintenance.",
                "url": "https://www.ready.gov/business-continuity-planning"
              },
              "improvementPlan": {
                "displayText": "maintain current contact lists for all relevant parties including third parties."
              }
            },
            {
              "id": "ops_ransomware_3_d",
              "title": "We regularly test our communication procedures during ransomware exercises.",
              "description": "Regular testing ensures that communication procedures are effective during actual incidents.",
              "helpfulResource": {
                "displayText": "Communication testing and crisis communication exercise planning.",
                "url": "https://www.dhs.gov/sites/default/files/publications/dhs-cybersecurity-performance-goals_0.pdf"
              },
              "improvementPlan": {
                "displayText": "regularly test our communication procedures during ransomware exercises."
              }
            },
            {
              "id": "ops_ransomware_3_e",
              "title": "We are not following any of the above best practices.",
              "description": "We are not following any of the above best practices.",
              "improvementPlan": {
                "displayText": "Begin implementing incident communication procedures starting with out-of-band channels."
              }
            }
          ],
          "riskLevel": "MEDIUM",
          "pillar": "operational_excellence",
          "improvementPlan": {
            "displayText": "Maintain out-of-band communication channels, prepare notification templates, maintain current contact lists, and regularly test communication procedures."
          },
          "riskRules": [
            {
              "condition": "default",
              "risk": "MEDIUM_RISK"
            }
          ]
        },
        {
          "id": "ops_ransomware_4",
          "category": "SIEM Integration and Monitoring",
          "title": "How do you integrate SIEM capabilities for ransomware detection?",
          "description": "Implement comprehensive SIEM integration to detect and respond to ransomware attacks.",
          "choices": [
            {
              "id": "ops_ransomware_4_a",
              "title": "We configure our SIEM with ransomware-specific detection rules.",
              "description": "Specialized detection rules identify ransomware attack patterns.",
              "helpfulResource": {
                "displayText": "SIEM detection rules and ransomware signature development for security monitoring.",
                "url": "https://www.elastic.co/guide/en/security/current/detection-engine-overview.html"
              },
              "improvementPlan": {
                "displayText": "configure our SIEM with ransomware-specific detection rules."
              }
            },
            {
              "id": "ops_ransomware_4_b",
              "title": "We integrate diverse data sources into our SIEM for comprehensive visibility.",
              "description": "Diverse data sources provide visibility into all aspects of potential ransomware activity.",
              "helpfulResource": {
                "displayText": "SIEM data source integration and log aggregation best practices for security monitoring.",
                "url": "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/security-analytics.html"
              },
              "improvementPlan": {
                "displayText": "integrate diverse data sources into our SIEM for comprehensive visibility."
              }
            },
            {
              "id": "ops_ransomware_4_c",
              "title": "We implement correlation rules to identify multi-stage ransomware attacks.",
              "description": "Correlation rules identify complex attack patterns that span multiple systems or time periods.",
              "helpfulResource": {
                "displayText": "SIEM correlation rules and multi-stage attack detection methodologies.",
                "url": "https://attack.mitre.org/techniques/T1486/"
              },
              "improvementPlan": {
                "displayText": "implement correlation rules to identify multi-stage ransomware attacks."
              }
            },
            {
              "id": "ops_ransomware_4_d",
              "title": "We protect our SIEM infrastructure from tampering during attacks.",
              "description": "Protection ensures that monitoring capabilities remain available during an attack.",
              "helpfulResource": {
                "displayText": "SIEM infrastructure hardening and security monitoring system protection.",
                "url": "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/security.html"
              },
              "improvementPlan": {
                "displayText": "protect our SIEM infrastructure from tampering during attacks."
              }
            },
            {
              "id": "ops_ransomware_4_e",
              "title": "We are not following any of the above best practices.",
              "description": "We are not following any of the above best practices.",
              "improvementPlan": {
                "displayText": "Begin implementing SIEM capabilities starting with basic ransomware detection rules."
              }
            }
          ],
          "riskLevel": "HIGH",
          "pillar": "operational_excellence",
          "improvementPlan": {
            "displayText": "Configure ransomware-specific detection rules, integrate diverse data sources, implement correlation rules, and protect SIEM infrastructure from tampering."
          },
          "riskRules": [
            {
              "condition": "default",
              "risk": "HIGH_RISK"
            }
          ]
        }
      ]
    },
    {
      "id": "performance_efficiency",
      "name": "Performance Efficiency",
      "questions": [
        {
          "id": "perf_ransomware_1",
          "category": "Resilience",
          "title": "How do you ensure your recovery processes can scale during a ransomware incident?",
          "description": "Design recovery processes that can scale to handle large-scale ransomware incidents.",
          "choices": [
            {
              "id": "perf_ransomware_1_a",
              "title": "We have tested our recovery processes at scale.",
              "description": "Testing at scale ensures recovery processes can handle large-scale incidents.",
              "helpfulResource": {
                "displayText": "AWS Well-Architected disaster recovery testing and chaos engineering practices.",
                "url": "https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/test-reliability.html"
              },
              "improvementPlan": {
                "displayText": "have tested our recovery processes at scale."
              }
            },
            {
              "id": "perf_ransomware_1_b",
              "title": "We use automation for recovery processes to improve speed and consistency.",
              "description": "Automation improves the speed and consistency of recovery processes.",
              "helpfulResource": {
                "displayText": "AWS Systems Manager automation and disaster recovery automation best practices.",
                "url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-automation.html"
              },
              "improvementPlan": {
                "displayText": "use automation for recovery processes to improve speed and consistency."
              }
            },
            {
              "id": "perf_ransomware_1_c",
              "title": "We have identified and prioritized critical systems for recovery.",
              "description": "Prioritization ensures the most critical systems are recovered first.",
              "helpfulResource": {
                "displayText": "Business impact analysis and system criticality assessment for disaster recovery.",
                "url": "https://www.ready.gov/business-impact-analysis"
              },
              "improvementPlan": {
                "displayText": "have identified and prioritized critical systems for recovery."
              }
            },
            {
              "id": "perf_ransomware_1_d",
              "title": "We have pre-provisioned recovery resources to avoid delays.",
              "description": "Pre-provisioned resources ensure rapid recovery without delays for resource allocation.",
              "helpfulResource": {
                "displayText": "AWS disaster recovery strategies and pre-provisioned resource planning.",
                "url": "https://docs.aws.amazon.com/whitepapers/latest/disaster-recovery-workloads-on-aws/disaster-recovery-strategies.html"
              },
              "improvementPlan": {
                "displayText": "have pre-provisioned recovery resources to avoid delays."
              }
            },
            {
              "id": "perf_ransomware_1_e",
              "title": "We are not following any of the above best practices.",
              "description": "We are not following any of the above best practices.",
              "improvementPlan": {
                "displayText": "Begin implementing scalable recovery processes starting with automation and system prioritization."
              }
            }
          ],
          "riskLevel": "MEDIUM",
          "pillar": "performance_efficiency",
          "improvementPlan": {
            "displayText": "Test recovery processes at scale, implement automation for recovery, prioritize critical systems, and pre-provision recovery resources."
          },
          "riskRules": [
            {
              "condition": "default",
              "risk": "MEDIUM_RISK"
            }
          ]
        },
        {
          "id": "perf_ransomware_2",
          "category": "Security Automation",
          "title": "How do you optimize your detection and monitoring capabilities for ransomware?",
          "description": "Implement efficient detection and monitoring capabilities that can identify ransomware activity without excessive resource utilization.",
          "choices": [
            {
              "id": "perf_ransomware_2_a",
              "title": "We use AWS-native security services to minimize operational overhead.",
              "description": "AWS-native services like GuardDuty, Security Hub, and Detective provide efficient detection capabilities with minimal operational overhead.",
              "helpfulResource": {
                "displayText": "Overview of AWS native security services and their integration benefits.",
                "url": "https://aws.amazon.com/products/security/"
              },
              "improvementPlan": {
                "displayText": "use AWS-native security services to minimize operational overhead."
              }
            },
            {
              "id": "perf_ransomware_2_b",
              "title": "We optimize log collection and analysis to focus on relevant security events.",
              "description": "Optimized log collection ensures that security monitoring is both effective and efficient.",
              "helpfulResource": {
                "displayText": "CloudWatch Logs optimization and efficient log analysis strategies.",
                "url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatchLogsConcepts.html"
              },
              "improvementPlan": {
                "displayText": "optimize log collection and analysis to focus on relevant security events."
              }
            },
            {
              "id": "perf_ransomware_2_c",
              "title": "We implement automated response actions for common ransomware indicators.",
              "description": "Automated response actions improve efficiency and reduce response time for common ransomware indicators.",
              "helpfulResource": {
                "displayText": "AWS Lambda and EventBridge for automated security response and incident remediation.",
                "url": "https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rules.html"
              },
              "improvementPlan": {
                "displayText": "implement automated response actions for common ransomware indicators."
              }
            },
            {
              "id": "perf_ransomware_2_d",
              "title": "We regularly tune detection thresholds to balance sensitivity and resource utilization.",
              "description": "Regular tuning ensures that detection capabilities remain effective while minimizing resource utilization.",
              "helpfulResource": {
                "displayText": "Security monitoring optimization and alert tuning best practices for efficient detection.",
                "url": "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_cloudwatch.html"
              },
              "improvementPlan": {
                "displayText": "regularly tune detection thresholds to balance sensitivity and resource utilization."
              }
            },
            {
              "id": "perf_ransomware_2_e",
              "title": "We are not following any of the above best practices.",
              "description": "We are not following any of the above best practices.",
              "improvementPlan": {
                "displayText": "Begin implementing efficient security automation starting with AWS-native services."
              }
            }
          ],
          "riskLevel": "MEDIUM",
          "pillar": "performance_efficiency",
          "improvementPlan": {
            "displayText": "Use AWS-native security services, optimize log collection and analysis, implement automated response actions, and regularly tune detection thresholds."
          },
          "riskRules": [
            {
              "condition": "default",
              "risk": "MEDIUM_RISK"
            }
          ]
        },
        {
          "id": "perf_ransomware_3",
          "category": "Specific Ransomware Use Cases",
          "title": "How do you detect and respond to specific ransomware attack patterns?",
          "description": "Implement detection and response capabilities for specific ransomware attack patterns.",
          "choices": [
            {
              "id": "perf_ransomware_3_a",
              "title": "We implement detection for ransomware targeting cloud storage services.",
              "description": "Specialized detection identifies ransomware that targets cloud storage buckets and services.",
              "helpfulResource": {
                "displayText": "S3 access logging and CloudTrail for detecting unusual storage access patterns.",
                "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html"
              },
              "improvementPlan": {
                "displayText": "implement detection for ransomware targeting cloud storage services."
              }
            },
            {
              "id": "perf_ransomware_3_b",
              "title": "We monitor for ransomware that attempts to modify cloud infrastructure via APIs.",
              "description": "API monitoring detects attempts to modify infrastructure for ransomware deployment.",
              "helpfulResource": {
                "displayText": "CloudTrail API monitoring and suspicious infrastructure modification detection.",
                "url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html"
              },
              "improvementPlan": {
                "displayText": "monitor for ransomware that attempts to modify cloud infrastructure via APIs."
              }
            },
            {
              "id": "perf_ransomware_3_c",
              "title": "We implement detection for double-extortion tactics that exfiltrate data.",
              "description": "Specialized detection identifies data exfiltration that often precedes encryption.",
              "helpfulResource": {
                "displayText": "Data loss prevention and exfiltration detection using Amazon Macie and VPC Flow Logs.",
                "url": "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html"
              },
              "improvementPlan": {
                "displayText": "implement detection for double-extortion tactics that exfiltrate data."
              }
            },
            {
              "id": "perf_ransomware_3_d",
              "title": "We monitor for ransomware that attempts to disable security tools.",
              "description": "Security tool monitoring detects attempts to disable protections before encryption.",
              "helpfulResource": {
                "displayText": "Security service monitoring and protection against security tool tampering.",
                "url": "https://docs.aws.amazon.com/config/latest/developerguide/security-best-practices.html"
              },
              "improvementPlan": {
                "displayText": "monitor for ransomware that attempts to disable security tools."
              }
            },
            {
              "id": "perf_ransomware_3_e",
              "title": "We are not following any of the above best practices.",
              "description": "We are not following any of the above best practices.",
              "improvementPlan": {
                "displayText": "Begin implementing specific ransomware detection starting with cloud storage monitoring."
              }
            }
          ],
          "riskLevel": "HIGH",
          "pillar": "performance_efficiency",
          "improvementPlan": {
            "displayText": "Implement detection for cloud storage targeting, monitor API activity, implement detection for data exfiltration, and monitor security tool status."
          },
          "riskRules": [
            {
              "condition": "default",
              "risk": "HIGH_RISK"
            }
          ]
        }
      ]
    },
    {
      "id": "cost_optimization",
      "name": "Cost Optimization",
      "questions": [
        {
          "id": "cost_ransomware_1",
          "category": "Cost Optimization",
          "title": "How do you balance cost optimization with ransomware protection?",
          "description": "Implement cost-effective ransomware protection measures.",
          "choices": [
            {
              "id": "cost_ransomware_1_a",
              "title": "We have analyzed the cost impact of different ransomware protection measures.",
              "description": "Cost analysis ensures investment in the most effective protection measures.",
              "helpfulResource": {
                "displayText": "AWS Cost Explorer and cost analysis tools for security investment optimization.",
                "url": "https://docs.aws.amazon.com/cost-management/latest/userguide/ce-what-is.html"
              },
              "improvementPlan": {
                "displayText": "have analyzed the cost impact of different ransomware protection measures."
              }
            },
            {
              "id": "cost_ransomware_1_b",
              "title": "We use tiered protection based on data and system criticality.",
              "description": "Tiered protection ensures appropriate investment based on risk and criticality.",
              "helpfulResource": {
                "displayText": "Data classification and tiered security architecture for cost-effective protection.",
                "url": "https://docs.aws.amazon.com/whitepapers/latest/data-classification/data-classification.html"
              },
              "improvementPlan": {
                "displayText": "use tiered protection based on data and system criticality."
              }
            },
            {
              "id": "cost_ransomware_1_c",
              "title": "We leverage AWS managed security services to reduce operational overhead.",
              "description": "Managed services reduce operational overhead while maintaining effective protection.",
              "helpfulResource": {
                "displayText": "Cost optimization strategies for AWS security services and managed solutions.",
                "url": "https://docs.aws.amazon.com/wellarchitected/latest/cost-optimization-pillar/welcome.html"
              },
              "improvementPlan": {
                "displayText": "leverage AWS managed security services to reduce operational overhead."
              }
            },
            {
              "id": "cost_ransomware_1_d",
              "title": "We regularly review and optimize our security controls for cost-effectiveness.",
              "description": "Regular review ensures continued cost-effectiveness of security controls.",
              "helpfulResource": {
                "displayText": "AWS Trusted Advisor and cost optimization tools for security service optimization.",
                "url": "https://docs.aws.amazon.com/awssupport/latest/user/trusted-advisor.html"
              },
              "improvementPlan": {
                "displayText": "regularly review and optimize our security controls for cost-effectiveness."
              }
            },
            {
              "id": "cost_ransomware_1_e",
              "title": "We are not following any of the above best practices.",
              "description": "We are not following any of the above best practices.",
              "improvementPlan": {
                "displayText": "Begin implementing cost-effective ransomware protection starting with managed security services."
              }
            }
          ],
          "riskLevel": "MEDIUM",
          "pillar": "cost_optimization",
          "improvementPlan": {
            "displayText": "Analyze cost impact of protection measures, implement tiered protection based on criticality, leverage managed security services, and regularly review controls for cost-effectiveness."
          },
          "riskRules": [
            {
              "condition": "default",
              "risk": "MEDIUM_RISK"
            }
          ]
        },
        {
          "id": "cost_ransomware_2",
          "category": "Backup Strategy",
          "title": "How do you optimize backup costs while maintaining ransomware resilience?",
          "description": "Implement cost-effective backup strategies that maintain ransomware resilience.",
          "choices": [
            {
              "id": "cost_ransomware_2_a",
              "title": "We use tiered storage for backups based on recovery requirements.",
              "description": "Tiered storage ensures that backup costs align with recovery requirements.",
              "helpfulResource": {
                "displayText": "S3 storage classes and lifecycle policies for cost-effective backup strategies.",
                "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage-class-intro.html"
              },
              "improvementPlan": {
                "displayText": "use tiered storage for backups based on recovery requirements."
              }
            },
            {
              "id": "cost_ransomware_2_b",
              "title": "We implement lifecycle policies to transition backups to lower-cost storage over time.",
              "description": "Lifecycle policies reduce storage costs while maintaining appropriate retention periods.",
              "helpfulResource": {
                "displayText": "S3 lifecycle management and automated storage class transitions for cost optimization.",
                "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html"
              },
              "improvementPlan": {
                "displayText": "implement lifecycle policies to transition backups to lower-cost storage over time."
              }
            },
            {
              "id": "cost_ransomware_2_c",
              "title": "We optimize backup frequency and retention based on data criticality and change rate.",
              "description": "Optimized backup frequency and retention ensures appropriate protection without excessive costs.",
              "helpfulResource": {
                "displayText": "AWS Backup cost optimization and retention policy best practices.",
                "url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/cost-optimization.html"
              },
              "improvementPlan": {
                "displayText": "optimize backup frequency and retention based on data criticality and change rate."
              }
            },
            {
              "id": "cost_ransomware_2_d",
              "title": "We regularly review and optimize our backup strategy for cost-effectiveness.",
              "description": "Regular review ensures continued cost-effectiveness of backup strategies.",
              "helpfulResource": {
                "displayText": "Backup cost analysis and optimization strategies using AWS Cost and Usage Reports.",
                "url": "https://docs.aws.amazon.com/cur/latest/userguide/what-is-cur.html"
              },
              "improvementPlan": {
                "displayText": "regularly review and optimize our backup strategy for cost-effectiveness."
              }
            },
            {
              "id": "cost_ransomware_2_e",
              "title": "We are not following any of the above best practices.",
              "description": "We are not following any of the above best practices.",
              "improvementPlan": {
                "displayText": "Begin implementing cost-effective backup strategies starting with tiered storage."
              }
            }
          ],
          "riskLevel": "MEDIUM",
          "pillar": "cost_optimization",
          "improvementPlan": {
            "displayText": "Use tiered storage for backups, implement lifecycle policies, optimize backup frequency and retention, and regularly review backup strategies for cost-effectiveness."
          },
          "riskRules": [
            {
              "condition": "default",
              "risk": "MEDIUM_RISK"
            }
          ]
        }
      ]
    },
    {
      "id": "sustainability",
      "name": "Sustainability",
      "questions": [
        {
          "id": "sust_ransomware_1",
          "category": "Sustainability",
          "title": "How do you ensure ransomware protection measures are sustainable?",
          "description": "Design ransomware protection measures that are sustainable over time.",
          "choices": [
            {
              "id": "sust_ransomware_1_a",
              "title": "We automate security processes to reduce manual effort.",
              "description": "Automation reduces manual effort and improves sustainability of security processes.",
              "helpfulResource": {
                "displayText": "AWS Security automation and orchestration with Systems Manager and Lambda.",
                "url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-automation.html"
              },
              "improvementPlan": {
                "displayText": "automate security processes to reduce manual effort."
              }
            },
            {
              "id": "sust_ransomware_1_b",
              "title": "We implement continuous improvement processes for security controls.",
              "description": "Continuous improvement ensures security controls remain effective over time.",
              "helpfulResource": {
                "displayText": "DevSecOps practices and continuous security improvement methodologies.",
                "url": "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/continuous-improvement.html"
              },
              "improvementPlan": {
                "displayText": "implement continuous improvement processes for security controls."
              }
            },
            {
              "id": "sust_ransomware_1_c",
              "title": "We balance security requirements with operational efficiency.",
              "description": "Balancing security with efficiency ensures sustainable protection measures.",
              "helpfulResource": {
                "displayText": "Well-Architected Framework for balancing security, performance, and operational efficiency.",
                "url": "https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html"
              },
              "improvementPlan": {
                "displayText": "balance security requirements with operational efficiency."
              }
            },
            {
              "id": "sust_ransomware_1_d",
              "title": "We regularly review and update our ransomware protection strategy.",
              "description": "Regular review ensures the protection strategy remains relevant and effective.",
              "helpfulResource": {
                "displayText": "Security strategy review and threat landscape adaptation best practices.",
                "url": "https://www.cisa.gov/sites/default/files/publications/CISA_MS-ISAC_Ransomware%20Guide_S508C.pdf"
              },
              "improvementPlan": {
                "displayText": "regularly review and update our ransomware protection strategy."
              }
            },
            {
              "id": "sust_ransomware_1_e",
              "title": "We are not following any of the above best practices.",
              "description": "We are not following any of the above best practices.",
              "improvementPlan": {
                "displayText": "Begin implementing sustainable security practices starting with automation."
              }
            }
          ],
          "riskLevel": "LOW",
          "pillar": "sustainability",
          "improvementPlan": {
            "displayText": "Automate security processes, implement continuous improvement, balance security with efficiency, and regularly review and update the protection strategy."
          },
          "riskRules": [
            {
              "condition": "default",
              "risk": "NO_RISK"
            }
          ]
        },
        {
          "id": "sust_ransomware_2",
          "category": "Employee Security Awareness",
          "title": "How do you ensure your team maintains ransomware awareness and readiness?",
          "description": "Implement sustainable awareness and readiness programs to maintain ransomware resilience.",
          "choices": [
            {
              "id": "sust_ransomware_2_a",
              "title": "We conduct regular ransomware awareness training for all staff.",
              "description": "Regular training ensures that all staff maintain awareness of ransomware risks and response procedures.",
              "helpfulResource": {
                "displayText": "CISA ransomware awareness training resources and best practices for employee education.",
                "url": "https://www.cisa.gov/stopransomware/ransomware-guide"
              },
              "improvementPlan": {
                "displayText": "conduct regular ransomware awareness training for all staff."
              }
            },
            {
              "id": "sust_ransomware_2_b",
              "title": "We integrate ransomware awareness into onboarding for new employees.",
              "description": "Integration into onboarding ensures that all new employees receive appropriate ransomware awareness training.",
              "helpfulResource": {
                "displayText": "Employee security awareness training and onboarding program development.",
                "url": "https://www.sans.org/security-awareness-training/"
              },
              "improvementPlan": {
                "displayText": "integrate ransomware awareness into onboarding for new employees."
              }
            },
            {
              "id": "sust_ransomware_2_c",
              "title": "We conduct regular ransomware exercises to maintain readiness.",
              "description": "Regular exercises ensure that teams maintain readiness to respond to ransomware incidents.",
              "helpfulResource": {
                "displayText": "Cybersecurity exercise planning and ransomware simulation best practices.",
                "url": "https://www.cisa.gov/sites/default/files/publications/cisa-cyber-exercise-playbook_508.pdf"
              },
              "improvementPlan": {
                "displayText": "conduct regular ransomware exercises to maintain readiness."
              }
            },
            {
              "id": "sust_ransomware_2_d",
              "title": "We update awareness materials based on emerging ransomware threats and tactics.",
              "description": "Regular updates ensure that awareness materials remain relevant to current ransomware threats.",
              "helpfulResource": {
                "displayText": "Threat intelligence integration and security awareness content updates.",
                "url": "https://www.cisa.gov/news-events/cybersecurity-advisories"
              },
              "improvementPlan": {
                "displayText": "update awareness materials based on emerging ransomware threats and tactics."
              }
            },
            {
              "id": "sust_ransomware_2_e",
              "title": "We are not following any of the above best practices.",
              "description": "We are not following any of the above best practices.",
              "improvementPlan": {
                "displayText": "Begin implementing employee security awareness starting with basic ransomware training."
              }
            }
          ],
          "riskLevel": "MEDIUM",
          "pillar": "sustainability",
          "improvementPlan": {
            "displayText": "Conduct regular ransomware awareness training, integrate awareness into onboarding, conduct regular exercises, and update awareness materials based on emerging threats."
          },
          "riskRules": [
            {
              "condition": "default",
              "risk": "MEDIUM_RISK"
            }
          ]
        }
      ]
    }
  ]
}

```
