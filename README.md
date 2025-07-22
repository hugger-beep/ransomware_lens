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
              "improvementPlan": {
                "displayText": "Enable MFA for all AWS console and programmatic access."
              }
            },
            {
              "id": "sec_ransomware_1_b",
              "title": "We implement strict IAM policies following least privilege principles.",
              "description": "Least privilege ensures users and services have only the permissions necessary to perform their tasks, limiting the potential impact of compromised credentials.",
              "improvementPlan": {
                "displayText": "Review and implement least privilege IAM policies."
              }
            },
            {
              "id": "sec_ransomware_1_c",
              "title": "We use AWS Organizations SCPs to establish preventative guardrails.",
              "description": "Service Control Policies provide account-level restrictions that can prevent actions commonly used in ransomware attacks.",
              "improvementPlan": {
                "displayText": "Implement AWS Organizations SCPs for preventative controls."
              }
            },
            {
              "id": "sec_ransomware_1_d",
              "title": "We implement just-in-time access and temporary elevated permissions.",
              "description": "Just-in-time access reduces the window of opportunity for attackers by only granting elevated permissions when needed and for limited duration.",
              "improvementPlan": {
                "displayText": "Implement just-in-time access for administrative functions."
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
              "improvementPlan": {
                "displayText": "Enable Amazon GuardDuty in all regions."
              }
            },
            {
              "id": "sec_ransomware_2_b",
              "title": "We use AWS Security Hub to aggregate and prioritize security findings.",
              "description": "Security Hub provides a comprehensive view of security alerts and compliance status across AWS accounts.",
              "improvementPlan": {
                "displayText": "Enable AWS Security Hub for centralized security findings."
              }
            },
            {
              "id": "sec_ransomware_2_c",
              "title": "We monitor CloudTrail for suspicious administrative actions.",
              "description": "CloudTrail logs provide an audit trail of actions taken in your AWS account that can be monitored for suspicious activity.",
              "improvementPlan": {
                "displayText": "Implement CloudTrail monitoring with alerting."
              }
            },
            {
              "id": "sec_ransomware_2_d",
              "title": "We use Amazon Macie to detect sensitive data access patterns.",
              "description": "Macie can identify unusual access patterns to sensitive data that might indicate exfiltration before encryption.",
              "improvementPlan": {
                "displayText": "Enable Amazon Macie for data access monitoring."
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
              "improvementPlan": {
                "displayText": "configure Lambda functions with minimal permissions following least privilege."
              }
            },
            {
              "id": "sec_ransomware_3_b",
              "title": "We secure API Gateway endpoints with appropriate authentication and authorization.",
              "description": "Properly secured API Gateway endpoints prevent unauthorized access that could lead to ransomware deployment.",
              "improvementPlan": {
                "displayText": "secure API Gateway endpoints with appropriate authentication and authorization."
              }
            },
            {
              "id": "sec_ransomware_3_c",
              "title": "We implement runtime protection for serverless functions.",
              "description": "Runtime protection helps detect and prevent malicious code execution within serverless functions.",
              "improvementPlan": {
                "displayText": "implement runtime protection for serverless functions."
              }
            },
            {
              "id": "sec_ransomware_3_d",
              "title": "We monitor serverless event sources for unusual patterns that might indicate compromise.",
              "description": "Monitoring event sources helps detect potential ransomware activity targeting serverless architectures.",
              "improvementPlan": {
                "displayText": "monitor serverless event sources for unusual patterns that might indicate compromise."
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
              "improvementPlan": {
                "displayText": "segment our VPCs and subnets based on security requirements and data sensitivity."
              }
            },
            {
              "id": "sec_ransomware_4_b",
              "title": "We implement security groups and NACLs with least privilege access.",
              "description": "Properly configured security groups and NACLs limit network connectivity to only what is required.",
              "improvementPlan": {
                "displayText": "implement security groups and NACLs with least privilege access."
              }
            },
            {
              "id": "sec_ransomware_4_c",
              "title": "We use AWS Network Firewall or third-party solutions for advanced traffic filtering.",
              "description": "Advanced traffic filtering helps detect and block command-and-control traffic and other malicious network activity.",
              "improvementPlan": {
                "displayText": "use AWS Network Firewall or third-party solutions for advanced traffic filtering."
              }
            },
            {
              "id": "sec_ransomware_4_d",
              "title": "We implement zero trust principles for network access.",
              "description": "Zero trust principles ensure that all network access is authenticated, authorized, and encrypted regardless of source location.",
              "improvementPlan": {
                "displayText": "implement zero trust principles for network access."
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
              "improvementPlan": {
                "displayText": "conduct security assessments of SaaS providers before integration."
              }
            },
            {
              "id": "sec_ransomware_5_b",
              "title": "We implement least privilege access for third-party integrations.",
              "description": "Least privilege access limits the potential impact if a third-party integration is compromised.",
              "improvementPlan": {
                "displayText": "implement least privilege access for third-party integrations."
              }
            },
            {
              "id": "sec_ransomware_5_c",
              "title": "We monitor third-party access and activities within our environment.",
              "description": "Monitoring helps detect suspicious activities from third-party integrations.",
              "improvementPlan": {
                "displayText": "monitor third-party access and activities within our environment."
              }
            },
            {
              "id": "sec_ransomware_5_d",
              "title": "We maintain the ability to quickly disconnect compromised integrations.",
              "description": "Quick disconnection capabilities limit the impact of compromised third-party services.",
              "improvementPlan": {
                "displayText": "maintain the ability to quickly disconnect compromised integrations."
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
              "improvementPlan": {
                "displayText": "implement consistent identity and access management across cloud platforms."
              }
            },
            {
              "id": "sec_ransomware_6_b",
              "title": "We segment network connections between cloud environments.",
              "description": "Network segmentation prevents lateral movement between cloud platforms.",
              "improvementPlan": {
                "displayText": "segment network connections between cloud environments."
              }
            },
            {
              "id": "sec_ransomware_6_c",
              "title": "We correlate security alerts across cloud platforms for comprehensive visibility.",
              "description": "Alert correlation provides visibility into attacks that span multiple cloud environments.",
              "improvementPlan": {
                "displayText": "correlate security alerts across cloud platforms for comprehensive visibility."
              }
            },
            {
              "id": "sec_ransomware_6_d",
              "title": "We implement consistent encryption standards across cloud platforms.",
              "description": "Consistent encryption standards protect data regardless of where it resides.",
              "improvementPlan": {
                "displayText": "implement consistent encryption standards across cloud platforms."
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
              "improvementPlan": {
                "displayText": "implement security scanning for IaC templates before deployment."
              }
            },
            {
              "id": "sec_ransomware_7_b",
              "title": "We protect IaC repositories with strong access controls and MFA.",
              "description": "Strong access controls prevent unauthorized modifications to infrastructure code.",
              "improvementPlan": {
                "displayText": "protect IaC repositories with strong access controls and MFA."
              }
            },
            {
              "id": "sec_ransomware_7_c",
              "title": "We implement approval workflows for infrastructure changes.",
              "description": "Approval workflows prevent unauthorized or malicious infrastructure changes.",
              "improvementPlan": {
                "displayText": "implement approval workflows for infrastructure changes."
              }
            },
            {
              "id": "sec_ransomware_7_d",
              "title": "We use secure secret management for IaC pipelines.",
              "description": "Secure secret management prevents credentials from being exposed in infrastructure code.",
              "improvementPlan": {
                "displayText": "use secure secret management for IaC pipelines."
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
              "improvementPlan": {
                "displayText": "implement advanced behavioral analytics to detect AI-assisted attacks."
              }
            },
            {
              "id": "sec_ransomware_8_b",
              "title": "We protect our generative AI systems from prompt injection and poisoning attacks.",
              "description": "Protecting AI systems prevents them from being weaponized against our environment.",
              "improvementPlan": {
                "displayText": "protect our generative AI systems from prompt injection and poisoning attacks."
              }
            },
            {
              "id": "sec_ransomware_8_c",
              "title": "We use AI-enhanced security tools to counter AI-assisted threats.",
              "description": "AI-enhanced security tools can better detect and respond to AI-assisted attacks.",
              "improvementPlan": {
                "displayText": "use AI-enhanced security tools to counter AI-assisted threats."
              }
            },
            {
              "id": "sec_ransomware_8_d",
              "title": "We implement strict access controls for AI systems and sensitive data.",
              "description": "Access controls prevent AI systems from being used to identify security vulnerabilities for malicious purposes.",
              "improvementPlan": {
                "displayText": "implement strict access controls for AI systems and sensitive data."
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
              "improvementPlan": {
                "displayText": "use AWS Backup with immutable backups and time-based retention."
              }
            },
            {
              "id": "rel_ransomware_1_b",
              "title": "We implement cross-region and cross-account backup strategies.",
              "description": "Storing backups in separate regions and accounts provides isolation from the primary environment.",
              "improvementPlan": {
                "displayText": "implement cross-region and cross-account backup strategies."
              }
            },
            {
              "id": "rel_ransomware_1_c",
              "title": "We regularly test backup restoration in isolated environments.",
              "description": "Regular testing ensures backups can be successfully restored when needed.",
              "improvementPlan": {
                "displayText": "regularly test backup restoration in isolated environments."
              }
            },
            {
              "id": "rel_ransomware_1_d",
              "title": "We implement separate access controls for backup administration.",
              "description": "Separate access controls ensure that compromise of primary environment credentials does not compromise backup systems.",
              "improvementPlan": {
                "displayText": "implement separate access controls for backup administration."
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
              "improvementPlan": {
                "displayText": "version and immutably store all Lambda function code."
              }
            },
            {
              "id": "rel_ransomware_2_b",
              "title": "We implement strict S3 bucket policies and versioning for function dependencies.",
              "description": "S3 bucket policies and versioning protect function dependencies from tampering.",
              "improvementPlan": {
                "displayText": "implement strict S3 bucket policies and versioning for function dependencies."
              }
            },
            {
              "id": "rel_ransomware_2_c",
              "title": "We use infrastructure as code with version control for all serverless resources.",
              "description": "Infrastructure as code with version control enables rapid reconstruction of serverless resources.",
              "improvementPlan": {
                "displayText": "use infrastructure as code with version control for all serverless resources."
              }
            },
            {
              "id": "rel_ransomware_2_d",
              "title": "We implement function isolation and least privilege for each serverless component.",
              "description": "Function isolation and least privilege limit the blast radius of a compromise.",
              "improvementPlan": {
                "displayText": "implement function isolation and least privilege for each serverless component."
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
              "improvementPlan": {
                "displayText": "conduct regular ransomware-specific recovery exercises."
              }
            },
            {
              "id": "rel_ransomware_3_b",
              "title": "We validate that backups are free from ransomware before restoration.",
              "description": "Validation prevents restoring infected backups that could reintroduce ransomware into the environment.",
              "improvementPlan": {
                "displayText": "validate that backups are free from ransomware before restoration."
              }
            },
            {
              "id": "rel_ransomware_3_c",
              "title": "We test recovery in isolated environments before restoring to production.",
              "description": "Testing in isolated environments ensures that recovery procedures are effective and do not introduce additional risks.",
              "improvementPlan": {
                "displayText": "test recovery in isolated environments before restoring to production."
              }
            },
            {
              "id": "rel_ransomware_3_d",
              "title": "We document and measure RTO/RPO achievement in recovery exercises.",
              "description": "Measuring RTO/RPO achievement ensures that recovery objectives can be met in actual ransomware scenarios.",
              "improvementPlan": {
                "displayText": "document and measure RTO/RPO achievement in recovery exercises."
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
              "improvementPlan": {
                "displayText": "isolate payment processing systems from other infrastructure."
              }
            },
            {
              "id": "rel_ransomware_4_b",
              "title": "We implement tokenization or point-to-point encryption for payment data.",
              "description": "Tokenization and encryption minimize payment data exposure and reduce the impact of ransomware.",
              "improvementPlan": {
                "displayText": "implement tokenization or point-to-point encryption for payment data."
              }
            },
            {
              "id": "rel_ransomware_4_c",
              "title": "We maintain alternative payment processing capabilities.",
              "description": "Alternative capabilities ensure business continuity if primary payment systems are compromised.",
              "improvementPlan": {
                "displayText": "maintain alternative payment processing capabilities."
              }
            },
            {
              "id": "rel_ransomware_4_d",
              "title": "We implement enhanced monitoring for payment processing systems.",
              "description": "Enhanced monitoring enables early detection of ransomware targeting payment systems.",
              "improvementPlan": {
                "displayText": "implement enhanced monitoring for payment processing systems."
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
              "improvementPlan": {
                "displayText": "assess ransomware risks from our technology supply chain."
              }
            },
            {
              "id": "rel_ransomware_5_b",
              "title": "We include security requirements in vendor contracts.",
              "description": "Contractual requirements establish security expectations for vendors.",
              "improvementPlan": {
                "displayText": "include security requirements in vendor contracts."
              }
            },
            {
              "id": "rel_ransomware_5_c",
              "title": "We verify software dependencies and components before use.",
              "description": "Verification prevents the introduction of compromised components.",
              "improvementPlan": {
                "displayText": "verify software dependencies and components before use."
              }
            },
            {
              "id": "rel_ransomware_5_d",
              "title": "We maintain contingency plans for critical supplier compromise.",
              "description": "Contingency plans ensure business continuity if a critical supplier is compromised.",
              "improvementPlan": {
                "displayText": "maintain contingency plans for critical supplier compromise."
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
              "improvementPlan": {
                "displayText": "have documented ransomware-specific incident response procedures."
              }
            },
            {
              "id": "ops_ransomware_1_b",
              "title": "We regularly conduct tabletop exercises for ransomware scenarios.",
              "description": "Tabletop exercises help teams practice response procedures and identify gaps.",
              "improvementPlan": {
                "displayText": "regularly conduct tabletop exercises for ransomware scenarios."
              }
            },
            {
              "id": "ops_ransomware_1_c",
              "title": "We maintain offline copies of incident response procedures and contact information.",
              "description": "Offline copies ensure access to procedures even if systems are compromised.",
              "improvementPlan": {
                "displayText": "maintain offline copies of incident response procedures and contact information."
              }
            },
            {
              "id": "ops_ransomware_1_d",
              "title": "We have pre-established relationships with forensic and incident response specialists.",
              "description": "Pre-established relationships ensure rapid access to specialized expertise when needed.",
              "improvementPlan": {
                "displayText": "have pre-established relationships with forensic and incident response specialists."
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
              "improvementPlan": {
                "displayText": "use Amazon Inspector and other tools to continuously scan for vulnerabilities."
              }
            },
            {
              "id": "ops_ransomware_2_b",
              "title": "We have defined SLAs for patching based on vulnerability severity.",
              "description": "Defined SLAs ensure timely remediation of vulnerabilities based on risk.",
              "improvementPlan": {
                "displayText": "have defined SLAs for patching based on vulnerability severity."
              }
            },
            {
              "id": "ops_ransomware_2_c",
              "title": "We use infrastructure as code to ensure consistent and rapid patching.",
              "description": "Infrastructure as code enables consistent and rapid deployment of patches.",
              "improvementPlan": {
                "displayText": "use infrastructure as code to ensure consistent and rapid patching."
              }
            },
            {
              "id": "ops_ransomware_2_d",
              "title": "We implement compensating controls when patches cannot be immediately applied.",
              "description": "Compensating controls mitigate risk when patches cannot be immediately applied.",
              "improvementPlan": {
                "displayText": "implement compensating controls when patches cannot be immediately applied."
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
              "improvementPlan": {
                "displayText": "maintain out-of-band communication channels for incident response."
              }
            },
            {
              "id": "ops_ransomware_3_b",
              "title": "We have prepared notification templates for different stakeholders and scenarios.",
              "description": "Prepared templates ensure clear and consistent communication during incidents.",
              "improvementPlan": {
                "displayText": "have prepared notification templates for different stakeholders and scenarios."
              }
            },
            {
              "id": "ops_ransomware_3_c",
              "title": "We maintain current contact lists for all relevant parties including third parties.",
              "description": "Current contact lists ensure that all necessary parties can be reached during an incident.",
              "improvementPlan": {
                "displayText": "maintain current contact lists for all relevant parties including third parties."
              }
            },
            {
              "id": "ops_ransomware_3_d",
              "title": "We regularly test our communication procedures during ransomware exercises.",
              "description": "Regular testing ensures that communication procedures are effective during actual incidents.",
              "improvementPlan": {
                "displayText": "regularly test our communication procedures during ransomware exercises."
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
              "improvementPlan": {
                "displayText": "configure our SIEM with ransomware-specific detection rules."
              }
            },
            {
              "id": "ops_ransomware_4_b",
              "title": "We integrate diverse data sources into our SIEM for comprehensive visibility.",
              "description": "Diverse data sources provide visibility into all aspects of potential ransomware activity.",
              "improvementPlan": {
                "displayText": "integrate diverse data sources into our SIEM for comprehensive visibility."
              }
            },
            {
              "id": "ops_ransomware_4_c",
              "title": "We implement correlation rules to identify multi-stage ransomware attacks.",
              "description": "Correlation rules identify complex attack patterns that span multiple systems or time periods.",
              "improvementPlan": {
                "displayText": "implement correlation rules to identify multi-stage ransomware attacks."
              }
            },
            {
              "id": "ops_ransomware_4_d",
              "title": "We protect our SIEM infrastructure from tampering during attacks.",
              "description": "Protection ensures that monitoring capabilities remain available during an attack.",
              "improvementPlan": {
                "displayText": "protect our SIEM infrastructure from tampering during attacks."
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
              "improvementPlan": {
                "displayText": "have tested our recovery processes at scale."
              }
            },
            {
              "id": "perf_ransomware_1_b",
              "title": "We use automation for recovery processes to improve speed and consistency.",
              "description": "Automation improves the speed and consistency of recovery processes.",
              "improvementPlan": {
                "displayText": "use automation for recovery processes to improve speed and consistency."
              }
            },
            {
              "id": "perf_ransomware_1_c",
              "title": "We have identified and prioritized critical systems for recovery.",
              "description": "Prioritization ensures the most critical systems are recovered first.",
              "improvementPlan": {
                "displayText": "have identified and prioritized critical systems for recovery."
              }
            },
            {
              "id": "perf_ransomware_1_d",
              "title": "We have pre-provisioned recovery resources to avoid delays.",
              "description": "Pre-provisioned resources ensure rapid recovery without delays for resource allocation.",
              "improvementPlan": {
                "displayText": "have pre-provisioned recovery resources to avoid delays."
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
              "improvementPlan": {
                "displayText": "use AWS-native security services to minimize operational overhead."
              }
            },
            {
              "id": "perf_ransomware_2_b",
              "title": "We optimize log collection and analysis to focus on relevant security events.",
              "description": "Optimized log collection ensures that security monitoring is both effective and efficient.",
              "improvementPlan": {
                "displayText": "optimize log collection and analysis to focus on relevant security events."
              }
            },
            {
              "id": "perf_ransomware_2_c",
              "title": "We implement automated response actions for common ransomware indicators.",
              "description": "Automated response actions improve efficiency and reduce response time for common ransomware indicators.",
              "improvementPlan": {
                "displayText": "implement automated response actions for common ransomware indicators."
              }
            },
            {
              "id": "perf_ransomware_2_d",
              "title": "We regularly tune detection thresholds to balance sensitivity and resource utilization.",
              "description": "Regular tuning ensures that detection capabilities remain effective while minimizing resource utilization.",
              "improvementPlan": {
                "displayText": "regularly tune detection thresholds to balance sensitivity and resource utilization."
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
              "improvementPlan": {
                "displayText": "implement detection for ransomware targeting cloud storage services."
              }
            },
            {
              "id": "perf_ransomware_3_b",
              "title": "We monitor for ransomware that attempts to modify cloud infrastructure via APIs.",
              "description": "API monitoring detects attempts to modify infrastructure for ransomware deployment.",
              "improvementPlan": {
                "displayText": "monitor for ransomware that attempts to modify cloud infrastructure via APIs."
              }
            },
            {
              "id": "perf_ransomware_3_c",
              "title": "We implement detection for double-extortion tactics that exfiltrate data.",
              "description": "Specialized detection identifies data exfiltration that often precedes encryption.",
              "improvementPlan": {
                "displayText": "implement detection for double-extortion tactics that exfiltrate data."
              }
            },
            {
              "id": "perf_ransomware_3_d",
              "title": "We monitor for ransomware that attempts to disable security tools.",
              "description": "Security tool monitoring detects attempts to disable protections before encryption.",
              "improvementPlan": {
                "displayText": "monitor for ransomware that attempts to disable security tools."
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
              "improvementPlan": {
                "displayText": "have analyzed the cost impact of different ransomware protection measures."
              }
            },
            {
              "id": "cost_ransomware_1_b",
              "title": "We use tiered protection based on data and system criticality.",
              "description": "Tiered protection ensures appropriate investment based on risk and criticality.",
              "improvementPlan": {
                "displayText": "use tiered protection based on data and system criticality."
              }
            },
            {
              "id": "cost_ransomware_1_c",
              "title": "We leverage AWS managed security services to reduce operational overhead.",
              "description": "Managed services reduce operational overhead while maintaining effective protection.",
              "improvementPlan": {
                "displayText": "leverage AWS managed security services to reduce operational overhead."
              }
            },
            {
              "id": "cost_ransomware_1_d",
              "title": "We regularly review and optimize our security controls for cost-effectiveness.",
              "description": "Regular review ensures continued cost-effectiveness of security controls.",
              "improvementPlan": {
                "displayText": "regularly review and optimize our security controls for cost-effectiveness."
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
              "improvementPlan": {
                "displayText": "use tiered storage for backups based on recovery requirements."
              }
            },
            {
              "id": "cost_ransomware_2_b",
              "title": "We implement lifecycle policies to transition backups to lower-cost storage over time.",
              "description": "Lifecycle policies reduce storage costs while maintaining appropriate retention periods.",
              "improvementPlan": {
                "displayText": "implement lifecycle policies to transition backups to lower-cost storage over time."
              }
            },
            {
              "id": "cost_ransomware_2_c",
              "title": "We optimize backup frequency and retention based on data criticality and change rate.",
              "description": "Optimized backup frequency and retention ensures appropriate protection without excessive costs.",
              "improvementPlan": {
                "displayText": "optimize backup frequency and retention based on data criticality and change rate."
              }
            },
            {
              "id": "cost_ransomware_2_d",
              "title": "We regularly review and optimize our backup strategy for cost-effectiveness.",
              "description": "Regular review ensures continued cost-effectiveness of backup strategies.",
              "improvementPlan": {
                "displayText": "regularly review and optimize our backup strategy for cost-effectiveness."
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
              "improvementPlan": {
                "displayText": "automate security processes to reduce manual effort."
              }
            },
            {
              "id": "sust_ransomware_1_b",
              "title": "We implement continuous improvement processes for security controls.",
              "description": "Continuous improvement ensures security controls remain effective over time.",
              "improvementPlan": {
                "displayText": "implement continuous improvement processes for security controls."
              }
            },
            {
              "id": "sust_ransomware_1_c",
              "title": "We balance security requirements with operational efficiency.",
              "description": "Balancing security with efficiency ensures sustainable protection measures.",
              "improvementPlan": {
                "displayText": "balance security requirements with operational efficiency."
              }
            },
            {
              "id": "sust_ransomware_1_d",
              "title": "We regularly review and update our ransomware protection strategy.",
              "description": "Regular review ensures the protection strategy remains relevant and effective.",
              "improvementPlan": {
                "displayText": "regularly review and update our ransomware protection strategy."
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
              "improvementPlan": {
                "displayText": "conduct regular ransomware awareness training for all staff."
              }
            },
            {
              "id": "sust_ransomware_2_b",
              "title": "We integrate ransomware awareness into onboarding for new employees.",
              "description": "Integration into onboarding ensures that all new employees receive appropriate ransomware awareness training.",
              "improvementPlan": {
                "displayText": "integrate ransomware awareness into onboarding for new employees."
              }
            },
            {
              "id": "sust_ransomware_2_c",
              "title": "We conduct regular ransomware exercises to maintain readiness.",
              "description": "Regular exercises ensure that teams maintain readiness to respond to ransomware incidents.",
              "improvementPlan": {
                "displayText": "conduct regular ransomware exercises to maintain readiness."
              }
            },
            {
              "id": "sust_ransomware_2_d",
              "title": "We update awareness materials based on emerging ransomware threats and tactics.",
              "description": "Regular updates ensure that awareness materials remain relevant to current ransomware threats.",
              "improvementPlan": {
                "displayText": "update awareness materials based on emerging ransomware threats and tactics."
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
