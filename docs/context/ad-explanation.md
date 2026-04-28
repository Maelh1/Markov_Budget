# What is Active Directory ?

## Definition
**Active Directory (AD)** is a directory service developed by Microsoft since 1999 for Windows Server environments. It provides a centralized structure for managing identities, computers, and network resources within an organization.
In a modern enterprise, Active Directory is almost always present.

---

## Main Roles
Active Directory performs several vital functions:

* **User Management**: Centralization of accounts and identities.

* **Access Control**: Precise management of network connections.

* **Machine Administration**: Management of the IT fleet (workstations and servers).

* **Permission Definition**: Assignment of rights to resources.

---

## The Challenge of Modern Security
Designed over twenty years ago, the system was conceived in a context where cybersecurity stakes were very different. While threats have evolved radically, Active Directory configurations often remain unchanged, sometimes favoring ease of use over security.

---

## Common Vulnerabilities

* **Lateral Movement**: Attackers exploit relationships between system elements to reach critical resources such as Domain Controllers.

* **Privileged Access Management**: Intermediate users often have sensitive rights without real global control.

* **Default Read Access**: The system often allows access to sensitive information that helps an attacker map the network.

---

## Risks Associated with Access Control Lists (ACL)
ACLs are often complex and misconfigured, creating indirect paths to elevated privileges:

* A non-administrator user may possess permissions allowing them to become an administrator.

* **Typical Example**: A technical support account capable of resetting the password of a critical account.

Thus, Active Directory security does not solely depend on protecting the most sensitive accounts, but on all the relationships and permissions that structure the system. This complexity makes it difficult to identify flaws and explains why **Active Directory remains a major target for cyberattacks.**

---

> **Source**: Darren Mar-Elia, based on analyses published on [semperis.com](https://www.semperis.com/blog/tools-attacking-active-directory/).