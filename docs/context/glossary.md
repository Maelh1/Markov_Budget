# Glossary

This page introduces the core concepts of an Active Directory (AD) environment.

In our project, we model Active Directory as a **graph**:

- **Nodes** represent objects (users, computers, groups, etc.)

- **Edges** represent relationships between these objects (permissions, memberships, etc.)

---

## Active Directory nodes

**Analogy**: Think of AD as a **building complex** that contains everything : people, rooms, rules, and security systems.


| Node | Simple Definition | Concrete Example | Building Analogy |
|------|------------------|------------------|------------------|
| **Domain** | A logical boundary grouping users, computers, and policies under common rules | `corp.local` domain for all employees | A **building** within a larger complex |
| **Organizational Unit (OU)** | A container used to organize users, groups, and computers | OU "HR" containing HR employees | A **floor or department** |
| **Group** | A collection of users or computers with shared permissions | "IT Admins" group managing servers | A **team with shared access badges** |
| **User** | An individual account representing a person | Employee account `jdoe` | A **person in the building** |
| **Computer** | A device joined to the domain | Company laptop connected to the network | A **workstation or office desk** |
| **Group Policy Object (GPO)** | A set of rules applied to a Domain or a OU or a Site | Enforcing strong password policies | The **building rules** |

---

## Why nodes matter in cybersecurity ?

Understanding these objects is critical because attackers often:
- Compromise **users** to gain access

- Abuse **groups** for privilege escalation

- Move laterally between **computers**

- Exploit **GPOs** to deploy malicious configurations

- Navigate through **OUs and domains** to reach critical assets

In the next section, we will explore **edges**, which define how these nodes are connected and how attacks propagate through the system.

---

## What is a Security Principal?

Before introducing edges, we need to define an important concept: **Security Principal**.

A **Security Principal** is any entity that:
- can be authenticated (it has an identity)
- can be granted permissions

### In Active Directory, this includes:
- **Users**
- **Groups**
- **Computers**

In other words, a Security Principal is **not a new type of node**, but a way to refer to all objects that can have permissions.

---

## Active Directory edges

In an Active Directory graph, **edges represent relationships between nodes**.  
They define **who can access what**, **who controls whom**, and ultimately **how an attacker can move inside the system**.

## Domain/OU → OU or Domain/OU → Security Principal

| Edge | Simple Definition | Concrete Example | Building Analogy |
|------|------------------|------------------|------------------|
| `Contains` | A container holds other objects | A Domain contains OUs; an OU contains users and computers | A building contains floors and rooms |

## Domain → Domain

| Edge | Simple Definition | Concrete Example | Building Analogy |
|------|------------------|------------------|------------------|
| `TrustedBy` | One domain trusts another for authentication | Users from Domain B can access resources in Domain A | Two buildings with shared access agreements |

## Security Principal → Group

| Edge | Simple Definition | Concrete Example | Building Analogy |
|------|------------------|------------------|------------------|
| `MemberOf` | A user or computer belongs to a group | User "jdoe" is in "IT Admins" | A person is part of a team |
| `AddMember` | Permission to add members to a group | A user can add others to "Admins" | Someone who distributes access badges |

## Security Principal → Computer

| Edge | Simple Definition | Concrete Example | Building Analogy |
|------|------------------|------------------|------------------|
| `AdminTo` | Full administrative control over a computer | User is admin on a server | A master key holder |
| `CanPSRemote` | Execute commands remotely via PowerShell | Run remote commands on a machine | A remote control system |
| `CanRDP` | Remote desktop access | Login to a server via RDP | A remote entry door |
| `ExecuteDCOM` | Execute remote commands via DCOM | Run code remotely on a machine | A hidden maintenance access |

## User → Computer

| Edge | Simple Definition | Concrete Example | Building Analogy |
|------|------------------|------------------|------------------|
| `HasSession` | A user has an active session on a computer | Admin logged into a workstation | A person currently inside a room |

## ACLs (Access Control Permissions)

| Edge | Simple Definition | Concrete Example | Building Analogy |
|------|------------------|------------------|------------------|
| `AllExtendedRights` | Special advanced permissions on an object | User has extended rights on an account | A special override permission |
| `AddAllowedToAct` | Can configure delegation rights | Allow a machine to act on behalf of others | Authorize someone to act for others |
| `AllowedToAct` | Can act on behalf of another entity | Service impersonates users | A proxy badge |
| `AllowedToDelegate` | Can delegate credentials to services | Reuse credentials across services | A trusted courier |
| `ForceChangePassword` | Can reset another user’s password | Reset admin password | Change someone’s access code |
| `GenericAll` | Full control over an object | Full access to a user or computer | Master key + full authority |
| `GenericWrite` | Can modify object attributes | Edit user properties | Modify someone’s profile/permissions |
| `GetChanges` | Can read directory changes | Monitor AD updates | Access to logs |
| `GetChangesAll` | Can read all changes (including sensitive data) | Perform DCSync attack | Access to all secrets |
| `Owns` | Ownership of an object | Own a group or resource | Legal owner of a room |
| `WriteDacl` | Modify access control lists | Change permissions on an object | Edit the access list |
| `WriteOwner` | Change ownership of an object | Take ownership of a resource | Transfer property ownership |

## GPO → Domain/OU

| Edge | Simple Definition | Concrete Example | Building Analogy |
|------|------------------|------------------|------------------|
| `GpLink` | Links a GPO to a Domain or OU | Apply a policy to all machines in an OU | Apply rules to a floor |

---

