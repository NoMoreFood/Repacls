---
layout: default
title: Command reference
permalink: /reference/
---

# Repacls command reference

[Usage guide]({{ '/' | relative_url }}) · [Download binaries](https://github.com/NoMoreFood/Repacls/releases/latest)

```text
repacls.exe /Path <Path> [global options] [operations]
```

Run Repacls from an administrator command prompt. Scans are recursive by default. This reference describes the commands in the source tree; run `repacls.exe /?` for the options supported by your executable.

- [Scan options](#scan-options)
- [Inspection and reporting](#inspection-and-reporting)
- [Security updates](#security-updates)
- [Inheritance and help](#inheritance-and-help)
- [Permission flags and scopes](#permission-flags-and-scopes)

## Scan options

Global options apply to the entire command regardless of where they appear.

| Option | Purpose |
| --- | --- |
| `/Path <Path>` | Scan a file, directory, registry key, or AD distinguished name. Repeat to scan multiple roots. |
| `/PathList <FileName>` | Read a UTF-8 file containing one scan path per line. |
| <code>/PathMode &lt;File&#124;Registry&#124;ActiveDirectory&gt;</code> | Choose the object type. `File` is the default. `REG` and `ADS` are accepted abbreviations. |
| `/MaxDepth <Depth>` | Limit how deep to scan. `0` processes only the root; the default has no depth limit. Permission inheritance can still affect descendants beyond that limit. |
| `/SharePaths <Server>[:Options]` | Scan shares discovered on a server. By default, skip administrative and hidden shares and deduplicate overlapping share paths. |
| `/DomainPaths <Domain>[:Options]` | Discover domain member servers and scan their shares. Accepts the share options below and `StopOnError`. |
| `/DomainPathsWithSite <Domain>[:Options] <SiteRegex>` | Restrict domain server discovery to Active Directory sites matching a regular expression. |
| `/Threads <Count>` | Set the number of worker threads. The default is `5`. |
| `/Quiet` | Suppress non-error console messages. |
| `/Log <FileName>` | Write console messages to a CSV file. |
| `/WhatIf` | Analyze proposed security changes without applying them. |
| `/NoHiddenSystem` | Skip objects that have both the hidden and system attributes. |

Share options are separated by colons:

| Option | Purpose |
| --- | --- |
| `AdminOnly` | Scan only administrative shares. |
| `IncludeHidden` | Include hidden, nonadministrative shares. |
| `NoDeDupe` | Preserve overlapping share paths instead of deduplicating them. |
| `Match=<Regex>` | Include shares whose names match the expression. |
| `NoMatch=<Regex>` | Exclude shares whose names match the expression. |
| `StopOnError` | With domain discovery, stop when a server's shares cannot be read. |

```bat
repacls.exe /SharePaths "FileServer:IncludeHidden:Match=Team.*" /Report "shares.csv" ".*"
repacls.exe /DomainPathsWithSite "CONTOSO:StopOnError" "Boston.*" /Report "sites.csv" ".*"
```

Registry paths use forms such as `HKLM\Software`; AD paths use distinguished names such as `OU=Teams,DC=Contoso,DC=Com`. Active Directory scans force `/WhatIf` and support inspection rather than changes to property-specific permissions.

## Inspection and reporting

| Operation | Purpose |
| --- | --- |
| `/PrintDescriptor` | Print security descriptors as objects are processed. |
| `/CheckCanonical` | Report ACLs whose entries are not in canonical order. |
| `/BackupSecurity <FileName>` | Save each scanned object's path and security descriptor as <code>path&#124;descriptor</code>. |
| <code>/FindAccount &lt;Name&#124;Sid&gt;</code> | Find references to a particular account. |
| <code>/FindDomain &lt;Domain&#124;Sid&gt;</code> | Find references to accounts in a domain. |
| `/FindNullAcl` | Find null ACLs, which allow unrestricted access. |
| `/Report <FileName> <AccountRegex>` | Write a CSV with paths, descriptor parts, accounts, permissions, and inheritance flags. Use `.*` for all accounts. |
| `/Locate <FileName> <FileRegex>` | Report matching file names and their creation time, modified time, size, and attributes. Also supports names of registry and AD objects. |
| `/LocateHash <FileName> <FileRegex>:<Hash>[:<Size>]` | Find files with the specified hash. An optional file size avoids hashing files of a different size. |
| `/LocateText <FileName> <FileRegex>:<TextRegex>` | Search matching files line by line and report the full path, line number, and matched text. Supports UTF-16 LE, UTF-8, and ANSI text. |
| `/LocateShortcut <FileName> <TargetRegex>` | Find `.lnk` files whose stored target path matches the expression. Report the shortcut path, timestamps, size, attributes, target, and working directory. |

Name and text expressions are case insensitive. `/LocateText` matches the file name before reading its contents. `/LocateShortcut` reads stored targets without saving changes to the shortcut files.

`/LocateHash` determines the algorithm from the hexadecimal hash length: MD5, SHA1, SHA256, SHA384, or SHA512.

```bat
repacls.exe /Path "D:\Shares" /FindAccount "CONTOSO\Auditors"
repacls.exe /Path "D:\Logs" /LocateText "errors.csv" ".*\.log:ERROR"
repacls.exe /Path "D:\Shares" /LocateShortcut "shortcuts.csv" "\\\\OldServer\\.*"
```

`/BackupSecurity` records Windows security descriptor strings, including the descriptor parts retrieved for the scan. `/RestoreSecurity` applies saved descriptors to matching paths.

## Security updates

Operations run in the order specified. Combine related operations to perform them in one scan. Use `/WhatIf` to preview proposed security changes.

| Operation | Purpose |
| --- | --- |
| <code>/GrantPerms &lt;Name&#124;Sid&gt;:&lt;Flags&gt;</code> | Ensure the account has the specified allow permissions, adding entries where necessary. |
| <code>/DenyPerms &lt;Name&#124;Sid&gt;:&lt;Flags&gt;</code> | Ensure the account has the specified deny permissions. |
| <code>/AddAccountIfMissing &lt;Name&#124;Sid&gt;</code> | Shorthand for granting inheritable full control with `(CI)(OI)(F)`. |
| <code>/SetOwner &lt;Name&#124;Sid&gt;</code> | Change ownership. |
| <code>/ReplaceAccount &lt;SourceName&#124;Sid&gt;:&lt;TargetName&#124;Sid&gt;</code> | Replace one account with another in selected descriptor parts. |
| <code>/ReplaceMap &lt;FileName&gt;[&#124;&lt;Parts&gt;]</code> | Read account replacements from a UTF-8 mapping file. An optional part list restricts the descriptor parts to update. |
| `/CopyMap <FileName>` | Copy mapped account permissions while preserving the source account. Affects DACL and SACL entries, not ownership. |
| `/MoveDomain <SourceDomain>:<TargetDomain>` | Replace domain account references with matching account names in the target domain. Both domains must be resolvable. |
| `/CopyDomain <SourceDomain>:<TargetDomain>` | Add equivalent DACL and SACL entries for matching target-domain accounts while retaining source entries. |
| `/UpdateHistoricalSids` | Replace an account's historical SID references with its primary SID. |
| <code>/RemoveAccount &lt;Name&#124;Sid&gt;</code> | Remove references to the account. If it owns the object or is its primary group, replace that reference with the built-in Administrators group. |
| <code>/RemoveDomain &lt;Domain&#124;Sid&gt;</code> | Remove references to accounts whose SIDs belong to the domain. |
| <code>/RemoveOrphans &lt;Domain&#124;Sid&gt;</code> | Remove references to unresolved accounts in the specified domain. |
| `/RemoveRedundant` | Remove explicit permission entries already supplied by inheritance. |
| `/Compact` | Merge compatible ACL entries. |
| `/CanonicalizeAcls` | Reorder entries into canonical ACL order. |
| `/RestoreSecurity <FileName>` | Restore descriptors saved by `/BackupSecurity` to matching paths. |
| `/RemoveStreams` | Remove alternate data streams from scanned files. |
| `/RemoveStreamsByName <Regex>` | Remove alternate data streams whose names match the expression. |

Mapping files contain one source and target pair per line:

```text
OLD\Accounting:NEW\Finance
OLD\Engineering:NEW\Engineering
```

Account arguments usually accept a name or SID. `/MoveDomain` and `/CopyDomain` need resolvable domain names for account-name matching.

```bat
repacls.exe /Path "D:\Shares" /ReplaceMap "accounts.txt|DACL,OWNER" /WhatIf
repacls.exe /Path "D:\Shares" /UpdateHistoricalSids /RemoveRedundant /Compact /WhatIf
repacls.exe /Path "D:\Shares" /RemoveStreamsByName ".*Zone\.Identifier.*" /WhatIf
```

## Inheritance and help

Inheritance operations are exclusive and cannot be combined with other security operations. Global scan options, including `/Path`, `/MaxDepth`, and `/WhatIf`, still apply.

| Operation | Purpose |
| --- | --- |
| `/ResetChildren` | Reset descendants to inherit security from their parents. Leave the selected root's security unchanged. |
| `/InheritChildren` | Enable inheritance on descendants while preserving explicit entries. Leave the selected root's security unchanged. |
| `/Help`, `/?`, `/H` | Show executable help. No scan path is required. |

```bat
repacls.exe /Path "D:\Shares" /InheritChildren /WhatIf
```

## Permission flags and scopes

`/GrantPerms` and `/DenyPerms` accept ICACLS-style flags. Quote the entire account-and-flags argument so the shell preserves parentheses.

| Flag | Meaning |
| --- | --- |
| `F` | Full control. |
| `M` | Modify. |
| `RX` | Read and execute. |
| `R` | Read. |
| `W` | Write. |
| `D` | Delete. |
| `CI` | Child directories inherit the entry. |
| `OI` | Child files inherit the entry. |
| `IO` | Inherit only; the entry does not apply to the current object. |
| `NP` | Do not propagate inheritance beyond immediate children. |

Advanced rights include `N`, `DE`, `RC`, `WDAC`, `WO`, `S`, `AS`, `MA`, `GR`, `GW`, `GE`, `GA`, `RD`, `WD`, `AD`, `REA`, `WEA`, `X`, `DC`, `RA`, and `WA`.

```bat
repacls.exe /Path "D:\Shares" /GrantPerms "CONTOSO\Auditors:(CI)(OI)(RX)" /WhatIf
```

For operations that accept descriptor scopes, append a colon and a comma-separated list of `DACL`, `SACL`, `OWNER`, or `GROUP` to the account argument. A DACL controls access; a SACL controls auditing. The scope limits which parts an operation can inspect or change.

```bat
repacls.exe /Path "D:\Shares" /RemoveAccount "CONTOSO\FormerUser:DACL,OWNER" /WhatIf
```

`/ReplaceMap` uses a pipe before the part list, such as `"accounts.txt|DACL,OWNER"`.

Multithreaded report order can vary. Use `/Threads 1` when sequential output is needed, or sort CSV reports before comparing them.
