---
layout: default
title: Usage guide
---

# Repacls usage guide

Repacls inspects and updates Windows permissions across files, directories, shares, and other Windows objects. Use it for access reviews, file server and domain migrations, inheritance repairs, and security backups. Multiple operations can run in one recursive scan, with account-name caching and configurable worker threads to support large file servers.

[Download binaries](https://github.com/NoMoreFood/Repacls/releases/latest) · [Command reference]({{ '/reference/' | relative_url }}) · [Source and build instructions](https://github.com/NoMoreFood/Repacls)

## Get started

Download the ZIP attached to a GitHub release, extract it, and choose the executable in the `x64` or `x86` folder. The release also includes individual executables and a `SHA256SUMS.txt` file. The automatically generated source archives contain source files.

Run Repacls from an administrator command prompt. It attempts to acquire the backup, restore, and take-ownership privileges needed to process security settings. Paths are scanned recursively unless you restrict the depth with `/MaxDepth`.

To list the commands supported by your executable:

```bat
repacls.exe /?
```

The command reference follows the source tree; your executable's help lists the options available in that build.

## Audit a share

Export a CSV report of accounts, permissions, and inheritance flags:

```bat
repacls.exe /Path "\\FileServer\Team" /Report "permissions.csv" ".*"
```

Filter the report to accounts in a particular domain:

```bat
repacls.exe /Path "\\FileServer\Team" /Report "contoso.csv" "CONTOSO\\.*"
```

Use `/FindAccount` or `/FindDomain` to locate account references, `/FindNullAcl` to find objects with a null ACL, and `/CheckCanonical` to find permission entries that are out of canonical order. A null ACL allows unrestricted access; an empty ACL grants no access.

## Back up and preview changes

Save security descriptors before a migration or permission repair:

```bat
repacls.exe /Path "D:\Shares" /BackupSecurity "security-backup.txt"
```

Preview an account replacement:

```bat
repacls.exe /Path "D:\Shares" /ReplaceAccount "OLD\Team:NEW\Team" /WhatIf
```

`/WhatIf` reports proposed security changes without applying them. Review the output, then run the same command without `/WhatIf` to apply the change. `/RestoreSecurity` reads the descriptors saved by `/BackupSecurity` and applies them to matching paths within the scan:

```bat
repacls.exe /Path "D:\Shares" /RestoreSecurity "security-backup.txt" /WhatIf
```

## Migrate accounts and domains

`/CopyDomain` keeps existing access and adds equivalent entries for matching account names in another domain. `/MoveDomain` replaces those references instead. Both domains must be resolvable for name-based matching. For renamed accounts, use `/CopyMap`, `/ReplaceMap`, or `/ReplaceAccount` with an explicit mapping.

```bat
repacls.exe /Path "D:\Shares" /CopyDomain "OLD:NEW" /WhatIf
repacls.exe /Path "D:\Shares" /ReplaceMap "accounts.txt" /WhatIf
```

A mapping file is UTF-8 text with one source and destination account per line:

```text
OLD\Accounting:NEW\Finance
OLD\Engineering:NEW\Engineering
```

After an Active Directory migration, `/UpdateHistoricalSids` replaces historical SID references with the account's primary SID. Most account arguments also accept SID strings, which are useful when an old account can no longer be resolved.

## Repair access and inheritance

Grant inheritable read and execute access to a group:

```bat
repacls.exe /Path "D:\Shares" /GrantPerms "CONTOSO\Auditors:(CI)(OI)(RX)" /WhatIf
```

Permission flags use the familiar ICACLS notation. `(CI)` applies inheritance to child directories, `(OI)` to child files, and `(RX)` grants read and execute access.

`/RemoveRedundant` removes explicit permission entries already supplied by inheritance. `/Compact` merges compatible entries, while `/CanonicalizeAcls` puts entries in canonical order. These operations run in the order specified:

```bat
repacls.exe /Path "D:\Shares" /RemoveRedundant /Compact /WhatIf
```

`/InheritChildren` enables inheritance on descendants while preserving their explicit entries. `/ResetChildren` resets descendants to inherit from their parent. These two operations are exclusive: run each separately from other security operations. The root path's security settings are preserved.

## Choose the scan scope

Repeat `/Path` to scan multiple roots or use `/PathList` with a UTF-8 file containing one path per line. `/SharePaths` discovers shares on a server; `/DomainPaths` discovers shares across domain member servers; `/DomainPathsWithSite` restricts discovery to matching Active Directory sites.

```bat
repacls.exe /SharePaths "FileServer:IncludeHidden" /Report "server.csv" ".*"
repacls.exe /PathList "paths.txt" /Report "selected.csv" ".*"
```

With `/PathMode Registry`, use paths such as `HKLM\Software`. With `/PathMode ActiveDirectory`, use distinguished names such as `OU=Teams,DC=Contoso,DC=Com`. Active Directory scanning is limited to inspection and reporting: Repacls forces `/WhatIf` in this mode and does not model permissions on individual AD properties.

## Inspect files and shortcuts

`/Locate` reports matching file names and metadata, `/LocateHash` matches file contents by hash, `/LocateText` reports matching text lines, and `/LocateShortcut` finds `.lnk` files by their stored target path. Reports can be opened as CSV files.

```bat
repacls.exe /Path "D:\Logs" /LocateText "errors.csv" ".*\.log:ERROR"
repacls.exe /Path "D:\Shares" /LocateShortcut "shortcuts.csv" "\\\\OldServer\\.*"
```

Use `/RemoveStreams` or `/RemoveStreamsByName` when you need to remove alternate data streams from files.

## Control output and performance

Global options apply to the entire command regardless of their position. `/Threads` controls concurrency, `/Quiet` suppresses non-error console output, and `/Log` writes console messages to a CSV file. Account names are cached during the scan.

Multithreaded output order can vary. Use `/Threads 1` for sequential processing, or sort reports when comparing scans. When scanning large trees, `/Quiet` or redirected console output can reduce output overhead.

See the [command reference]({{ '/reference/' | relative_url }}) for complete syntax, permission flags, share-discovery options, and security-descriptor scopes.
