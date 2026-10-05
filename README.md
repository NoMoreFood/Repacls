# Repacls

Repacls is a Windows command-line utility for inspecting and updating permissions across large directory trees. It helps administrators audit access, migrate accounts between domains, repair access control lists, and back up or restore security settings. Multithreaded scanning and account-name caching make it useful on file servers with large numbers of files.

[Download Repacls](https://github.com/NoMoreFood/Repacls/releases/latest) · [Usage guide and command reference](https://nomorefood.github.io/Repacls/)

## What can it do?

- **Audit permissions:** export CSV reports, find references to particular accounts or domains, and identify unresolved accounts, null ACLs, and noncanonical permission entries.
- **Migrate access:** copy or replace accounts, map accounts from a file, move permissions between domains, and update references to historical SIDs.
- **Repair permissions:** grant or deny access, change ownership, restore inheritance, and remove redundant or mergeable permission entries.
- **Back up security:** save security descriptors and restore them across scanned objects.
- **Inspect files:** report file metadata, search by name, content, or hash, find shortcuts by their target, and remove alternate data streams.
- **Scan multiple locations:** process local paths, UNC paths, lists of paths, server shares, or shares discovered across an Active Directory domain.

Repacls primarily works with files and folders. It also supports registry security and limited inspection of Active Directory objects.

## Where would you use it?

Use Repacls during file server and domain migrations to find permissions that still reference old accounts, copy access to replacement accounts, or apply an explicit account mapping. It is also useful for access reviews: produce reports for a share, account, or domain and investigate orphaned or unusually permissive security settings.

For routine maintenance, Repacls can recover inheritance, consolidate ACL entries, and correct ownership or access across a directory tree. Operations can be combined into one scan, so a large file server does not need to be enumerated separately for each change.

## Get started

Download the ZIP from [GitHub Releases](https://github.com/NoMoreFood/Repacls/releases/latest) and extract the executable for your architecture from the `x64` or `x86` directory. Run it from an administrator command prompt. Precompiled binaries and their SHA-256 checksums are attached to releases; the source archives contain source files.

Export a permissions report:

```bat
repacls.exe /Path "D:\Shares" /Report "permissions.csv" ".*"
```

Back up security settings before making changes:

```bat
repacls.exe /Path "D:\Shares" /BackupSecurity "security-backup.txt"
```

Preview replacing an account across the tree:

```bat
repacls.exe /Path "D:\Shares" /ReplaceAccount "OLD\Team:NEW\Team" /WhatIf
```

Scanning is recursive by default. `/WhatIf` previews proposed changes to security settings; remove it when you are ready to apply those changes. Global options control the scan, while security operations run in the order you specify.

The [usage guide](https://nomorefood.github.io/Repacls/) covers scanning shares and domains, permission flags, account mappings, inheritance, and the full command reference. Run `repacls.exe /?` to see the options supported by your installed build.

## Building from source

Open [Build/repacls.sln](Build/repacls.sln) in Visual Studio with the C++ desktop tools and Windows SDK installed. Select `x64` or `x86` and build a Debug or Release configuration. Executables are written under `Build/Debug` or `Build/Release`; intermediate files are kept under `Build/Temp`.

| Directory | Contents |
| --- | --- |
| [Code](Code/) | C++ source, headers, and executable resources. |
| [Build](Build/) | Visual Studio solution and projects, plus the signing and ZIP packaging script. |
| [Tests](Tests/) | Native ACL regressions and PowerShell functional tests. |

Repacls is maintained by Bryan Berns and distributed under the [GNU General Public License](LICENSE).
