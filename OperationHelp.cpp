#include "OperationHelp.h"

#include <iostream>

ClassFactory<OperationHelp> OperationHelp::RegisteredFactory(GetCommand());
ClassFactory<OperationHelp> OperationHelp::RegisteredFactoryAltOne(GetCommandAltOne());
ClassFactory<OperationHelp> OperationHelp::RegisteredFactoryAltTwo(GetCommandAltTwo());

OperationHelp::OperationHelp(std::queue<std::wstring> & oArgList, const std::wstring & sCommand) : Operation(oArgList)
{
	std::wcout <<
		LR"(
repacls.exe /Path <Absolute Path> ... other options ....

Repacls was developed to address large scale migrations, transitions, health
checks, and access control optimizations. Repacls is multi-threaded and
employs account name caching to accelerate operation on large file servers
with millions of files. It was developed to address a variety of platform
limitations, resource consumption concerns, and bugs within xcacls, icacls,
setacl, and subinacl. Limited functionality is also provided for Active
Directory objects and registry.

Important: Unless otherwise specified, all repacls commands are recursive.

Repacls must be executed with administrator permissions and will attempt to
acquire the backup, restore, and take ownership privileges during its
execution.

Any command line parameter that accepts an account or domain name can also use
a SID string instead of the name. This may be necessary if working with an
account or domain that is no longer resolvable.

Global Options
==============
Global Options affect the entire command regardless of where they appear in the
passed command line. It is recommended to include them at the very beginning
or end of your command as to not confuse them with ordered parameters.

/Path <Path>
   Specifies the file or directory to process. If a directory, the directory
   is processed recursively; all operations specified affect the directory
   and all files and folders under the directory (unless otherwise specified).
   This parameter is mandatory. This command can be specified multiple times.

   Enumerating registry paths and Active Directory containers is also supported
   when /PathMode is set. Registry paths should be specified as HIVE\Key 
   (e.g., HKLM\Software). Active Directory scanning is supported but should 
   be limited to read-only operations since permissions targeted at specific 
   properties are not supported; Active Directory paths should be specified as 
   distinguished names (e.g., OU=Users,DC=Home,DC=Local)

/PathList <FileName>
   Specifies a file that contains a list of paths to process. Each path 
   should be listed on a separate line and the file should be UTF-8 formatted. 
   Each path read from the file is processed the same as if it were passed 
   using /Path (see above). 

/PathMode <File|Registry|ActiveDirectory>
   Specifies the input format of any path specified by /Path and other ways
   of providing paths. 'File' is the default if not specified. 

/MaxDepth <NumberOfContainersDeep>
   Specifies how deep the scan should go within the path. This default is
   to be fully recursive (infinite). Specifying 0 will only enumerate the 
   root node. This does not limit the propagation of inheritable permissions 
   that could be set on children due to a change at a parent.

/SharePaths <ComputerName>[:AdminOnly|IncludeHidden|NoDeDupe|Match=|NoMatch=]
   Specifies a server that has one or more shares to process. This command is
   equivalent to specifying /Path for every share on a particular file server.
   By default, only non-administrative, non-hidden shares are scanned.
   To only scan administrative shares (e.g. C$), append :AdminOnly to the
   computer name. To include hidden, non-administrative shares, append
   :IncludeHidden to the computer name. By appending :Match= or :NoMatch=
   followed by a regular expression, any share name that does not match or 
   mismatch the specified string, respectively, will be excluded. By default, 
   shares whose directories are already covered by other shares are
   automatically de-duped; to stop this behavior use the :NoDeDupe flag.

/DomainPaths <DomainName>[:StopOnError|<See /SharePaths>]
   Specifies a domain to scan for member servers that should be processed.
   For each server that is found, a /SharePaths command is processed
   for that particular server. This takes the same extra parameters as
   /SharePaths including another option StopOnError to stop processing if
   the shares of any particular computer cannot be read; if not specified
   an error will be shown on the screen but processing will continue.

/DomainPathsWithSite <DomainName>[:StopOnError|<See /SharePaths>] [ADSite]
   Same as /DomainPaths but will further filter to the specified Active 
   Directory site name of the device. ADSite can be a regular expression.

/Quiet
   Hides all non-error output. This option will greatly enhance performance if
   a large number of changes are being processed. Alternatively, it is
   advisable to redirect console output to a file (using the > redirector) if
   /Quiet cannot be specified.

/Threads <NumberOfThreads>
   Specifies the number of threads to use while processing. The default value
   of '5' is usually adequate, but can be increased if performing changes
   over a higher-latency connection. Since changes to a parent directory
   often affect the inherited security on children, the security of children
   objects are always processed after the security on their parent objects
   are fully processed.

/Log <FileName>
   Specifies that messages written to the screen should also be written to the
   designated file. The file is a comma separated value file.

/WhatIf
   This option will analyze security and report on any potential changes
   without actually committing the data. Use of /WhatIf is recommended for
   those first using the tool.

/NoHiddenSystem
   Use this option to avoid processing any file marked as both 'hidden' and
   'system'. These are what Windows refers to 'operating system protected
   files' in Windows Explorer.

Ordered Options
===============
Ordered Options are executed on each SID encountered in the security descriptor
in the order they are specified on the command line. Executing commands in
this way is preferable to multiple commands because the security descriptor is
only read and written once for the entire command which is especially helpful
for large volumes.

Commands That Do Not Alter Settings
-----------------------------------
/PrintDescriptor
   Prints out the security descriptor to the screen. This is somewhat useful
   for seeing the under-the-covers changes to the security descriptor before
   and after a particular command.

/CheckCanonical
   This command inspects the DACL and SACL for canonical order compliance
   (i.e., the rules in the ACL are ordered as explicitly deny, explicitly 
   allow, inherited deny, inherited allow). If non-canonical entries are 
   detected, it is recommended to inspect the ACL with icacls.exe or Windows
   Explorer to ensure the ACL is not corrupted in a more significant way.

/BackupSecurity <FileName>
   Export the security descriptor to the file specified. The file is
   outputted in the format of file|descriptor on each line. The security
   descriptor is formatted as specified in the documentation for
   ConvertDescriptorToStringSecurityDescriptor(). This command does
   not print informational messages other than errors.

/FindAccount <Name|Sid>
   Reports any instance of an account specified.

/FindDomain <Name|Sid>
   Reports any instance of an account matching the specified domain.

/FindNullAcl
   Reports any instance of a null ACL. A null ACL, unlike an empty ACL, allows
   all access (i.e., similar to an ACE with 'Everyone' with 'Full Control')

/Locate <FileName> <FileRegularExpression>
   This command will write a comma separated value file with the fields of
   filename, creation time, file modified time, file size and file attributes.
   The regular expression will perform a case insensitive regular expression
   search against file name or directory name. For Active Directory scans, the 
   distinguished name is searched. For registry scans, the key name is searched
   To report all data, pass .* as the regular expression.
)";

	std::wcout <<
		LR"(
/LocateHash <FileName> <FileRegularExpression>:<SearchHash>[:<SearchSize>]
   Similar to /Locate, but the report file will also contain the hash  
   of files that match the search criteria. The hash algorithm is automatically
   determined based on the length of the provided SearchHash values, which must
   be provided in hex characters. Supported hashes are MD5, SHA1, SHA256, SHA384,
   and SHA512. The search criteria can optionally include a hash file size. 
   Specifying file size can dramatically increase search performance since only 
   files with matching sizes are read for hash comparison.

/Report <FileName> <AccountRegularExpression>
   This command will write a comma separated value file with the fields of
   filename, security descriptor part (e.g., DACL), account name, permissions,
   and inheritance flags. The regular expression will perform a case
   insensitive regular expression search against the account name in
   DOMAIN\user format. To report all data, pass .* as the regular expression.
   An optional qualifier after regular expression can be specified after the
   regular expression to refine what part of the security descriptor to scan.
   See Other Notes & Limitations section for more information.

Commands That Can Alter Settings (When /WhatIf Is Not Present)
--------------------------------
/GrantPerms <Name|Sid>:<Flags>
/DenyPerms <Name|Sid>:<Flags>
   This command will ensure the account specified has the specified access to
   the path and all containers/objects within the path either via explicit or
   inherited permissions. The syntax of <Name|Sid>:<Flags> is the same of that
   from ICACLS. For example, /GrantPerms SYSTEM:(F)(CI)(OI) will check if 
   SYSTEM has Full Control to all subdirectories and, if it does not, will add
   full control with inheritance enabled. This command is often useful to 
   correct issues where a user or administrator has mistakenly removed an group
   from subdirectories with broken inheritance.

/CanonicalizeAcls
   This command will look for out-of-order ACEs within the DACL and reorder 
   them to be canonical. Canonical order is as follows: explicit deny, explicit
   allow, inherited deny, inherited allow.

/Compact
   This command will look for mergeable entries in the security descriptor and
   merge them. For example, running icacls.exe <file> /grant Everyone:R
   followed by icacls.exe <file> /grant Everyone:(CI)(OI)(R) will produce
   two entries even though the second command supersedes the first one.
   Windows Explorer automatically merges these entries when displaying security
   information so you have to use other utilities to detect these
   inefficiencies. While there's nothing inherently wrong with these
   entries, it is possible for them to result in performance degradation.

/CopyDomain <SourceDomainName>:<TargetDomainName>
   This command is identical to /MoveDomain except that the original
   entry referring the SourceDomainName is retained instead of replaced.
   This command only applies to the SACL and the DACL. If this command is
   used multiple times, it is recommended to use /Compact to ensure there
   are not any redundant access control entries.

/CopyMap <FileName>
   This command will read in the specified file that contains a list of 
   account mappings in <SearchName>:<CopyName> format. This command only
   affects the DACL and SACL. This common is similar to the /ReplaceMap 
   command but it does not affect the owner and does not removed the original
   account.

/MoveDomain <SourceDomainName>:<TargetDomainName>
   This command will look to see whether any account in <SourceDomain>
   has an identically-named account in <TargetDomain>. If so, any entries
   are converted to use the new domain. For example,
   'OldDomain\Domain Admins' would become 'NewDomain\Domain Admins'. Since
   this operation relies on the names being resolvable, specifying a SID
   instead of domain name for this command does not work.

/RemoveAccount <Name|Sid>
   Will remove <Name> from the security descriptor. If the specified name
   is found as the file owner, the owner is replaced by the built-in
   Administrators group. If the specified name is found as the group owner
   (a defunct attribute that has no function in terms of security), it is
   also replaced with the built-in Administrators group.

/RemoveDomain <Domain|Sid>
   Remove any account whose SID is derived from the <Domain> specified.

/RemoveOrphans <Domain|Sid>
   Remove any account whose SID is derived from the <Domain> specified
   and can no longer be resolved to a valid name.

/RemoveRedundant
   This command will remove any explicit permission that is redundant of
   the permissions it is already given through inheritance. This option
   helps recover from the many individual explicit permissions that may
   have been littered from the old cacls.exe command that didn't understand
   how to set up inheritance.

/RemoveStreams
/RemoveStreamsByName <RegularExpression>
   Removes any alternate data streams on targeted files. With 
   /RemoveStreamsByName, you can also specify a regular expression to target a
   specific stream. For example: /RemoveStreamsByName ".*Zone\.Identifier.*"

/ReplaceAccount <SearchName|SearchSid>:<ReplaceName|ReplaceSid>
   Search for an account and replace it with another account.

/ReplaceMap <FileName>
   This command will read in the specified file that contains a list of
   account mappings that are specified in the same format as /ReplaceAccount.

/RestoreSecurity <FileName>
   The reverse operation of /BackupSecurity. Takes the file name and security
   descriptors specified in the file specified and applies them to the file
   system. This command does not print informational messages other than
   errors.

/SetOwner <Name|Sid>
   Will set the owner of the file to the name specified.

/UpdateHistoricalSids
   Will update any SIDs that are present in the security descriptor and are
   part of a SID history with the primary SID that is associated with an
   account. This is especially useful after a domain migration and prior to 
   removing excess SID history on accounts.
)";

	std::wcout <<
	LR"(
Exclusive Options
=================
Exclusive options cannot be combined with any other security operations.

/Help or /? or /H
   Shows this information.

/ResetChildren
   This will reset all children of path to the to inherit from the parent. It
   will not affect the security of the parent. This command does not affect
   the security of the root directory as specified by the /Path argument.

/InheritChildren
   This will cause any parent that is currently set to block inheritance to
   start allowing inheritance. Any explicit entries on the children are
   preserved. This command will not affect the security of the root directory
   as specified by the /Path argument.

Other Notes & Limitations
=========================
- To only affect a particular part of a security descriptor, you can add on an
  optional ':X' parameter after the end of the account name where X is a comma
  separated list of DACL, SACL, OWNER, or GROUP. For example,
  '/RemoveAccount "DOM\joe:DACL,OWNER"' will only cause the designated account
  to be removed from the DACL and OWNER parts of the security descriptor.

- Since repacls is multi-threaded, any file output shown on the screen or
  written to an output file may appear differently between executions. If this
  is problematic for your needs, you can turn off multi-threading by setting
  /Threads to '1' or, in the case of comparing files between runs, sort the
  output before comparing with your favorite text editor.

- Antivirus applications can degrade performance tremendously if active while
  running repacls. If performance is a concern and you are processing a large
  volume, you may want to consider temporarily disabling real-time virus
  scanning. 

Examples
========
- Replace all instances of DOM\jack to DOM\jill in C:\test:
  repacls.exe /Path C:\Test /ReplaceAccount "DOM\jack:DOM\jill"

- Migrate all permissions for all accounts with matching
  names in DOMA with DOMB:
  repacls.exe /Path C:\Test /MoveDomain DOMA:DOMB

- Update old SID references, remove any explicit permissions that are already
  granted by inherited permissions, and compact all ACLs if not compacted:
  repacls.exe /Path C:\Test /UpdateHistoricalSids /RemoveRedundant /Compact

Type 'repacls.exe /? | more' to scroll this documentation.
)";

	std::exit(0);
}