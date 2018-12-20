# Repacls Usage Information

Link To Latest Binaries (1.10.0.0): [Here](https://github.com/NoMoreFood/Repacls/raw/v1.10.0.2/Build/Repacls.zip)

```
===============================================================================
= Repacls Version 1.10.0.2 by Bryan Berns
===============================================================================

repacls.exe /Path <Absolute Path> ... other options ....

Repacls was developed to address large scale migrations, transitions, health
checks, and access control optimizations.  Repacls is multi-threaded and
employs account name caching to accelerate operation on large file servers
with millions of files.  It was developed to address a variety of platform
limitations, resource consumption concerns, and bugs within xcacls, icacls,
setacl, and subinacl.

Important: Unless otherwise specified, all repacls commands are recursive.

Repacls must be executed with administrator permissions and will attempt to
acquire the backup, restore, and take ownership privileges during its
execution.

Any command line parameter that accepts an account or domain name can also use
a SID string instead of the name.  This may be necessary if working with an
account or domain that is no longer resolvable.

Global Options
==============
Global Options affect the entire command regardless of where they appear in the
passed command line.  It is recommended to include them at the very beginning
or end of your command as to not confuse them with ordered parameters.

/Path <Path>
   Specifies the file or directory to process.  If a directory, the directory
   is processed recursively; all operations specified affect the directory
   and all files and folders under the directory (unless otherwise specified).
   This parameter is mandatory.  This command can be specified multiple times.

/PathList <FileName>
   Specifies a file that contains a list of files or directories to process.
   Each path should be listed on a separate line and the file should be UTF-8
   formatted.  Each path read from the file is processed the same as if it 
   where passed using /Path (see above). 

/SharePaths <ComputerName>[:AdminOnly|IncludeHidden|Match=<Str>|NoMatch=<Str>]
   Specifies a server that has one or more shares to process.  This command is
   equivalent to specifying /Path for every share on a particular file server.
   By default, only non-administrative, non-hidden shares are scanned.
   To only scan administrative shares (e.g. C$), append :AdminOnly to the
   computer name.  To include hidden, non-administrative shares, append
   :IncludeHidden to the computer name.  By appending :Match= or :NoMatch=
   with a literal string or regular expression, any share name that does not
   match or mismatch the specified string, respectively, will be excluded.

/DomainPaths <DomainName>[:StopOnError|<See /SharePaths>]
   Specifies a domain to scan for member servers that should be processed.
   For each server that is found, a /SharePaths command is processed
   for that particular server.  This takes the same extra parameters as
   /SharePaths including another option StopOnError to stop processing if
   the shares of any particular computer cannot be read; if not specified
   an error will be shown on the screen but processing will continue.

/Quiet
   Hides all non-error output. This option will greatly enhance performance if
   a large number of changes are being processed.  Alternatively, it is
   advisable to redirect console output to a file (using the > redirector) if
   /Quiet cannot be specified.

/Threads <NumberOfThreads>
   Specifies the number of threads to use while processing.  The default value
   of '5' is usually adequate, but can be increased if performing changes
   over a higher-latency connection.  Since changes to a parent directory
   often affect the inherited security on children, the security of children
   objects are always processed after the security on their parent objects
   are fully processed.

/Log <FileName>
   Specifies that messages written to the screen should also be written to the
   designated file. The file is a comma separated value file.

/WhatIf
   This option will analyze security and report on any potential changes
   without actually committing the data.  Use of /WhatIf is recommended for
   those first using the tool.

/NoHiddenSystem
   Use this option to avoid processing any file marked as both 'hidden' and
   'system'.  These are what Windows refers to 'operating system protected
   files' in Windows Explorer.

Ordered Options
===============
Ordered Options are executed on each SID encountered in the security descriptor
in the order they are specified on the command line.  Executing commands in
this way is preferable to multiple commands because the security descriptor is
only read and written once for the entire command which is especially helpful
for large volumes.

Commands That Do Not Alter Security
-----------------------------------
/PrintDescriptor
   Prints out the security descriptor to the screen.  This is somewhat useful
   for seeing the under-the-covers changes to the security descriptor before
   and after a particular command.

/CheckCanonical
   This command inspects the DACL and SACL for canonical order compliance
   (i.e., the rules in the ACL are ordered as explicitly deny, explicitly 
   allow, inherited deny, inherited allow).  If non-canonical entries are 
   detected, it is recommended to inspect the ACL with icacls.exe or Windows
   Explorer to ensure the ACL is not corrupted in a more significant way.

/BackupSecurity <FileName>
   Export the security descriptor to the file specified.  The file is
   outputted in the format of file|descriptor on each line.  The security
   descriptor is formatted as specified in the documentation for
   ConvertDescriptorToStringSecurityDescriptor().  This command does
   not print informational messages other than errors.

/FindAccount <Name|Sid>
   Reports any instance of an account specified.

/FindDomain <Name|Sid>
   Reports any instance of an account matching the specified domain.

/FindNullAcl
   Reports any instance of a null ACL.  A null ACL, unlike an empty ACL, allows
   all access (i.e., similar to an ACE with 'Everyone' with 'Full Control')

/Locate <FileName> <RegularExpression>
   This command will write a comma separated value file with the fields of
   filename, creation time, file modified time, file size and file attributes.
   The regular expression will perform a case insensitive regular expression
   search against file name or directory name.  To report all data, pass .*
   as the regular expression.

/Report <FileName> <RegularExpression>
   This command will write a comma separated value file with the fields of
   filename, security descriptor part (e.g., DACL), account name, permissions,
   and inheritance flags.  The regular expression will perform a case
   insensitive regular expression search against the account name in
   DOMAIN\user format.  To report all data, pass .* as the regular expression.
   An optional qualifier after regular expression can be specified after the
   regular expression to refine what part of the security descriptor to scan.
   See Other Notes & Limitations section for more information.

Commands That Can Alter Security (When /WhatIf Is Not Present)
--------------------------------
/AddAccountIfMissing <Name|Sid>
   This command will ensure the account specified has full control access to
   path and all directories/files under the path either via explicit or
   inherited permissions.  This command does not take into account any
   permissions that would be granted to the specified user via group
   membership.  If the account does not have access, access is
   granted.  This command is useful to correct issues where a user or
   administrator has mistakenly removed an administrative group from some
   directories.

/Compact
   This command will look for mergeable entries in the security descriptor and
   merge them.  For example, running icacls.exe <file> /grant Everyone:R
   followed by icacls.exe <file> /grant Everyone:(CI)(OI)(R) will produce
   two entries even those the second command supersedes the first one.
   Windows Explorer automatically merges these entries when display security
   information so you have to use other utilities to detect these
   inefficiencies.  While there's nothing inherently wrong with these
   entries, it possible for them to result file system is performance
   degradation.

/CopyDomain <SourceDomainName>:<TargetDomainName>
   This command is identical to /MoveDomain except that the original
   entry referring the SourceDomainName is retained instead of replaced.
   This command only applies to the SACL and the DACL.  If this command is
   used multiple times, it is recommended to use /Compact to ensure there
   are not any redundant access control entries.

/MoveDomain <SourceDomainName>:<TargetDomainName>
   This command will look to see whether any account in <SourceDomain>
   has an identically-named account in <TargetDomain>.  If so, any entires
   are converted to use the new domain.  For example,
   'OldDomain\Domain Admins' would become 'NewDomain\Domain Admins'.  Since
   this operation relies on the names being resolvable, specifying a SID
   instead of domain name for this command does not work.

/RemoveAccount <Name|Sid>
   Will remove <Name> from the security descriptor.  If the specified name
   is found as the file owner, the owner is replaced by the built-in
   Administrators group.  If the specified name is found as the group owner
   (a defunct attribute that has no function in terms of security), it is
   also replace with the built-in Administrators group.

/RemoveOrphans <Domain|Sid>
   Remove any account whose SID is derived from the <Domain> specified
   and can no longer be resolved to a valid name.

/RemoveRedundant
   This command will remove any explicit permission that is redundant of
   of the permissions its already given through inheritance.  This option
   helps recovered from the many individual explicit permissions that may
   have been littered from the old cacls.exe command that didn't understand
   how to set up inheritance.

/ReplaceAccount <SearchName|SearchSid>:<ReplaceName|ReplaceSid>
   Search for an account and replace it with another account.

/ReplaceMap <FileName>
   This command will read in the specified file that contains a list of
   account mappings that are specified in the same format as /ReplaceAccount.

/RestoreSecurity <FileName>
   The reverse operation of /BackupSecurity.  Takes the file name and security
   descriptors specified in the file specified and applies them to the file
   system.  This command does not print informational messages other than
   errors.

/SetOwner <Name|Sid>
   Will set the owner of the file to the name specified.

/UpdateHistoricalSids
   Will update any SIDs that present in the security descriptor and are part
   of a SID history with the primary SID that is associated an account.  This
   is especially useful after a domain migration and prior to removing
   excess SID history on accounts.

Exclusive Options
=================
Exclusive options cannot be combined with any other security operations.

/Help or /? or /H
   Shows this information.

/ResetChildren
   This will reset all children of path to the to inherit from the parent.  It
   will not affect the security of the parent.  This command does not affect
   the security the root directory as specified by the /Path argument.

/InheritChildren
   This will cause any parent that is currently set to block inheritance to
   start allowing inheritance.  Any explicit entries on the children are
   preserved.  This command does not will not affect the security the root
   directory as specified by the /Path argument.

Other Notes & Limitations
=========================
- To only affect a particular part of a security descriptor, you can add on an
  optional ':X' parameter after the end of the account name where X is a comma
  separated list of DACL,SACL, OWNER, or GROUP.  For example,
  '/RemoveAccount "DOM\joe:DACL,OWNER"' will only cause the designated account
  to be removed from the DACL and OWNER parts of the security descriptor.

- Since repacls is multi-threaded, any file output shown on the screen or
  written to an output file may appear differently between executions.  If this
  is problematic for your needs, you can turn off multi-threading by setting
  /Threads to '1' or, in the case of comparing files between runs, sort the
  output before comparing with your favorite text editor.

- Antivirus applications can degrade performance tremendously if active while
  running repacls.  If performance is a concern and you are processing a large
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
```
