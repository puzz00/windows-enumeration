# Enumerating Windows

## Users and Groups

We need to find out which user we have gained access to a target machine as along with the privileges which are associated with that user.

We will also need to enumerate more about the other users on the machine along with the groups they belong to. This is important for the purposes of priv esc. We will want to know which users belong to groups which have elevated privileges such as members of the local administrators group.

We will want to find out the following:

- Current user and privs
- Additional user info (password policy, age, expirty etc)
- Other users on the system / domain
- Groups and group memberships - interesting groups which might have elevated privs
- Members of the built-in Administrator group

Once we know which users belong to interesting groups we can target them for priv esc purposes.

### Meterpreter

From a meterpreter session, we can use `getuid` and `getprivs` or `run post/windows/gather/win_privs` to find out more about the current user and their privileges.

We can also background the session and use `use post/windows/gather/enum_logged_on_users` to find out which other users are logged onto the target machine.

### Cmd Prompt

We can use windows commands to enumerate users and groups.

The command `whoami` lets us know the username. We can also use `echo %USERNAME%`

We can use `whoami /priv` to find out more about the privileges of the current user.

To find out more about other users on the compromised machine, we can use `query user` and `net user` and to find out more about a specific user we can use `net user messi`

The `query user` command will show us users who are logged on - this is important because we might need to be more careful with what we do if we see an admin user logged on as they might detect unusual activity more easily.

To enumerate other users present on a *domain* we can use `net user /domain`

Once we have found usernames for a local machine or a domain, we can iterate through them and run commands to look for interesting data. An example of this is searching for credentials which might have been stored in fields such as the description or comment:

```
for %n in (fcastle,mwatson,SQLService) do net user %n /domain | findstr "pass"
```

To find out which local groups exist on the victim machine, we can use `net localgroup`

We can look for interesting groups as groups can give their members elevated privileges. We can look for members of interesting groups using `net localgroup administrators` We can then potentially target members of these interesting groups for priv esc purposes.

## System Information

When we land on a victim machine, it is important that we take the time to enumerate more about its system. We need this information to help us with other post exploitation activities such as privilege escalation. We will want to know the following:

- Hostname
- OS Name | Windows 10, 11 etc
- OS Build and Service Pack | Windows 7 SP1 7600 for example
- OS Architecture | x64 or x86
- Installed Updates and Hotfixes

This information will help us look for known vulnerabilities and exploits which can be used on the target system.

The architecture will help us if we are developing a priv esc exploit - for compilation purposes - or we are crafting a *meterpreter* session.

The security updates will let us know if it is worth our while working with an exploit or not - it is useless if the vulnerability has been already patched.

### Meterpreter

We can use `getuid` and `sysinfo` to collect useful data from within a *meterpreter* session on the victim machine. These commands will return to us all the data we covered above *except* the installed updates and hot fixes.

![sys1](images/1.png)

### Cmd Prompt

We can gather the necessary data without a meterpreter session by using commands in a cmd terminal.

We can use `hostname` to find the hostname.

![sys2](images/2.png)

An excellent command is `systeminfo` as it will give us all the necessary data *including* the *hotfixes* and more. We can copy the hotfix id numbers and search online to find out more about them so we know which vulnerability the hotfix was patching.

![sys3](images/3.png)

![sys4](images/4.png)

To save time however we can use `wmic qfe get Caption,Description,HotFixID,InstalledOn` to get more data about the hotfixes so we dont have to research them online.

We can focus on the `Security Updates` in the returned data as these are the ones we are interested in.

There are also links to further info about the updates so we will not have to waste our lives using search engines to find the data we want.

![sys5](images/5.png)

>[!TIP]
>It is worth looking for a file called `eula.txt` as it is found on *some* windows systems and contains useful data about the OS - if it is present on the compromised machine it will be found at `C:\Windows\System32\eula.txt`
