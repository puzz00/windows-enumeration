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

