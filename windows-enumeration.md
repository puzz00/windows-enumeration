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

![u1](images/u1.png)

The `query user` command will show us users who are logged on - this is important because we might need to be more careful with what we do if we see an admin user logged on as they might detect unusual activity more easily.

![u2](images/u2.png)

We can use `net users` to see the other user accounts on the compromised machine.

![u0](images/u0.png)

To enumerate other users present on a *domain* we can use `net user /domain`

Once we have found usernames for a local machine or a domain, we can iterate through them and run commands to look for interesting data. An example of this is searching for credentials which might have been stored in fields such as the description or comment:

```
for %n in (fcastle,mwatson,SQLService) do net user %n /domain | findstr "pass"
```

![u5](images/u5.png)

To find out which local groups exist on the victim machine, we can use `net localgroup`

![u3](images/u3.png)

We can look for interesting groups as groups can give their members elevated privileges. We can look for members of interesting groups using `net localgroup administrators` We can then potentially target members of these interesting groups for priv esc purposes.

![u4](images/u4.png)

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

![sys1](images/s1.png)

### Cmd Prompt

We can gather the necessary data without a meterpreter session by using commands in a cmd terminal.

We can use `hostname` to find the hostname.

![sys2](images/s2.png)

An excellent command is `systeminfo` as it will give us all the necessary data *including* the *hotfixes* and more. We can copy the hotfix id numbers and search online to find out more about them so we know which vulnerability the hotfix was patching.

![sys3](images/s3.png)

![sys4](images/s4.png)

To save time however we can use `wmic qfe get Caption,Description,HotFixID,InstalledOn` to get more data about the hotfixes so we dont have to research them online.

We can focus on the `Security Updates` in the returned data as these are the ones we are interested in.

There are also links to further info about the updates so we will not have to waste our lives using search engines to find the data we want.

![sys5](images/s5.png)

>[!TIP]
>It is worth looking for a file called `eula.txt` as it is found on *some* windows systems and contains useful data about the OS - if it is present on the compromised machine it will be found at `C:\Windows\System32\eula.txt`

## Network Information

It is important to enumerate data about networks when we compromise a machine as this will help us potentially *pivot* to other hosts and perhaps networks where we can possibly find more interesting data.

We are mostly interested in finding out about internal networks the machine might be connected to which we are not able to see from an external point of view.

An example of this would be a machine hosting a website which is accessible to the public internet but which is connected to an *internal* network using a different *network interface card* - this internal network is not visible to visitors of the website but can be discovered by an attacker who has compromised the server and is busy enumerating it.

>[!IMPORTANT]
>If new networks are discovered it is important that we enumerate them for new hosts - this will be covered in detail when we explore *pivoting* in a different set of notes - we need to know how to find them first which is what we are covering here

We want to find out about:

- Current IP address and network adapter
- Internal networks if present
- TCP and UDP services which are running along with their respective port numbers
- Other hosts on the *same* network as the compromised machine
- Routing and ARP table data
- Windows firewall state

We can use `ipconfig` and `ipconfig /all` to find out more about the network adapters which the compromised machine is using along with their respective network data such as IPV4 addresses and subnets.

These commands will also show us the IP address of the *defaut gateway* which is responsible for routing traffic on the subnet.

![nw1](images/n1.png)

> [!TIP]
> Even if we dont find any other networks it is still important to scan the network the compromised machine is on in order to look for hosts on it which are not visible from an external point of view

![nw6](images/n6.png)

We can use `route print` to look at the *routing table* which might show us some interesting or extra routes.

![nw2](images/n2.png)

The *arp table* is very useful and well worth looking at - it will show us the IP addresses of machines which the compromised machine has been communicating with using Address Resolution Protocol - this can help us target our further attacks against the network.

The command `arp -a` will show us the *arp table* data.

![nw3](images/n3.png)

We can find out more about the tcp and udp services which are running along with their respective ports using `netstat -ano`

![nw4](images/n4.png)

When we want to find out about the state of the firewall we can use `netsh advfirewall show allprofiles` - the `help` command can let us know what we can do `netsh advfirewall firewall help`

![nw5](images/n5.png)

## Processes and Services

It is important to find out more about the processes, services and scheduled tasks on a compromised machine.

- A process is an instance of a running executable | examples include open web browsers and documents which are being edited
- A service is a process which runs in the background and does not interact with the desktop - aka a daemon as in the original daemons from Greek myth | examples are web servers and print spoolers
- Scheduled tasks are routine tasks which have been automated to run to a set time schedule | examples include making backups of files or running anti-virus scans

### Meterpreter

We can use `ps` from inside a *meterpreter* session to list the running processes on a compromised machine.

![p1](images/p1.png)

We can filter by the *architecture* of the processes using `ps -A x64` for *64 bit* processes and `ps -A x86` for *32 bit* processes.

![p2](images/p2.png)

![p3](images/p3.png)

If we want to find only processes which are running as *NT AUTHORITY/SYSTEM* - the most privileged non-interactive user account - using `ps -s`

![p4](images/p4.png)

>[!NOTE]
>We will only see the *system* processes if we are already operating within the security context of a privileged user

We can combine filter commands - for example if we only want to see *64 bit* processes which are running as *NT AUTHORITY/SYSTEM* we can use `ps -A x64 -s`

We can search by the name of the process using `pgrep explorer.exe`

![p5](images/p5.png)

The *process id* along with its *name* | *architecture* and the *security privileges* it is running under are important to note.

>[!TIP]
>When it comes to *migrating* our *meterpreter* session to a different process we can use `migrate <PID>` - *explorer.exe* is a good stable process to use

![p6](images/p6.png)

### Command Shell

We can use `net start` to see the running *services* and we can get more data about them using `wmic service list brief`

![p7](images/p7.png)

![p8](images/p8.png)

If we want to find the running *processes* along with the *services* which are running under them using `tasklist /SVC`

![p9](images/p9.png)

To look at the *scheduled tasks* we can use `schtasks /query /fo LIST /v` This command returns lots of data so it makes sense to save its output into a *.txt* file.

![p10](images/p10.png)

![p11](images/p11.png)

## Automating Windows Local Enumeration

Whilst it is important to know how to *manually* enumerate a windows machine - it is a good idea to use *automated* enumeration scripts when we are working within a tight time schedule as they quickly check and return all of the areas we have covered in these notes - they can also perform simple *privilege escalation* enumeration.

### Meterpreter

We can run automated checks from within a meterpreter session if we have one.

To find out more about the user we have gained access to the compromised machine as we can use `run post/windows/gather/win_privs`

![auto1](images/a1)

We can enumerate the logged-on users and the *recently* logged-on users with `run post/windows/gather/enum_logged_on_users`

![auto2](images/a2)

It is possible to see if the compromised machine is a *virtual machine* by using `run post/windows/gather/checkvm`

![auto3](images/a3)

To find out more about the installed applications we can use `run post/windows/gather/enum_applications` - this can be useful to run when we are looking for *priv esc* opportunities via vulnerable applications.

![auto4](images/a4)

We can enumerate the other computers which are in the same *domain* as the compromised machine using `run post/windows/gather/enum_computers`

![auto5](images/a5)

>[!NOTE]
>If the compromised machine is not part of a *domain* we will not see any hosts get returned from the command `run post/windows/gather/enum_computers`

If we do find new hosts on the domain we can consider trying to *pivot* to them.

We can enumerate installed *patches* and *hotfixes* by using `run post/windows/gather/enum_patches`

![auto6](images/a6)

To enumerate network shares which are available we can use `run post/windows/gather/enum_shares`

The command to perform an *arp scan* on a specified *subnet* is `run post/windows/gather/arp_scanner RHOSTS=10.2.26.0/24`

![auto7](images/a7)

We can establish a new route to a different subnet - for example another subnet which the compromised machine is attached to via a different *nic* - by using `run autoroute -s 172.16.56.0/24`

We can use the same command to establish a route to the internal subnet which the first compromised machine is attached to - it does not have to be *dual homed* for us to find new target machines `run autoroute -s 10.2.16.0/20`

The active *routing table* can be enumerated using `run autoroute -p`

![auto8](images/a8)

The active *routing table* will - hopefully - now show the newly added route which will use the meterpreter session on the compromised machine as a way to *pivot* to the newly discovered network.

### Just Another Windows Enumeration Script

A good powershell enumeration script to use is [J.A.W.S.](https://github.com/411Hall/JAWS)

Since it is written in powershell we do not have to worry about trying to get an `.exe` binary to execute on the compromised machine.

We can download jaws to our attacking machine and then transfer it to the compromised machine.

>[!TIP]
>When transfering data to a compromised windows machine it is a good idea to transfer it to `C:\Temp` - if this directory does not already exist we can create it by using `mkdir C:\Temp`

Once we have sucessfully transferred jaws onto the victim machine we can run it using `powershell.exe -ep bypass .\jaws.ps1 -OutputFilename jaws.txt`

![auto9](images/a9)

>[!NOTE]
>We have saved the returned data to a `.txt` file because jaws returns lots of data and we will want to be able to analyse it more easily - the resulting `jaws.txt` file can be transferred to our attacking machine

### PrivescCheck

Another good enumeration script which uses powershell is [PrivescCheck.ps1](https://github.com/itm4n/PrivescCheck)

Once we have transfered it to the victim machine we can run it using `powershell.exe -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Report priv_esc_check_1"`

The above command will run the checks and save the returned data into a report called `priv_esc_check_1`

![auto10](images/a10)

>[!TIP]
>We can use the `-Extended` flag to get more data from PrivescCheck

## Conclusion

We have looked at ways to enumerate a compromised windows machine when we first land on it.

Manual methods have been covered as well as the use of an automated script or two.

The main thing to keep in mind is that *all data is useful* and as such needs to be recorded in a systematic way so we can go back to it during our test and quickly find what we need.

The data we collect during enumeration paves the way for privilege escalation opportunities | it can help when looking to obtain persistence and it can lead us to new hosts and networks to attack.

All in all - we need to get to understand the nature of the system or systems we are working on as each is unique - the better we enumerate and understand what we find - the more successful our attacks will be :smiley: 

---

> water shapes its course according to the nature of the ground over which it flows | the soldier works out his victory in relation to the foe whom he is facing