# POSIX Permission Bits 📖
If I ask, what does `chmod 777` do - you might say it gives everyone full permissions over that file. What about `chmod 0777` or `chmod 660`? If you need an explainer, then make sure to read along as we'll be covering, from start to end, how POSIX-compliant permission bits work, a common permission system used on UNIX-like OS's like macOS, BSD and of course ... Linux!

## A breif introduction to binary numbers
Hopefully, you're already familliar with binary numbers, but if you're not heres a quick rundown:
- We humans use base-10 (denary or decimal) for counting so each place value increments in powers of 10 like this: 1, 10, 100, 1000, etc.
- Computers use base-2 (or binary) for counting so each place value increments in powers of 2 like this: 1, 2, 4, 8, 16, etc.

| Base-2 & Base-10 |
|---|
| In base-2, the maximum amount of digits is 2 (0-1 inclusive). |
|  In base-10, the maximum amount of digits is 10 (0-9 inclusive). |

To write 255 in base-10, we do the following:
![](https://github.com/adev4004/rants/blob/main/assets/1/1.png?raw=true)

So that means 2 * 100 + 5 * 10 + 5 * 1 = 255. In this case we have 3 digits which are used to represent the number. 

To do the same in base-2, we do the following:
![](https://github.com/adev4004/rants/blob/main/assets/1/2.png?raw=true)

So that means 128 * 1 + 64 * 1 + 32 * 1 + 16 * 1 + 8 * 1 + 4 * 1 + 2 * 1 + 1 * 1 = 255. In this case we have 8 bits (binary digits) which are used to represent the number. 

## Symbolic file permissions
When you run the `ls -l` you will see something like `-rwxrwxrwx` for the permissions of an object in your file system. This is the **symbolic** representation of the permissions. Let's break it down:
- The first `-` is a placeholder which usually exists on normal files. In place of this you might see different letters which identify a type of object on the filesystem. Below is a list of the common "special file" designators:
	- `d` is a directory (folder)
	- `c` is a character device
	- `l` is a symbolic link
	- `p` is a named pipe
	- `s` is a socket
	- `b` is a block device
	- `D` is a door
- The next 3 characters, in our example is `rwx`, but could be `rw-`, `r--`, or any combination are the permission bits for the **owner**. In our case, `read`, `write`, and `execute` permissions have been granted.
- The next 3 characters, are the permission bits for the **owner's group**.
- The last 3 characters, are the permission bits for **everyone else**.

To set permissions for an object on the filesystem using the symbolic method, one can use the `chmod` command. You can use `+` to set a bit, and `-` to unset a bit. To make a file executable for the **owner** you can use this command:
```bash
chmod +x <file>
```

> Note, on the third letter of each grouping, you may see another letter othan than `x`. You may see `s` or `t` if setuid/setgid or sticky bits are set and the file is executable or you may see `S` or `T` if they are set and the file is not executable. This can be confusing to understand which is why the next section will explain the numerical form. (This is explained further down.)

## Numerical file permissions
So, leading up from the previous section - how can we express `-rwxrwxrwx` as a number. Well, we first need to interpret the permission bits in binary first. Now, you could go two possible ways about this (and one of them is wrong).

### Option 1 - One binary number

![](https://github.com/adev4004/rants/blob/main/assets/1/3.png?raw=true)

The sum of this is `511`. Which is difficult to interpret for both us and the computer. So, clearly this is the incorrect way of doing it.

### Option 2 - 3 binary numbers (Correct way)

![](https://github.com/adev4004/rants/blob/main/assets/1/4.png?raw=true)

The sum of each 3-bit number is 7 (4 + 2 + 1), which gives us a permission code of 777. This is the correct numerical representation of the permission bits.

Given that now we know how to express the permissions for `-rwxrwxrwx` is both symbolic and numerical form, how can we manipulate it now? Simple, just change one of the bits. Say you want to deny write access to everyone else but yourself and your user group. Just change the W bit from 1 to a 0 in the last group.

So `111 111 111` becomes `111 111 101` which is equal to `rwx rwx r-x` which is also equal to `775` (as 4 + 1 = 5).

![](https://github.com/adev4004/rants/blob/main/assets/1/5.png?raw=true)

Now I mentioned before about how the `x` can sometimes be an `s`,`t` or the uppercase variants depending on the other special bits. This is where we can introduce the 4th optional octet. It is placed at the beginning of the permission code. The default value is `0` which means none of them are set. This means that:
- Permission `777` is the same as `0777`
- Permission `775` is the same as `0775`

Example for `0775`:

![](https://github.com/adev4004/rants/blob/main/assets/1/6.png?raw=true)

Here's a little explainer of the special bits:
- The user bit known as **SUID**, causes the file to be executed as the owner no matter who passed the command. The most common example of this is `sudo`. The `sudo` binary must have the SUID bit set because it **must** run as root (the owner) in order to elevate the command your account is trying to run.
- The group bit known as **SGID**, causes the file to be executed as the owner's **group** no matter who passed the command, similar to SUID.
- The final bit is called the **sticky bit**, this has no effect on files but when applied to a directory, it prevents deletion of the folder and files making it such that only the owner and root can remove the files.

> The SUID symbolic letters `s` and `S` will only appear in the **first** grouping in place of the `x`. For SGID, the same letters (`s` & `S`) will be used but this time, in the **second** grouping. The sticky bit, `t` or `T`, appears in the **third** group in place of the `x`.

So, if we wanted to create a file that meets these requirements and the owner is root:
- SUID bit is set (file always runs as root)
- SGID bit is not set (not needed)
- Sticky bit is not set
- Can only be modified by the owner, not the group or anyone else.
- Can be executed by everyone.

We can set the bits accordingly:

![](https://github.com/adev4004/rants/blob/main/assets/1/7.png?raw=true)

In the symbolic form:
```bash
-rwsr-xr-x
```
And in the numeric form:
```
4755
```

We can apply this to a file using `chmod` now:
```bash
chmod 4755 file
```

We can also use the symbolic method, but that could take several commands to adjust each aspect of the permissions (user, group and everyone) so for these cases, the numerical method is preferred.

And that's that! You now know how to master permissions on your POSIX filesystem!

## Additional reading resources
- https://www.redhat.com/sysadmin/suid-sgid-sticky-bit
