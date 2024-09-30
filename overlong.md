

# Flare-On 2019: Overlong

#flare-on #ctf #flare-on-overlong #x64dbg #reverse-engineering Sep 30,
2019






-   [\[1\] Memecat
    Battlestation](/flare-on-2019/memecat-battlestation.md)
-   [\[2\] Overlong](#)
-   [\[3\] Flarebear](/flare-on-2019/flarebear.md)
-   [\[4\] DNS Chess](/flare-on-2019/dnschess.md)
-   [\[5\] demo](/flare-on-2019/demo.md)
-   [\[6\] bmphide](/flare-on-2019/bmphide.md)
-   [\[7\] wopr](/flare-on-2019/wopr.md)




![](/img/flare2019-2-cover.png)

Overlong was a challenge that could lead to complex rabbit holes, or,
with some intelligent guess work, be solved quite quickly. From the
start, with the title and the way that the word *overlong* was bolded in
the prompt, I was looking for an integer to overflow or change in some
way. That, plus additional clues, made this one pretty quick work.

## Challenge

> The secret of this next challenge is cleverly hidden. However, with
> the right approach, finding the solution will not take an **overlong**
> amount of time.

The file is an x86 executable:



    $ file Overlong.exe
    Overlong.exe: PE32 executable (GUI) Intel 80386, for MS Windows



## Running It

It just prints a message box:

![](/img/1566912837287.png)

It's worth noting that it ends with a `:`, suggesting there might be
more message to come.

## RE

### Overview

There are only three functions:

-   `start`
-   `sub_401000`
-   `sub_401160`

### start

The `start` function is quite simple. It gets pointers to two buffers,
pushes them onto the stack (along with an integer, 0x1c), and calls
`sub_401160`, which populates one of the buffers with the message I saw
in the box above, and returns the length of that buffer. It then uses
the length to null terminal the string, and passes it to `MessageBoxA`.

![](/img/1566913210902.png)

If I load it in `x32dbg`, I'll follow the second buffer (I've named it
`Text` above) in the dump. I can see how it updates over the function
call:

[![](/img/1566913606813.png)*Click for full
size ![image*](/img/1566913606813.png)

[![](/img/1566913622476.png)*Click for full
size ![image*](/img/1566913622476.png)

Without going any further, I took a shot. My hypothesis is that
`sub_401000` takes an input buffer, and output buffer, and a length. It
then decodes byte from the input buffer into the output buffer, up to
length bytes. This explains why the message ends prematurely, if the
length is wrong.

I started the program, but when it hit a breakpoint at start, I changed
the integer value from 0x1c to 0x5c (which felt arbitrarily large enough
to get a flag). When I then hit to continue, the message box popped with
the solution:

![](/img/1566913994338.png)

**Flag: I_a_M_t_h_e_e_n_C_o_D_i_n_g@flare-on.com**





