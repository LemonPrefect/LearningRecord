---
# image bucket id
butterId: 4df72543-170c-4dff-a021-5bc0cff9f636
---

# Week5 Summary

## What have I done

- BUUOJ 刷题 WriteUps
- 蓝帽杯挨打（

## [WriteUp] How did I accomplish these things

### [INSHack2018]GCorp - Stage 1

使用 Wireshark 分析流量包，跟踪 TCP 流，可以在最后找到如下信息。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1619713619333.f265f6fe03e57d2bc95f9015285a3ffe0ee84e31.png)

```plain text
SU5TQXtjMTgwN2EwYjZkNzcxMzI3NGQ3YmYzYzY0Nzc1NjJhYzQ3NTcwZTQ1MmY3N2I3ZDIwMmI4MWUxNDkxNzJkNmE3fQ==
```

将其 Base64 解码一次即可得到 flag。

```flag
INSA{c1807a0b6d7713274d7bf3c6477562ac47570e452f77b7d202b81e149172d6a7}
```

### [HarekazeCTF2019]A_Z

`/source`  页面中可以找到如下关键代码片段。

```javascript
app.get('/', function (req, res, next) {
  let output = '';
  const code = req.query.code + '';
  if (code && code.length < 200 && !/[^a-z().]/.test(code)) {
    try {
      const result = vm.runInNewContext(code, {}, { timeout: 500 });
      if (result === 1337) {
        output = process.env.FLAG;
      } else {
        output = 'nope';
      }
    } catch (e) {
      output = 'nope';
    }
  } else {
    output = 'nope';
  }
  res.render('index', { title: '[a-z().]', output });
});
```

因此关键在于如何使用限定的字符集 `a-z().` 构造出 1337 这个数。通过尝试可以发现如下几点。

```javascript
(typeof(self)) // object
(typeof(self)).constructor.length // 1
NaN.constructor.length // 1
true.constructor.length // 1
(typeof(self)).sub.name.length // 3
(typeof(self)).replace.name.length //7
```

因此可以构造出如下载荷。

```javascript
eval(((typeof(self)).constructor()).concat(true.constructor.length).concat((typeof(self)).sub.name.length).concat((typeof(self)).sub.name.length).concat((typeof(self)).replace.name.length))
```

将载荷提交即可得到 flag。

```flag
flag{8d58e39a-55b3-45b3-a0f4-c297774e4077}
```

### [网鼎杯 2020 青龙组]虚幻2

检测附件的类型可知是一张图片。

```plain text
File type:   Portable Network Graphics image
Extension:   png
MIME type:   image/png
```

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1619757360271.90f7c54ea3f9a8c76011d7b2a05a17c6dbefa8bf.png)

猜测是三个颜色通道信息的叠合，同时看结构很像是汉信码。写个脚本将内容还原一下。

```python
from PIL import Image

image = Image.open('file.png')
pixels = ''
for i in range(0, 36):
    for j in range(0, 12):
        pixel = image.getpixel((i, j))
        for k in range(0, 3):
            pixels += ('1' if pixel[k] == 0 else '0')
print(pixels)
```

运行脚本可以得到如下内容。

```plain text
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011111110000110111111110011111110000010000000001100111101100000000010000010111110000000110110110011111010000010100000001010100111111000001010000010101110001010110110001011101010000010101110010010101010000011101010000010101110100110100010000011101010000000000000101010101111001000000000000000000000000010101001100111011000000001101100011010110000000100100100000001111101010000101010011100000110000010101000010110111111001111000000000010001101001100110011001111110000000000000000000000110001000001111000000011111111111111111110010010001010000011101001001000010110000111101000000011101010000101101110011010110100000010101010100110111001110010001110000010000101100001000101111000011110000011010110000111111101110100101110000011011011110010011110111101100010000011101001110010100001011001000110000000110111000100110111010000000000000000000000101110101111101000000000000010101110001111000000000011101010000010101110010000000000000011101010000010101110101011000000000011101010000010100000100000000000000000001010000010111110010110000000000011111010000010000000000000000000000000000010000011111110011000000000000011111110000000000000000000000000000000000000000000000000000000000000000000000000
```

使用如下的 CyberChef Receipt 可以生成图片。

```plain text
Find_/_Replace({'option':'Regex','string':'1'},'\\x00',true,false,true,false)
Find_/_Replace({'option':'Regex','string':'0'},'\\xff',true,false,true,false)
Generate_Image('Greyscale',8,36)
```

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1619758126695.8d3d19307f83033960293ab3218d7ba9eb7db210.png@100w)

将图片稍微处理一下，再填充一下空白处，使用汉信码的 app 扫描即可得到 flag。

![image-20210430130813382](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1619759293831.ffc0d6b42993834fcf636e9c42879f555fbe1408.png@100w)

```flag
flag{eed70c7d-e530-49ba-ad45-80fdb7872e0a}
```

### [INSHack2019]Passthru

用 Wireshark 载入附件中的 sslkey 后分析流量包，可以发现很多含有 `kcahsni` 的请求，将其反写可得 `inshack`，因此推测其与 flag 相关。使用 tshark 将请求的参数内容取出。

```plain text
tshark -r capture.pcap -o "tls.keylog_file:sslkey.log" -Y "http contains \"GET /searchbyimage\"" -T fields -e http.request.uri.query.parameter > data.txt
```

将取出的数据使用如下 CyberChef Receipt 处理即可得到含有 flag 的字符串。

```plain text
URL_Decode()
Find_/_Replace({'option':'Regex','string':'^i(.*)&kcahsni='},'',true,false,true,false)
Find_/_Replace({'option':'Regex','string':',(.*)$\\n'},'',true,false,true,false)
From_Hex('Auto')
Reverse('Character')
```

```flag
INSA{b274dddb2c7707ebe430dadcf1245c246713502d6e9579f00acd10a83f3da95e}
```

### [INSHack2019]Crunchy

附件给出的代码如下。

```python
def crunchy(n):
    if n < 2: return n
    return 6 * crunchy(n - 1) + crunchy(n - 2)

g = 17665922529512695488143524113273224470194093921285273353477875204196603230641896039854934719468650093602325707751568

print("Your flag is: INSA{%d}"%(crunchy(g)%100000007))
```

由于数字太大导致递归超出了范围，尝试用 SageMath 来解出。SageMath 中提供了一个包可以用来快速算出斐波那契数列。

> https://doc.sagemath.org/html/en/reference/combinat/sage/combinat/binary_recurrence_sequences.html

此时只需要写个脚本解出答案即可。

```python
g = 17665922529512695488143524113273224470194093921285273353477875204196603230641896039854934719468650093602325707751568
modNum = 100000007
binaryRecurrenceSequence = BinaryRecurrenceSequence(6, 1)
period = binaryRecurrenceSequence.period(modNum)
print(binaryRecurrenceSequence(g % period) % modNum)
```

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1619781699640.51fec9fdb628f17abfff1e39c0ff74afa1457d27.png)

```flag
INSA{41322239}
```

### [WMCTF2020]行为艺术

附件给出了一张图片，010 打开运行模板得到 CRC Mismatch 提示后根据 `hex: 0x380 0x284` 修正其高度，即可得到下图。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1619783064801.3ffc54440bf441f4c148ba8cecb921cf5b035da1.png)

略微读一下内容很容易发现图片的数字中有一个压缩文档，将图片内容转写下来得到如下信息。

```plain text
504B0304140000000800DB93C55086A39007D8000000DF01000008000000666C61672E74787475504B0E823010DD93708771DDCCB0270D5BBD0371815A9148AC6951C2ED9D271F89C62E2693D7F76BB7DE9FC80D2E6E68E782A326D2E01F81CE6D55E76972E9BA7BCCB3ACEF7B89F7B6E90EA16A6EE2439D45179ECDD1C5CCFB6B9AA489C1218C92B898779D765FCCBB58CC920B6662C5F91749931132258F32BBA7C288C5AE103133106608409DAC419F77241A3412907814AB7A922106B8DED0D25AEC8A634929025C46A33FE5A1D3167A100323B1ABEE4A7A0708413A19E17718165F5D3E73D577798E36D5144B66315AAE315078F5E51A29246AF402504B01021F00140009000800DB93C55086A39007D8000000DF010000080024000000000000002000000000000000666C61672E7478740A00200000000000010018004A0A9A64243BD601F9D8AB39243BD6012D00CA13223BD601504B050600000000010001005A000000FE00000000000000
```

使用如下的 CyberChef Receipt 可得到下一步的信息。

```plain text
From_Hex('None')
Unzip('',false)
Decode_text('UTF-8 (65001)')
```

```plain text
Good eyes! Here is your flag:
https://www.splitbrain.org/services/ook

+++++ ++++[ ->+++ +++++ +<]>+ +++++ .<+++ [->-- -<]>- .<+++ [->-- -<]>-
.<+++ +[->+ +++<] >+.<+ ++[-> ---<] >---- -.<++ +++++ [->++ +++++ <]>++
++.-- --.<+ +++[- >---- <]>-- ----. +++++ +++.< +++[- >---< ]>-.+ ++.++
+++++ .<+++ [->-- -<]>- .+++. -.... --.++ +.<++ +[->+ ++<]> ++++. <++++
++++[ ->--- ----- <]>-- ----- ----- --.<+ +++[- >++++ <]>+. +...< +++++
+++[- >++++ ++++< ]>+++ +++++ +++.. .-.<
```

使用信息中的网站进行 Brainfuck to Text 可得 flag。

```flag
WMCTF{wai_bi_baaaa_bo!2333~~~}
```

### [羊城杯 2020]逃离东南亚

附件解压后得到三个日记压缩文档，第一个打开后有一张图片。010 editor 打开后可知需要修复图片宽高。将其依照脚本爆破结果 `hex: 0xf9 0x12c` 修复后可得下图。

![image-20210430200843458](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1619784523989.9dd75ab600acad5e77d2d49666fbbf7e92b5f96b.png)

将 `wdnmd` 作为压缩包密码解压日记 2 压缩文档可得一串 Brainfuck 和一个音频。在 Brainfuck 前面补充上 8 个 `+` 即可解码成功并得到一串 Base64。使用 CyberChef 解码后检测文件类型可知其是一个 ELF 文件。

```plain text
File type:   Executable and Linkable Format
Extension:   elf,bin,axf,o,prx,so
MIME type:   application/x-executable
Description: Executable and Linkable Format file. No standard file extension.
```

将其用 IDA 打开可以得到如下源码。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  puts("hei~what you want??");
  sleep(1u);
  puts("want a flag? ");
  sleep(1u);
  puts("sorry~there is no flag");
  sleep(1u);
  puts("but maybe your can find something useful!");
  return 0;
}
```

音频中考虑存在隐写，因此尝试使用 SilentEye 尝试 Decode，得到了如下信息。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1619785170884.0fff21ffad708894d53adce50bf0f09b4510612e.png)

使用 `This1sThe3rdZIPpwd` 作为密码解压日记 3。可以得到一份日记和 libc 的源码。从 NEWS 中可以得到版本信息 `Version 2.28`。从 GitHub 上下载对应的源码，然后用 Diff Merge 做比对。根据日记中的暗示可以知道信息留存在代码中，因此比对一下更改即可。

> https://github.com/bminor/glibc/tree/3c03baca37fdcb52c3881e653ca392bba7a99c2b

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1619801149914.5fe37a86d125627e668512ba8efb9f780d0dbaca.png)

可以发现有一个文件的代码里增加了很多空格。此时再换到 Beyond Compare 比对一下可以得到如下结果，猜测这些空格中确实隐藏了信息。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1619802917513.76c172704eed10ca2c598d0a31f80221c78d3029.png)

使用如下的 CyberChef Receipt 可以得到其中的信息。

```plain text
Diff('\\n\\n\\n\\n\\n','Character',true,true,true,false)
Find_/_Replace({'option':'Regex','string':' '},'0',true,false,false,false)
Find_/_Replace({'option':'Regex','string':'\\t'},'1',true,false,true,false)
Find_/_Replace({'option':'Regex','string':'\\n'},'',true,false,true,false)
Find_/_Replace({'option':'Regex','string':'000000000'},'',true,false,true,false)
From_Binary('None',8)
```

```plain text
//Extract from arena.c
your flag is in malloc.c

//Extract from rtld.c
SOS! please help me -> rtld.c
```

对 malloc.c 提取信息可得 flag。

```flag
GWCTF{code_steganography_1s_funny!}
```

### [RCTF2019]printer

Wireshark 分析流量包，可得如下内容，

```plain text
BAR 348, 439, 2, 96 
BAR 292, 535, 56, 2 
BAR 300, 495, 48, 2 
BAR 260, 447, 2, 88 
BAR 204, 447, 56, 2 
BAR 176, 447, 2, 96 
BAR 116, 455, 2, 82 
BAR 120, 479, 56, 2 
BAR 44, 535, 48, 2 
BAR 92, 455, 2, 80 
BAR 20, 455, 72, 2 
BAR 21, 455, 2, 40 
BAR 21, 495, 24, 2 
BAR 45, 479, 2, 16 
BAR 36, 479, 16, 2 
BAR 284, 391, 40, 2 
BAR 324, 343, 2, 48 
BAR 324, 287, 2, 32 
BAR 276, 287, 48, 2 
BAR 52, 311, 48, 2 
BAR 284, 239, 48, 2 
BAR 308, 183, 2, 56 
BAR 148, 239, 48, 2 
BAR 196, 191, 2, 48 
BAR 148, 191, 48, 2 
BAR 68, 191, 48, 2 
BAR 76, 151, 40, 2 
BAR 76, 119, 2, 32 
BAR 76, 55, 2, 32 
BAR 76, 55, 48, 2 
BAR 112, 535, 64, 2 
BAR 320, 343, 16, 2 
BAR 320, 319, 16, 2 
BAR 336, 319, 2, 24 
BAR 56, 120, 24, 2 
BAR 56, 87, 24, 2 
BAR 56, 88, 2, 32 
BAR 224, 247, 32, 2 
BAR 256, 215, 2, 32 
BAR 224, 215, 32, 2 
BAR 224, 184, 2, 32 
BAR 224, 191, 32, 2 
BAR 272, 311, 2, 56 
BAR 216, 367, 56, 2 
BAR 216, 319, 2, 48 
BAR 240, 318, 2, 49 
BAR 184, 351, 2, 16 
BAR 168, 351, 16, 2 
BAR 168, 311, 2, 40 
BAR 152, 351, 16, 2 
BAR 152, 351, 2, 16
```

根据提示可找到打印机的文档。

> http://www.kroyeuropedownload.com/English_User_Manuals/TSPL_TSPL2_Programming_Jan_2017.pdf

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1619857758744.c0f6f3dcad14151a48e8e3c518c2b0281178029b.png)

根据规则使用 Python 将图片画出来。

```python
from PIL import Image

barcmds = [cmd.replace("BAR", "").strip().split(",") for cmd in open("barcmds", "r").readlines()]
image = Image.new("RGB", (500, 600), "white")

for cmd in barcmds:
    bar = Image.new("RGB", (int(cmd[2]), int(cmd[3])), (16, 63, 145))
    image.paste(bar, (int(cmd[0]), int(cmd[1])))
image = image.rotate(180)
image.save("result.png")
```

得到如下图片。

![image-20210501180326759](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1619863407310.69df5e90d7fbc0e9c714544ecf43ef43aef09db9.png@300w)

流量中还包含了 bitmap 的数据，根据文档中的描述可知其结构。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1619864785244.54cb2b6ee5a0f0cf7d05d146f9e22c74635f9366.png)

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1619864866827.52fa39cdcccc3ab704b2d2bd168a845f6fb4c445.png)

因此将指定部分数据提取出来后用如下 CyberChef Receipt 处理即可得到剩下部分的 flag。

```plain text
From_Hex('Auto')
To_Binary('None',8)
Find_/_Replace({'option':'Regex','string':'0'},'\\x00',true,false,true,false)
Find_/_Replace({'option':'Regex','string':'1'},'\\xff',true,false,true,false)
Generate_Image('Greyscale',1,208)
Rotate_Image(180)
```

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1619865002536.ac6f30af5426ef86b05724805d8c552883fe18b8.png)

```flag
flag{my_tsc_hc3pnikdk}
```

### [b01lers2020]matryoshka

附件给出的图片中有不同向的草莓，使用脚本将数据处理一下然后使用 CyberChef 重新渲染图片。

```python
from PIL import Image

image = Image.open("matryoshka.png")
offset = 12
for x in range(offset, image.width, 50):
    for y in range(offset, image.height, 50):
        (r, g, b) = image.getpixel((x, y))
        print(1 if r != 0 else 0, end="")
```

```plain text
Find_/_Replace({'option':'Regex','string':'1'},'\\xFF',true,false,true,false)
Find_/_Replace({'option':'Regex','string':'0'},'\\x00',true,false,true,false)
Generate_Image('Greyscale',2,121)
```

得到了一个二维码。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1619867652603.70d38bbeaf26cff1eb1ea7931979e516427a2552.png)

使用如下工具扫描可得一个 GZIP 文件。

> https://online-barcode-reader.inliteresearch.com/

使用如下的 CyberChef Receipt 处理可以得到一个二维码。

```plain text
From_Hexdump()
Gunzip()
Find_/_Replace({'option':'Regex','string':'l'},'\\xFF',true,false,true,false)
Find_/_Replace({'option':'Regex','string':'1'},'\\x00',true,false,true,false)
Generate_Image('Greyscale',2,86)
```

再次扫描得出的二维码后用如下 CyberChef Receipt 处理可得到又一个二维码。

```plain text
From_Hexdump()
Render_Image('Raw')
Invert_Image()
```

再次扫描二维码后可得一个 7z 文件的数据，稍微处理后将其打开。使用弱密码尝试可得压缩包密码为 1234。将压缩包解压即可得到 flag。

```flag
pctf{dolls_do_get_boring_after_a_while}
```

### [NPUCTF2020]OI的梦

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1619874114080.cc1b99f63ca59054e8a407ed8779a7635bceab28.png)

矩阵快速幂可以解决，很容易找到如下代码示例。稍微修改一下示例的代码。

> https://blog.csdn.net/bianxia123456/article/details/105167294/

```python
def mulMatrix(x, y):
    ans = [[0 for i in range(101)] for j in range(101)]
    for i in range(101):
        for j in range(101):
            for k in range(101):
                ans[i][j] += x[i][k] * y[k][j]
                ans[i][j] %= 10003
    return ans


def quickMatrix(m, n):
    E = [[0 for i in range(101)] for j in range(101)]
    for i in range(101):
        E[i][i] = 1
    while (n):
        if n % 2 != 0:
            E = mulMatrix(E, m)
        m = mulMatrix(m, m)
        n >>= 1
    return E


matrix = [[0 for i in range(101)] for j in range(101)]
dataIn = open("yyh.in", "r").readlines()
n, m, steps = dataIn[0].strip().split()
m = int(m)
for x in range(0, m):
    i, j = dataIn[x + 1].strip().split()
    i = int(i)
    j = int(j)
    matrix[i][j] = 1
    matrix[j][i] = 1
ans = quickMatrix(matrix, int(steps))
print(ans[1][int(n)])
```

```flag
flag{5174}
```

### Ball_sigin

egret 引擎开发的小游戏，主要的代码都在 Games.js 中。主要的玩法是操作小球滑动躲避树并收集对应左上角单词缺失的字母。将 Games.js 下载下来后格式化，可以发现在`hitWordLetter()` 方法下有如下逻辑。

```javascript
if (this._score === 60) {
	this.gameOverFunc();
}
```

也就是只要分数达到六十分即可获胜，定位到 `gameOverFunc()` 可以发现获胜结果是通过向 `/testData` 发送 POST 请求从服务端获取的，其中提交的数据结构如下。

```javascript
var datas = {
	'balls': this._balls,
	'trees': this._trees,
	'words': this._words,
	'infos': this._infos
};
```

将 `gameOverFunc()` 处的判断改一下，使其无论分数多少都提交数据，从而得到如下提交样例。

![](https://butter.lumosary.workers.dev/images/archive/7f363bdc-676b-4e98-b8ef-59cfda4fd170/1619697838325.4f1b9e467ccf84e6a2b596cef2bfc5c88fb973d1.png)

可以发现树的位置和单词的位置以及小球的位置都会被实时记录，因此想要手动伪造一份记录十分困难。定位到 `addBarriers()` 方法可以发现树的坐标是随机生成的，因此可以稍作修改使树排排站。

```javascript
treeBg.x = 1;
treeBg.y = Math.random() * (this._stageH - 80 - (this._isFitstApperar ? 500 : 0)) + (this._isFitstApperar ? 500 : 0);
```

使用 Fiddler 拦截请求来替换 Games.js，即可轻松完成游戏设定的目标。

![](https://butter.lumosary.workers.dev/images/archive/7f363bdc-676b-4e98-b8ef-59cfda4fd170/1619697410922.9a61625f26a8fcbfcfd85c5661c44861ce5d0534.png)

```flag
flag{f2852395-1f2b-47a6-bd29-cd54bb67a614}
```

### [Unsolved] one_Pointer_php

> how to change my euid？

#### PHP_INT_MAX 导致赋值报错

下载题目给出的附件，可以得到如下代码。

```php
<?php
include "user.php";
if($user=unserialize($_COOKIE["data"])){
	$count[++$user->count]=1;
	if($count[]=1){
		$user->count+=1;
		setcookie("data",serialize($user));
	}else{
		eval($_GET["backdoor"]);
	}
}else{
	$user=new User;
	$user->count=1;
	setcookie("data",serialize($user));
}
?>
```

```php
<?php
class User{
	public $count;
}
?>
```

很容易发现判断的语句是一个赋值语句，因此需要尝试让赋值语句返回 `false`。恰巧赋值的是一个数组，当数组的下标达到 `PHP_INT_MAX` 即 9223372036854775807 时再次使用 `$count[]=1` 增加新的数组元素时即会失败。因此只要让 `$count` 的值为 `PHP_INT_MAX` 即可，构造出如下序列化脚本。

```php
<?php
class User{
	public $count = PHP_INT_MAX - 1;
}
echo serialize(new User);
?>
```

运行脚本得到了如下载荷。

```php
O:4:"User":1:{s:5:"count";i:9223372036854775806;}
```

将载荷拼接到 `$_COOKIE["data"]` 中即可到达 `eval($_GET["backdoor"]);`，从而执行一部分指令。执行 `phpinfo()` 可以发现靶机所使用的是 PHP 7.4.16，且有如下 disable_functions 和 disable_classes。

```plain text
stream_socket_client,fsockopen,putenv,pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,iconv,system,exec,shell_exec,popen,proc_open,passthru,symlink,link,syslog,imap_open,dl,mail,error_log,debug_backtrace,debug_print_backtrace,gc_collect_cycles,array_merge_recursive

	Exception,SplDoublyLinkedList,Error,ErrorException,ArgumentCountError,ArithmeticError,AssertionError,DivisionByZeroError,CompileError,ParseError,TypeError,ValueError,UnhandledMatchError,ClosedGeneratorException,LogicException,BadFunctionCallException,BadMethodCallException,DomainException,InvalidArgumentException,LengthException,OutOfRangeException,PharException,ReflectionException,RuntimeException,OutOfBoundsException,OverflowException,PDOException,RangeException,UnderflowException,UnexpectedValueException,JsonException,SodiumException
```

### 冬奥会_is_coming

附件给出了一张图片，使用 `binwalk -e` 可以分离出一个压缩文档。压缩包的备注中有 `eight numbers` 的提示，但是压缩包本身并没有被加密，因此猜测是有隐写。使用 010 editor 打开解压所得的音频文件可在其尾部发现如下信息。

```plain text
🙃💵🌿🎤🚪🌏🐎🥋🚫😆🎃✅⌨🔪❓🚫🐍🙃🔬✉👁😆🎈🐘🏎🐘🐘😂😎🎅🖐🐍✉🍌🌪🐎🍵✅🚪✖☃👣👉ℹ🔪🍎🔄👣🚪😁👣💵🐅🍵🔬🛩😇🖐🖐🎅✅🏎👌🚨😆🎤🎅🦓🌿🦓🙃✖🍌🛩😂👑🌏☃😇😍🛩🚹😀🍌🎈💧🗒🗒
```

猜测是 emoji-aes 加密，但是使用冬奥会的日期作为 key 尝试解密并不成功，因此猜测在音频中仍然有信息。使用 MP3stego 配合冬奥会日期 `20220204` 作为 key 执行 `Decode.exe -X -P 20220204 .\encode.mp3` 可提取出如下信息。

```plain text
\xe2\x9c\x8c\xef\xb8\x8e \xe2\x98\x9d\xef\xb8\x8e\xe2\x99\x93\xef\xb8\x8e\xe2\xa7\xab\xef\xb8\x8e\xe2\x98\x9f\xef\xb8\x8e\xe2\x97\x86\xef\xb8\x8e\xe2\x99\x8c\xef\xb8\x8e \xe2\x9d\x92\xef\xb8\x8e\xe2\x99\x8f\xef\xb8\x8e\xe2\x97\xbb\xef\xb8\x8e\xe2\x96\xa1\xef\xb8\x8e\xe2\xac\xa7\xef\xb8\x8e\xe2\x99\x93\xef\xb8\x8e\xe2\xa7\xab\xef\xb8\x8e\xe2\x96\xa1\xef\xb8\x8e\xe2\x9d\x92\xef\xb8\x8e\xe2\x8d\x93\xef\xb8\x8e \xe2\x96\xa0\xef\xb8\x8e\xe2\x99\x8b\xef\xb8\x8e\xe2\x9d\x8d\xef\xb8\x8e\xe2\x99\x8f\xef\xb8\x8e\xe2\x99\x8e\xef\xb8\x8e \xf0\x9f\x93\x82\xef\xb8\x8e\xe2\x99\x8d\xef\xb8\x8e\xe2\x99\x8f\xef\xb8\x8e\xf0\x9f\x8f\xb1\xef\xb8\x8e\xe2\x99\x8f\xef\xb8\x8e\xe2\x99\x8b\xef\xb8\x8e\xf0\x9f\x99\xb5 \xe2\x99\x93\xef\xb8\x8e\xe2\xac\xa7\xef\xb8\x8e \xe2\x9d\x96\xef\xb8\x8e\xe2\x99\x8f\xef\xb8\x8e\xe2\x9d\x92\xef\xb8\x8e\xe2\x8d\x93\xef\xb8\x8e \xe2\x99\x93\xef\xb8\x8e\xe2\x96\xa0\xef\xb8\x8e\xe2\xa7\xab\xef\xb8\x8e\xe2\x99\x8f\xef\xb8\x8e\xe2\x9d\x92\xef\xb8\x8e\xe2\x99\x8f\xef\xb8\x8e\xe2\xac\xa7\xef\xb8\x8e\xe2\xa7\xab\xef\xb8\x8e\xe2\x99\x93\xef\xb8\x8e\xe2\x96\xa0\xef\xb8\x8e\xe2\x99\x91\xef\xb8\x8e\xf0\x9f\x93\xac\xef\xb8\x8e \xf0\x9f\x95\x88\xef\xb8\x8e\xe2\x99\x92\xef\xb8\x8e\xe2\x8d\x93\xef\xb8\x8e \xe2\x96\xa0\xef\xb8\x8e\xe2\x96\xa1\xef\xb8\x8e\xe2\xa7\xab\xef\xb8\x8e \xe2\xa7\xab\xef\xb8\x8e\xe2\x99\x8b\xef\xb8\x8e\xf0\x9f\x99\xb5\xe2\x99\x8f\xef\xb8\x8e \xe2\x99\x8b\xef\xb8\x8e \xe2\x97\x8f\xef\xb8\x8e\xe2\x96\xa1\xef\xb8\x8e\xe2\x96\xa1\xef\xb8\x8e\xf0\x9f\x99\xb5 \xe2\x99\x8b\xef\xb8\x8e\xe2\xa7\xab\xef\xb8\x8e \xe2\x99\x93\xef\xb8\x8e\xe2\xa7\xab\xef\xb8\x8e\xe2\x9c\x8d\xef\xb8\x8e
```

使用 CyberChef From Hex 解码后可得如下内容。

```plain text
✌︎☝︎♓︎⧫︎☟︎◆︎♌︎❒︎♏︎◻︎□︎⬧︎♓︎⧫︎□︎❒︎⍓︎■︎♋︎❍︎♏︎♎︎📂︎♍︎♏︎🏱︎♏︎♋︎🙵♓︎⬧︎❖︎♏︎❒︎⍓︎♓︎■︎⧫︎♏︎❒︎♏︎⬧︎⧫︎♓︎■︎♑︎📬︎🕈︎♒︎⍓︎■︎□︎⧫︎⧫︎♋︎🙵♏︎♋︎●︎□︎□︎🙵♋︎⧫︎♓︎⧫︎✍︎
```

用 [Wingdings Translator](https://wingdingstranslator.com/) 将其翻译后可得如下内容。

```plain text
A︎G︎i︎t︎H︎u︎b︎r︎e︎p︎o︎s︎i︎t︎o︎r︎y︎n︎a︎m︎e︎d︎1︎c︎e︎P︎e︎a︎🙵i︎s︎v︎e︎r︎y︎i︎n︎t︎e︎r︎e︎s︎t︎i︎n︎g︎.︎W︎h︎y︎n︎o︎t︎t︎a︎🙵e︎a︎l︎o︎o︎🙵a︎t︎i︎t︎?︎
```

在 GitHub 上搜寻 1cePeak 可以找到一个 repository，在其文件中可以找到如下关键内容。

```plain text
#!/bin/sh

echo How_6ad_c0uld_a_1cePeak_be? >&2
```

使用 `How_6ad_c0uld_a_1cePeak_be?` 作为 key 解密 emoji-aes 的密文可以得到 flag。

```flag
flag{e32f619b-dbcd-49bd-9126-5d841aa01767}
```

## Summary

蓝帽杯和队友错失线下 QAQ，吊死在 Web1 的小游戏上了，下次一定吸取教训。Misc 又学到新东西了。蓝帽杯的 Web2 也在复现了，冲冲冲。

