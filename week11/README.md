---
butterId: 4df72543-170c-4dff-a021-5bc0cff9f636
---

# Week10 Summary

## What have I done

- BUUCTF Misc 写题

## [WriteUp] How did I accomplish these things

### 洞拐洞拐洞洞拐

附件给出的是一张像素图，将其中的像素读取出来，黑色的转换为 1，白色的转换为 0。再经过一次 From Decimal 和 From Hex 可以得到一个 wav 文件。

![](https://api.lemonprefect.cn/image/hdslb/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1630411168792358/beeb714710fd3cd5fd8e17ea1a9961cf7e94a1a2.png@200w)

将 wav 的波形图画出来，可以得到如下图片。

![](https://api.lemonprefect.cn/image/hdslb/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1630412027844969/d07c38b7fc884ebb42564906356c8cd47d33ac36.png@500w)

此时可以发现节点大概分为 8 个，因此可以使用脚本对这部分进行处理，将八个节点提取出来转换为 0~7。将得到的数据再 From Octal 一次可以得到如下内容。

```plain text
MZWGCZ33G44GGNRTHE3DEMZSGQ4TQMZQMY2WCNRZGZSDCOBYHBRGMMZUMFSWIMZSGVRTQY3DGIZWIZDBO5SDKML2PJYXUMRTGMZTGYLBPU
```

使用 Base32 解码即可获得 flag，此时写一个一把梭脚本。

```python
from PIL import Image
import numpy as Numpy
from matplotlib import pyplot as Plot
import wave as Wave
import base64 as Base


TRANSARRAY_BINARY = [128, 64, 32, 16, 8, 4, 2, 1]
TRANSARRAY_HEXDECIMAL = [16, 16]

# Read image and parse the pixels
image = Image.open("./2239f085-4e8c-425b-9e8e-793c982c42f5.png")
data = ""
width, length = image.size
for y in range(length):
    for x in range(width):
        data += "0" if (image.getpixel((y, x)) == (255, 255, 255)) else "1"

# Translate the pixel data into binary data. #
binaryData = b""
for x in range(0, len(data), 16): # 16 chars as a group, perform 'From binary' --> 'From Hex' to get binary bytes.
    char = 0
    byte = ""
    for y in range(0, 8):
        char += int(data[x + y]) * TRANSARRAY_BINARY[y]
    byte += chr(char)
    char = 0
    for y in range(8, 16):
        char += int(data[x + y]) * TRANSARRAY_BINARY[y - 8]
    byte += chr(char)
    binaryData += int(byte, base=16).to_bytes(length=1, byteorder="big")
open("extract.wav", "wb").write(binaryData)

# Convert the wavefile to the array with margin 5 and 8 height, then perform 'From Octal' and Base32 decode. #
wavFile = Wave.open("./extract.wav", "rb")
channels, sampleWidth, frameRate, nFrames = wavFile.getparams()[:4]
waveData = Numpy.fromstring(wavFile.readframes(nFrames), dtype=Numpy.short)
waveData.shape = -1, 2
waveData = (waveData.T)[0]
Plot.plot(waveData)
Plot.savefig("./plot.png") # Save the plot of the wavedata.

TRANSARRAY_CURVE_OCTAL = [-24575, -16383, -8191, 0, 8191, 16383, 24575, 32767]
octalData = ""
for x in range(0, len(waveData), 5):
    octalData += str(TRANSARRAY_CURVE_OCTAL.index(waveData[x]))
data = "".join([chr(int(octalData[x : x + 3], base=8)) for x in range(0, len(octalData), 3)]) + "=" * 6
print(Base.b32decode(data.encode("UTF-8")).decode())
```

```flag
flag{78c639623249830f5a696d1888bf34aed325c8cc23ddawd51zzqz23333aa}
```

### [BSidesSF2020]magic

> Much magic, so rainbow, wow!

附件给出的图片如下。

![](https://api.lemonprefect.cn/image/hdslb/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1630419551017306/0351c4783831aa8ed77c7ff1889950822445ea1e.png@200w)

使用脚本读取图片内容可以发现其 alpha 通道的值并非一致，因此将其 alpha 通道的值统一为 255，即设定不透明。可以得出如下图片。

![](https://api.lemonprefect.cn/image/hdslb/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1630419676864913/1ee83849d0456bf911bff923abc65a170f80c1af.png@200w)

此时可以发现有一部分颜色比较统一，将其单独提取出来。将有内容的部分裁剪出来，可以得出缺少定位码的二维码，将二维码的定位码补全可得如下二维码。

![](https://api.lemonprefect.cn/image/hdslb/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1630419832715878/933ff66fde443ecc04049a6f4573713af136398f.png)

扫描二维码可得 flag。写出一把梭脚本。

```python
from PIL import Image
import zxing

image = Image.open("./unicorn.png")
width, length = image.size

for y in range(length):
    for x in range(width):
        r, g, b, a = image.getpixel((x, y))
        image.putpixel((x, y), (r, g, b, 255))
image.save("./unicorn_no_alpha.png")

# Crop the image and extract the QR Code.
image = image.crop((200, 501, 225, 526))
width, length = image.size
for y in range(length):
    for x in range(width):
        r, g, b, a = image.getpixel((x, y))
        if (r, g, b) == (28, 193, 153):
            image.putpixel((x, y), (16, 63, 145, 255))
        else:
            image.putpixel((x, y), (255, 255, 255, 255))

# Padding the missing QR Code identifications.
pixels = [
    [0, 0]
    , [0, 1], [1, 0], [1, 6], [6, 1]
    , [0, 2], [2, 0], [2, 6], [6, 2]
    , [0, 3], [3, 0], [3, 6], [6, 3]
    , [0, 4], [4, 0], [4, 6], [6, 4]
    , [0, 5], [5, 0], [5, 6], [6, 5]
    , [0, 6], [6, 0], [6, 6]
    , [2, 2], [3, 2], [4, 2]
    , [2, 3], [3, 3], [4, 3]
    , [2, 4], [3, 4], [4, 4]
]
for pixel in pixels:
    image.putpixel((pixel[0], pixel[1]), (16, 63, 145, 255))
    image.putpixel((pixel[0] + 18, pixel[1]), (16, 63, 145, 255))
    image.putpixel((pixel[0], pixel[1] + 18), (16, 63, 145, 255))
pixels = [
    [16, 16]
    , [17, 16], [17, 20], [16, 17], [20, 17]
    , [18, 16], [18, 20], [16, 18], [20, 18]
    , [19, 16], [19, 20], [16, 19], [20, 19]
    , [20, 16], [20, 20], [16, 20], [20, 20]
    , [18, 18]
]
for pixel in pixels:
    image.putpixel((pixel[0], pixel[1]), (16, 63, 145, 255))
image.save("./pic_fix_extracted_data_padded.png")

# Parse and decode the QR Code.
print(zxing.BarCodeReader().decode("./pic_fix_extracted_data_padded.png").parsed)
```

```flag
CTF{magical_unicorn_gait}
```

### [BSidesSF2020]mini-matroyshka

> A lot of the computer world is just layers of abstraction.  Layers and layers and layers and layers and layers and layers and layers and layers and ... layers and layers and ...

附件给出了一个字符串，CyberChef 一把梭即可获得 flag。

```plain text
Find_/_Replace({'option':'Regex','string':'b\'(.*)\''},'$1',true,false,true,false)
From_Base64('A-Za-z0-9+/=',true)
From_Base64('A-Za-z0-9+/=',true)
From_Base64('A-Za-z0-9+/=',true)
Gunzip()
From_Hex('None')
Gunzip()
From_Base64('A-Za-z0-9+/=',true)
Gunzip()
From_Base32('A-Z2-7=',false)
From_Hex('None')
Gunzip()
From_Base64('A-Za-z0-9+/=',true)
Gunzip()
From_Hex('None')
Gunzip()
From_Hex('None')
Find_/_Replace({'option':'Regex','string':'o'},'',true,false,true,false)
From_Octal('Comma')
From_Base64('A-Za-z0-9+/=',true)
Gunzip()
From_Base64('A-Za-z0-9+/=',true)
From_Hex('Auto')
From_Base64('A-Za-z0-9+/=',true)
URL_Decode()
From_Base85('0-9A-Za-z!#$%&()*+\\-;<=>?@^_`{|}~')
From_Decimal('Space',false)
From_Base64('A-Za-z0-9+/=',true)
Gunzip()
From_Base64('A-Za-z0-9+/=',true)
From_Morse_Code('Space','Line feed')
From_Base32('A-Z2-7=',false)
From_Base64('A-Za-z0-9+/=',true)
From_Base85('0-9A-Za-z!#$%&()*+\\-;<=>?@^_`{|}~')
Gunzip()
From_Base64('A-Za-z0-9+/=',true)
From_Hex('None')
From_Decimal('Space',false)
From_Base85('0-9A-Za-z!#$%&()*+\\-;<=>?@^_`{|}~')
From_Morse_Code('Space','Line feed')
From_Base32('A-Z2-7=',false)
```

```flag
CTF{so_easy_an_ogre_could_do_it}
```

### [GWCTF2019]fun

朴实无华的剪刀石头布小游戏，使用 IDA Pro 对给出的二进制文件进行分析。整理反编译的源码可以得到如下代码。

```c
int __cdecl main(int argc, const char **argv, const char **envp){
    unsigned int seed; // eax
    char userAnswer; // [rsp+14h] [rbp-1Ch] BYREF
    __int16 str_psrrps[3]; // [rsp+15h] [rbp-1Bh] BYREF
    int randomFactor; // [rsp+1Ch] [rbp-14h]
    int countWinRound; // [rsp+20h] [rbp-10h]
    char realAnswer; // [rsp+27h] [rbp-9h]
    int cheatFactor; // [rsp+28h] [rbp-8h]
    int countRound; // [rsp+2Ch] [rbp-4h]

    init(argc, argv, envp);
    alarm(0x20u);
    puts("Welcome go GWHT!");
    puts("Let's play rock-paper-scissors, if you can win me 32 times,you'll get the flag");
    qmemcpy(str_psrrps, "psrrps", sizeof(str_psrrps));
    countRound = 0;
    cheatFactor = 0;
    countWinRound = 0;
    seed = time(0LL);
    srand(seed);

    while (countRound <= 31){
        randomFactor = rand() % 3; // Must be 0, 1 or 2.
        printf("This time I'll take %c,what's your choice\n", str_psrrps[randomFactor + 2]);

        if (cheatFactor){
            if (cheatFactor == 1){
                realAnswer = str_psrrps[(randomFactor + 1) % 3];
            }else if(cheatFactor == 2){
                realAnswer = str_psrrps[(randomFactor + 2) % 3];
            }
        }else{
            realAnswer = str_psrrps[randomFactor];
        }

        __isoc99_scanf("%c", &userAnswer);
        getchar();
        if (realAnswer == userAnswer){
            puts("You win!");
            ++countWinRound;
            cheatFactor = (cheatFactor + 1) - 3 * ((cheatFactor + 1) / 3);
        }else{
            puts("You lose!");
            cheatFactor = 0;
        }
        ++countRound;
    }
    if (countWinRound == 32){
        puts("You get the flag:");
        system("cat /flag");
    }else{
        puts("bye bye!");
    }
    return 0;
}
```

因此只需要按照源码写出对应的交互将正确的答案提交即可。

```python
from pwn import *

process = remote("node4.buuoj.cn", 27227)
process.recvuntil(b"you'll get the flag")
countRound = 0
cheatFactor = 0
str_psrrps = "psrps"
while countRound < 32:
    choiceTold = process.recvuntil(b"choice\n").split(b",")[0].decode()[-1];
    randomFactor = "rps".index(choiceTold)
    print(f"[+] Round {countRound} Told {choiceTold}, randomFactor {randomFactor}, cheatFactor {cheatFactor}")
    if cheatFactor:
        if cheatFactor == 1:
            realAnswer = str_psrrps[(randomFactor + 1) % 3];
        elif cheatFactor == 2:
            realAnswer = str_psrrps[(randomFactor + 2) % 3];
    else:
        realAnswer = str_psrrps[randomFactor];
    process.sendline(realAnswer)
    print(f"[+] Send answer {realAnswer}")
    print(process.recvline().decode())
    cheatFactor = (cheatFactor + 1) - 3 * ((cheatFactor + 1) // 3)
    countRound += 1
print(process.recvline().decode())
print(process.recvline().decode())
```

运行脚本即可获得 flag。

```flag
flag{c2e8a834-7cee-479e-bb9c-bb58e53bab4d}
```

### [b01lers2020]image_adjustment

题目的附件给出了如下图片。

![](https://api.lemonprefect.cn/image/hdslb/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1630482008983449/eaea5d8ea0e7f1c3a794afd8ab6683466384b83a.png)

可以发现有很多红色的小竖线，写脚本将其对其即可得到 flag。

```python
from PIL import Image

image = Image.open("./attachment.png")
width, height = image.size
imageResult = Image.new("RGBA", (width, height), "white")
pixels = image.load()

for round in range(0, 2):
    print(f"[+] Round {round + 1}")
    if round == 1:
        pixels = Image.open("./result.png").load()
    for x in range(width):
        breakpoint = 0
        for y in range(round * 50, height):
            if pixels[x, y] == (255, 0, 0, 255):
                breakpoint = y
                print(f"[+] Found breakpoint {y} on column {x}")
                break
        for y in range(breakpoint, height):
            imageResult.putpixel((x, y - breakpoint), pixels[x, y])
        for y in range(0, breakpoint):
            imageResult.putpixel((x, y + (height - breakpoint)), pixels[x, y])
    imageResult.save("./result.png")
```

运行脚本可以得到如下包含 flag 的图片。

![](https://api.lemonprefect.cn/image/hdslb/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1630482747765512/332fb803d0c257ab4c0d12d167a06a15e90ef18a.png)

```flag
flag{ShuFfLiNg_Fl4gs}
```

## Summary

WMCTF 打得有点自闭 QAQ，下周准备能不能把 DASCTF 先补一下然后再看 WMCTF。
