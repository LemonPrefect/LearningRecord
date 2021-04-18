---
# image bucket id
butterId: 4df72543-170c-4dff-a021-5bc0cff9f636
---

# Week3 Summary

## What have I done

- BUUOJ 刷题 WriteUps

## [WriteUp] How did I accomplish these things

### [GWCTF2019]huyao

附件给出了两张图，猜测是盲水印。在网上找到一段可解出的脚本。

```python
# coding=utf-8
import cv2
import numpy as np
import random
import os
from argparse import ArgumentParser
ALPHA = 5
 
 
def build_parser():
    parser = ArgumentParser()
    parser.add_argument('--original', dest='ori', required=True)
    parser.add_argument('--image', dest='img', required=True)
    parser.add_argument('--result', dest='res', required=True)
    parser.add_argument('--alpha', dest='alpha', default=ALPHA)
    return parser
 
 
def main():
    parser = build_parser()
    options = parser.parse_args()
    ori = options.ori
    img = options.img
    res = options.res
    alpha = options.alpha
    if not os.path.isfile(ori):
        parser.error("original image %s does not exist." % ori)
    if not os.path.isfile(img):
        parser.error("image %s does not exist." % img)
    decode(ori, img, res, alpha)
 
 
def decode(ori_path, img_path, res_path, alpha):
    ori = cv2.imread(ori_path)
    img = cv2.imread(img_path)
    ori_f = np.fft.fft2(ori)
    img_f = np.fft.fft2(img)
    height, width = ori.shape[0], ori.shape[1]
    watermark = (ori_f - img_f) / alpha
    watermark = np.real(watermark)
    res = np.zeros(watermark.shape)
    random.seed(height + width)
    x = range(height / 2)
    y = range(width)
    random.shuffle(x)
    random.shuffle(y)
    for i in range(height / 2):
        for j in range(width):
            res[x[i]][y[j]] = watermark[i][j]
    cv2.imwrite(res_path, res, [int(cv2.IMWRITE_JPEG_QUALITY), 100])
 
 
if __name__ == '__main__':
    main()
```

使用 `python2 bwm.py --original huyao.png --image stillhuyao.png --result result.png` 可以提取出一张水印图，因此得到了 flag。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618158119719.be262706bb8401ebe9d381f21def113d089ca311.png@270h_300w_1c)

```flag
GWHT{BWM_1s_c00l}
```

### 我爱Linux

附件给出的是一张图片。在其末尾可以得到一串二进制数据。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618491407832.94cc2c15890475c424c7921d58468849a9bab35d.png)

使用 `print(pickle.loads(open("extract.bin", "rb").read()))` 处理一下得到如下内容。

```plain text
[[(3, 'm'), (4, '"'), (5, '"'), (8, '"'), (9, '"'), (10, '#'), (31, 'm'), (32, '"'), (33, '"'), (44, 'm'), (45, 'm'), (46, 'm'), (47, 'm'), (50, 'm'), (51, 'm'), (52, 'm'), (53, 'm'), (54, 'm'), (55, 'm'), (58, 'm'), (59, 'm'), (60, 'm'), (61, 'm'), (66, 'm'), (67, '"'), (68, '"'), (75, '#')], [(1, 'm'), (2, 'm'), (3, '#'), (4, 'm'), (5, 'm'), (10, '#'), (16, 'm'), (17, 'm'), (18, 'm'), (23, 'm'), (24, 'm'), (25, 'm'), (26, 'm'), (31, '#'), (37, 'm'), (38, 'm'), (39, 'm'), (43, '"'), (47, '"'), (48, '#'), (54, '#'), (55, '"'), (57, '"'), (61, '"'), (62, '#'), (64, 'm'), (65, 'm'), (66, '#'), (67, 'm'), (68, 'm'), (72, 'm'), (73, 'm'), (74, 'm'), (75, '#')], [(3, '#'), (10, '#'), (15, '"'), (19, '#'), (22, '#'), (23, '"'), (25, '"'), (26, '#'), (29, 'm'), (30, 'm'), (31, '"'), (36, '"'), (40, '#'), (47, 'm'), (48, '"'), (53, 'm'), (54, '"'), (59, 'm'), (60, 'm'), (61, 'm'), (62, '"'), (66, '#'), (71, '#'), (72, '"'), (74, '"'), (75, '#')], [(3, '#'), (10, '#'), (15, 'm'), (16, '"'), (17, '"'), (18, '"'), (19, '#'), (22, '#'), (26, '#'), (31, '#'), (36, 'm'), (37, '"'), (38, '"'), (39, '"'), (40, '#'), (45, 'm'), (46, '"'), (52, 'm'), (53, '"'), (61, '"'), (62, '#'), (66, '#'), (71, '#'), (75, '#')], [(3, '#'), (10, '"'), (11, 'm'), (12, 'm'), (15, '"'), (16, 'm'), (17, 'm'), (18, '"'), (19, '#'), (22, '"'), (23, '#'), (24, 'm'), (25, '"'), (26, '#'), (31, '#'), (36, '"'), (37, 'm'), (38, 'm'), (39, '"'), (40, '#'), (43, 'm'), (44, '#'), (45, 'm'), (46, 'm'), (47, 'm'), (48, 'm'), (51, 'm'), (52, '"'), (57, '"'), (58, 'm'), (59, 'm'), (60, 'm'), (61, '#'), (62, '"'), (66, '#'), (71, '"'), (72, '#'), (73, 'm'), (74, '#'), (75, '#')], [(23, 'm'), (26, '#'), (32, '"'), (33, '"')], [(24, '"'), (25, '"')], [], [(12, '#'), (17, 'm'), (18, '"'), (19, '"'), (23, 'm'), (24, 'm'), (25, 'm'), (26, 'm'), (33, '#'), (36, 'm'), (37, 'm'), (38, 'm'), (39, 'm'), (40, 'm'), (41, 'm'), (46, 'm'), (47, 'm'), (52, 'm'), (53, 'm'), (54, 'm'), (65, 'm'), (66, 'm'), (67, 'm'), (68, 'm'), (71, 'm'), (72, 'm'), (73, 'm'), (74, 'm'), (75, 'm'), (76, 'm')], [(2, 'm'), (3, 'm'), (4, 'm'), (9, 'm'), (10, 'm'), (11, 'm'), (12, '#'), (15, 'm'), (16, 'm'), (17, '#'), (18, 'm'), (19, 'm'), (22, '"'), (26, '"'), (27, '#'), (30, 'm'), (31, 'm'), (32, 'm'), (33, '#'), (40, '#'), (41, '"'), (45, 'm'), (46, '"'), (47, '#'), (50, 'm'), (51, '"'), (55, '"'), (58, 'm'), (59, 'm'), (60, 'm'), (64, '#'), (65, '"'), (68, '"'), (69, 'm'), (75, '#'), (76, '"')], [(1, '#'), (2, '"'), (5, '#'), (8, '#'), (9, '"'), (11, '"'), (12, '#'), (17, '#'), (24, 'm'), (25, 'm'), (26, 'm'), (27, '"'), (29, '#'), (30, '"'), (32, '"'), (33, '#'), (39, 'm'), (40, '"'), (44, '#'), (45, '"'), (47, '#'), (50, '#'), (51, 'm'), (52, '"'), (53, '"'), (54, '#'), (55, 'm'), (57, '#'), (58, '"'), (61, '#'), (64, '#'), (65, 'm'), (68, 'm'), (69, '#'), (74, 'm'), (75, '"')], [(1, '#'), (2, '"'), (3, '"'), (4, '"'), (5, '"'), (8, '#'), (12, '#'), (17, '#'), (26, '"'), (27, '#'), (29, '#'), (33, '#'), (38, 'm'), (39, '"'), (43, '#'), (44, 'm'), (45, 'm'), (46, 'm'), (47, '#'), (48, 'm'), (50, '#'), (55, '#'), (57, '#'), (58, '"'), (59, '"'), (60, '"'), (61, '"'), (65, '"'), (66, '"'), (67, '"'), (69, '#'), (73, 'm'), (74, '"')], [(1, '"'), (2, '#'), (3, 'm'), (4, 'm'), (5, '"'), (8, '"'), (9, '#'), (10, 'm'), (11, '#'), (12, '#'), (17, '#'), (22, '"'), (23, 'm'), (24, 'm'), (25, 'm'), (26, '#'), (27, '"'), (29, '"'), (30, '#'), (31, 'm'), (32, '#'), (33, '#'), (37, 'm'), (38, '"'), (47, '#'), (51, '#'), (52, 'm'), (53, 'm'), (54, '#'), (55, '"'), (57, '"'), (58, '#'), (59, 'm'), (60, 'm'), (61, '"'), (64, '"'), (65, 'm'), (66, 'm'), (67, 'm'), (68, '"'), (72, 'm'), (73, '"')], [], [], [], [(5, '#'), (8, '#'), (16, 'm'), (17, 'm'), (18, 'm'), (19, 'm'), (23, 'm'), (24, 'm'), (25, 'm'), (26, 'm'), (30, 'm'), (31, 'm'), (32, 'm'), (33, 'm'), (38, 'm'), (39, 'm'), (40, 'm'), (50, '#'), (57, '#'), (64, '#'), (71, 'm'), (72, 'm'), (73, 'm')], [(2, 'm'), (3, 'm'), (4, 'm'), (5, '#'), (8, '#'), (9, 'm'), (10, 'm'), (11, 'm'), (15, '#'), (16, '"'), (19, '"'), (20, 'm'), (22, 'm'), (23, '"'), (26, '"'), (27, 'm'), (29, '#'), (34, '#'), (36, 'm'), (37, '"'), (41, '"'), (44, 'm'), (45, 'm'), (46, 'm'), (50, '#'), (51, 'm'), (52, 'm'), (53, 'm'), (57, '#'), (58, 'm'), (59, 'm'), (60, 'm'), (64, '#'), (65, 'm'), (66, 'm'), (67, 'm'), (73, '#')], [(1, '#'), (2, '"'), (4, '"'), (5, '#'), (8, '#'), (9, '"'), (11, '"'), (12, '#'), (15, '#'), (16, 'm'), (19, 'm'), (20, '#'), (22, '#'), (25, 'm'), (27, '#'), (29, '"'), (30, 'm'), (31, 'm'), (32, 'm'), (33, 'm'), (34, '"'), (36, '#'), (37, 'm'), (38, '"'), (39, '"'), (40, '#'), (41, 'm'), (43, '#'), (44, '"'), (47, '#'), (50, '#'), (51, '"'), (53, '"'), (54, '#'), (57, '#'), (58, '"'), (60, '"'), (61, '#'), (64, '#'), (65, '"'), (67, '"'), (68, '#'), (73, '#')], [(1, '#'), (5, '#'), (8, '#'), (12, '#'), (16, '"'), (17, '"'), (18, '"'), (20, '#'), (22, '#'), (27, '#'), (29, '#'), (33, '"'), (34, '#'), (36, '#'), (41, '#'), (43, '#'), (44, '"'), (45, '"'), (46, '"'), (47, '"'), (50, '#'), (54, '#'), (57, '#'), (61, '#'), (64, '#'), (68, '#'), (73, '#')], [(1, '"'), (2, '#'), (3, 'm'), (4, '#'), (5, '#'), (8, '#'), (9, '#'), (10, 'm'), (11, '#'), (12, '"'), (15, '"'), (16, 'm'), (17, 'm'), (18, 'm'), (19, '"'), (23, '#'), (24, 'm'), (25, 'm'), (26, '#'), (29, '"'), (30, '#'), (31, 'm'), (32, 'm'), (33, 'm'), (34, '"'), (37, '#'), (38, 'm'), (39, 'm'), (40, '#'), (41, '"'), (43, '"'), (44, '#'), (45, 'm'), (46, 'm'), (47, '"'), (50, '#'), (51, '#'), (52, 'm'), (53, '#'), (54, '"'), (57, '#'), (58, '#'), (59, 'm'), (60, '#'), (61, '"'), (64, '#'), (65, '#'), (66, 'm'), (67, '#'), (68, '"'), (71, 'm'), (72, 'm'), (73, '#'), (74, 'm'), (75, 'm')], [], [], [], [(2, 'm'), (3, 'm'), (4, 'm'), (5, 'm'), (8, 'm'), (9, 'm'), (10, 'm'), (11, 'm'), (12, 'm'), (19, '#'), (24, 'm'), (25, 'm'), (26, 'm'), (29, '"'), (30, '"'), (31, 'm')], [(1, '#'), (2, '"'), (5, '"'), (6, 'm'), (8, '#'), (16, 'm'), (17, 'm'), (18, 'm'), (19, '#'), (22, 'm'), (23, '"'), (27, '"'), (31, '#')], [(1, '#'), (2, 'm'), (5, 'm'), (6, '#'), (8, '"'), (9, '"'), (10, '"'), (11, '"'), (12, 'm'), (13, 'm'), (15, '#'), (16, '"'), (18, '"'), (19, '#'), (22, '#'), (23, 'm'), (24, '"'), (25, '"'), (26, '#'), (27, 'm'), (31, '"'), (32, 'm'), (33, 'm')], [(2, '"'), (3, '"'), (4, '"'), (6, '#'), (13, '#'), (15, '#'), (19, '#'), (22, '#'), (27, '#'), (31, '#')], [(1, '"'), (2, 'm'), (3, 'm'), (4, 'm'), (5, '"'), (8, '"'), (9, 'm'), (10, 'm'), (11, 'm'), (12, '#'), (13, '"'), (15, '"'), (16, '#'), (17, 'm'), (18, '#'), (19, '#'), (23, '#'), (24, 'm'), (25, 'm'), (26, '#'), (27, '"'), (31, '#')], [(29, '"'), (30, '"')]]
```

发现其好像是坐标对应得关系，于是写个脚本将其对应出来。

```python
import pickle

contents = list(pickle.loads(open("extract.bin", "rb").read()))
for content in contents:
    line = list(
        "                                                                             ")
    for (x, y) in content:
        line[x] = y
    print(str(line).replace("\'", "").replace(", ", "").replace("[", "").replace("]", ""))
```

可以得到如下内容。

```plain text
   m""  ""#                    m""          mmmm  mmmmmm  mmmm    m""      # 
 mm#mm    #     mmm    mmmm    #     mmm   "   "#     #" "   "# mm#mm   mmm# 
   #      #    "   #  #" "#  mm"    "   #      m"    m"    mmm"   #    #" "# 
   #      #    m"""#  #   #    #    m"""#    m"     m"       "#   #    #   # 
   #      "mm  "mm"#  "#m"#    #    "mm"#  m#mmmm  m"    "mmm#"   #    "#m## 
                       m  #     ""                                           
                        ""                                                   
                                                                             
            #    m""   mmmm      #  mmmmmm    mm    mmm          mmmm  mmmmmm
  mmm    mmm#  mm#mm  "   "#  mmm#      #"   m"#  m"   "  mmm   #"  "m     #"
 #"  #  #" "#    #      mmm" #" "#     m"   #" #  #m""#m #"  #  #m  m#    m" 
 #""""  #   #    #        "# #   #    m"   #mmm#m #    # #""""   """ #   m"  
 "#mm"  "#m##    #    "mmm#" "#m##   m"        #   #mm#" "#mm"  "mmm"   m"   
                                                                             
                                                                             
                                                                             
     #  #       mmmm   mmmm   mmmm    mmm         #      #      #      mmm   
  mmm#  #mmm   #"  "m m"  "m #    # m"   "  mmm   #mmm   #mmm   #mmm     #   
 #" "#  #" "#  #m  m# #  m # "mmmm" #m""#m #"  #  #" "#  #" "#  #" "#    #   
 #   #  #   #   """ # #    # #   "# #    # #""""  #   #  #   #  #   #    #   
 "#m##  ##m#"  "mmm"   #mm#  "#mmm"  #mm#" "#mm"  ##m#"  ##m#"  ##m#"  mm#mm 
                                                                             
                                                                             
                                                                             
  mmmm  mmmmm      #    mmm  ""m                                             
 #"  "m #       mmm#  m"   "   #                                             
 #m  m# """"mm #" "#  #m""#m   "mm                                           
  """ #      # #   #  #    #   #                                             
 "mmm"  "mmm#" "#m##   #mm#"   #                                             
                             ""                                              
```

```flag
flag{a273fdedf3d746e97db9086ebbb195d6}
```

### [XMAN2018排位赛]file

附件给出的是一个镜像，使用 DiskInternals Linux Reader 挂载打开可以发现一个 lost+found 文件夹，说明存在可能可恢复的文件数据碎片。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618503187703.8fd9dca120e1ab04cc09bcbcddf3d10a1a2216eb.png)

使用 `extundelete attachment.img --restore-all` 尝试恢复即可得到一个 Vim 的 swp 文件。将其恢复后整理可得 flag。

```flag
flag{fugly_cats_need_luv_2}
```

### [HDCTF2019]信号分析

> 使用HackCube-Special分析固定码信号：https://www.freebuf.com/articles/wireless/191534.html

将附件使用 Audition 打开可以看到如下重复波形。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618507217657.744aad767e7ff22b3c3e9f1816def3130c733761.png)

根据参考文章的如下图片可以尝试解码。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618507302968.d7b7cff9ac0bef89dd43ddbf37ecd407008cbb45.png)

根据图片规律可解码得到 `FFFFFFFF0001`。

```flag
flag{FFFFFFFF0001}
```

### [De1CTF2019]Mine Sweeping

解压附件可得到一个游戏，使用 dnSpy 查看 `Assembly-CSharp.dll` 可以找到 `OnMouseUpAsButton()` 方法，其中存在着判断每次点击是否“踩雷”的操作。要完成游戏只需要点开所有方块即可，因此只需要把“踩雷”去掉。将原有的代码修改如下。

```c#
// Elements
// Token: 0x0600000A RID: 10
private void OnMouseUpAsButton()
{
	if (!Grids._instance.bGameEnd && !this.bIsOpen)
	{
		this.bIsOpen = true;
		int num = (int)base.transform.position.x;
		int num2 = (int)base.transform.position.y;
		int adjcent = Grids._instance.CountAdjcentNum(num, num2);
		this.SafeAndThunder(adjcent);
		Grids._instance.Flush(num, num2, new bool[29, 29]);
		if (Grids._instance.GameWin())
		{
			Grids._instance.bGameEnd = true;
			MonoBehaviour.print("game over: win");
		}
	}
}
```

编译后保存，再次打开游戏并点开所有方块即可得到如下二维码。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618558212529.5018a4be2b010ac4b82809c47f6282cac0ca1427.png@300w)

扫描二维码可得到 `http://qr02.cn/FeJ7dU`，访问即可获得 flag。

```flag
de1ctf{G3t_F1@g_AFt3R_Sw3ep1ng_M1n3s}
```

### \[INSHack2018\]\(not\) so deep

使用 Audition 打开附件可以发现半个 flag。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618559097680.2d01f9162a4b68c8a2610f15937f58561a786778.png)

根据其中含有的 st3G4n 推测是隐写，同时题目中有 deep，考虑是 DeepSound。但是没有给出 key，因此尝试使用 john 自带的 deepsound2john.py 来得到 hash 值从而爆破 key。

```bash
> python .\run\deepsound2john.py .\final_flag.wav
final_flag.wav:$dynamic_1529$b8f858d9deb0b805797cef03299e3bdd8990f48a
```

使用 john 爆破可以得到如下结果。

```plain text
azerty           (final_flag.wav)
```

因此得到了 key 为 azerty。使用 DeepSound 配合 key 解密可得一个文件。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618559638907.05db2068ee3850ca47334f5f4a409f243230c0e7.png)

提取出 flag2.txt 可得后一半 flag `0_1s_4lwayS_Th3_S4me}`。

```flag
INSA{Aud1o_st3G4n0_1s_4lwayS_Th3_S4me}
```

### [BSidesSF2019]diskimage

附件是一张图片，上半部分显示不正常，考虑有隐写。

![image-20210416155900562](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618559941227.a75a5eb87399e52e8c3978f4f2f106075975fd39.png@50q)

在 zsteg 的报告下有如下信息。

```plain text
b8,rgb,lsb,xy       .. file: DOS/MBR boot sector, code offset 0x3c+2, OEM-ID "~mitsumi", root entries 224, sectors 2880 (volumes <=32 MB) , sectors/FAT 9, sectors/track 18, serial number 0x7e572f0f, unlabeled, FAT (12 bit)
```

将文件提取出来 `zsteg -e 'b8,rgb,lsb,xy' attachment.png  > extracted.dat `，可以得到一个软盘数据文件。使用 testdisk 指令尝试恢复被删除的文件。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618561398231.18575ce83e848c1b7f9555d8882a50979c8bff60.png)

![image-20210416162348906](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618561429297.6f97bc81c2552c5f67ac73114024f88ba8541841.png)

在此界面时按 c 将文件拷贝到软盘数据文件的目录下。恢复得到的 `_LAG.ICO` 如下。

![image-20210416162644470](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618561604774.22466738c5a2cbadcf93c182b6916bb57451238d.png)

```flag
CTF{FAT12_FTW}
```

### [BSidesSF2020]barcoder

画图一把梭修复条形码，得到如下图片。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618563141840.633accf5b07c432c1b938968757349cb312f2140.png@200w)

使用 bcTester 扫描条形码可得 flag。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618563187108.fe4e0d8dcf8c4216a25ef18c259c1aef9acdb7cb.png)

```flag
CTF{way_too_common}
```

### [CFI-CTF 2018]Kadyrov's Cat

>A man from the soviet union has sent you two strange documents. Find the identity of the man as well as his location.
>
>Flag format is : `CFI{Firstname_Lastname_of_City}`

附件中的图片有经纬度。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618563867205.622fdd3c8f0530f330d67eef1163981be78ff1aa.png)

稍微计算一下可以得到如下结果。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618564139558.fd5e6700771dfd06a65308543ef08549dd8d8951.png)

使用地图可以得到地址 `Uzvaras bulvāris, Centra rajons, Rīga, LV-1050, Latvia`，因此城市是 Riga。

使用 Acrobat DC 打开附件给出的 PDF 文件可得如下内容。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618564527199.91a853ea64b19d1d38516c8e0e80abd85ada7ff4.png)

```flag
CFI{Kotik_Kadyrov_of_Riga}
```

### Weird_List

附件给出的是一堆数据，推测其构成了一幅图片。因此写个脚本将数据画出来。

```python
import PIL

pixels = [[120], [120], [24, 1, 87, 1, 7], [7, 1, 15, 1, 21, 1, 16, 1, 49, 1, 7], [2, 1, 1, 1, 2, 1, 15, 1, 4, 1, 3, 1, 1, 1, 10, 1, 16, 1, 4, 1, 1, 1, 2, 1, 1, 1, 19, 1, 7, 1, 1, 1, 2, 1, 1, 1, 3, 1, 6], [2, 1, 1, 1, 3, 1, 14, 1, 3, 1, 1, 1, 2, 1, 1, 1, 10, 1, 16, 1, 4, 1, 1, 1, 2, 1, 1, 1, 18, 1, 8, 1, 1, 1, 2, 1, 1, 1, 4, 1, 5], [2, 1, 1, 1, 3, 1, 14, 1, 3, 1, 1, 1, 2, 1, 1, 1, 10, 1, 16, 1, 4, 1, 1, 1, 2, 1, 1, 1, 17, 1, 1, 1, 7, 1, 1, 1, 2, 1, 1, 1, 4, 1, 5], [2, 1, 5, 1, 14, 1, 3, 1, 1, 1, 4, 1, 10, 1, 16, 1, 7, 1, 4, 1, 16, 1, 1, 1, 7, 1, 2, 1, 4, 1, 3, 1, 5], [2, 1, 5, 1, 14, 1, 3, 1, 2, 1, 4, 1, 9, 1, 16, 1, 7, 1, 4, 1, 16, 1, 1, 1, 10, 1, 4, 1, 3, 1, 5], [2, 1, 5, 1, 3, 1, 1, 1, 2, 1, 5, 1, 3, 1, 2, 1, 4, 1, 1, 1, 5, 1, 1, 1, 2, 1, 9, 1, 3, 1, 2, 1, 4, 1, 4, 1, 1, 1, 1, 1, 7, 1, 1, 1, 4, 1, 3, 1, 6, 1, 4, 1, 3, 1, 5], [2, 1, 5, 1, 3, 1, 1, 1, 2, 1, 1, 1, 3, 1, 3, 1, 2, 1, 3, 1, 2, 1, 4, 1, 1, 1, 2, 1, 1, 1, 7, 1, 1, 1, 2, 1, 1, 1, 5, 1, 4, 1, 1, 1, 1, 1, 7, 1, 1, 1, 4, 1, 3, 1, 1, 1, 4, 1, 4, 1, 3, 1, 5], [2, 1, 5, 1, 3, 1, 1, 1, 2, 1, 1, 1, 3, 1, 3, 1, 2, 1, 3, 1, 2, 1, 4, 1, 1, 1, 2, 1, 9, 1, 4, 1, 1, 1, 5, 1, 3, 1, 2, 1, 2, 1, 6, 1, 2, 1, 3, 1, 2, 1, 2, 1, 4, 1, 4, 1, 3, 1, 5], [2, 1, 1, 1, 3, 1, 5, 1, 2, 1, 1, 1, 3, 1, 3, 1, 2, 1, 2, 1, 8, 1, 1, 1, 2, 1, 9, 1, 4, 1, 1, 1, 4, 1, 3, 1, 6, 1, 6, 1, 2, 1, 3, 1, 2, 1, 2, 1, 4, 1, 2, 1, 5, 1, 5], [2, 1, 1, 1, 3, 1, 6, 1, 1, 1, 1, 1, 2, 1, 4, 1, 1, 1, 3, 1, 3, 1, 4, 1, 1, 1, 2, 1, 9, 1, 4, 1, 1, 1, 4, 1, 3, 1, 6, 1, 6, 1, 2, 1, 3, 1, 2, 1, 2, 1, 3, 1, 3, 1, 5, 1, 5], [2, 1, 5, 1, 6, 1, 1, 1, 4, 1, 4, 1, 1, 1, 3, 1, 3, 1, 4, 1, 2, 1, 1, 1, 9, 1, 4, 1, 6, 1, 3, 1, 6, 1, 6, 1, 2, 1, 3, 1, 2, 1, 2, 1, 3, 1, 3, 1, 1, 1, 4, 1, 4], [2, 1, 5, 1, 3, 1, 1, 1, 2, 1, 4, 1, 4, 1, 1, 1, 4, 1, 2, 1, 4, 1, 2, 1, 1, 1, 9, 1, 4, 1, 6, 1, 4, 1, 3, 1, 1, 1, 6, 1, 2, 1, 3, 1, 2, 1, 2, 1, 3, 1, 5, 1, 3, 1, 5], [2, 1, 5, 1, 3, 1, 1, 1, 2, 1, 5, 1, 3, 1, 1, 1, 5, 1, 2, 1, 3, 1, 2, 1, 2, 1, 9, 1, 3, 1, 1, 1, 3, 1, 6, 1, 1, 1, 1, 1, 7, 1, 2, 1, 3, 1, 2, 1, 2, 1, 3, 1, 5, 1, 3, 1, 5], [2, 1, 5, 1, 3, 1, 2, 1, 1, 1, 5, 1, 4, 1, 1, 1, 4, 1, 1, 1, 4, 1, 2, 1, 2, 1, 9, 1, 3, 1, 1, 1, 3, 1, 6, 1, 1, 1, 2, 1, 6, 1, 2, 1, 3, 1, 2, 1, 2, 1, 2, 1, 6, 1, 3, 1, 5], [2, 1, 5, 1, 3, 1, 2, 1, 1, 1, 5, 1, 6, 1, 4, 1, 6, 1, 2, 1, 3, 1, 9, 1, 2, 1, 1, 1, 3, 1, 6, 1, 1, 1, 2, 1, 6, 1, 2, 1, 3, 1, 2, 1, 2, 1, 2, 1, 6, 1, 3, 1, 5], [2, 1, 5, 1, 3, 1, 1, 1, 2, 1, 1, 1, 3, 1, 6, 1, 4, 1, 1, 1, 4, 1, 2, 1, 4, 1, 9, 1, 1, 1, 1, 1, 3, 1, 6, 1, 1, 1, 2, 1, 6, 1, 2, 1, 3, 1, 2, 1, 2, 1, 2, 1, 6, 1, 3, 1, 5], [2, 1, 5, 1, 3, 1, 1, 1, 2, 1, 1, 1, 3, 1, 5, 1, 5, 1, 6, 1, 1, 1, 5, 1, 9, 1, 1, 1, 1, 1, 2, 1, 7, 1, 1, 1, 2, 1, 6, 1, 2, 1, 3, 1, 2, 1, 2, 1, 1, 1, 7, 1, 3, 1, 5], [2, 1, 5, 1, 3, 1, 1, 1, 2, 1, 1, 1, 3, 1, 5, 1, 4, 1, 2, 1, 1, 1, 2, 1, 1, 1, 17, 1, 2, 1, 1, 1, 6, 1, 2, 1, 1, 1, 7, 1, 2, 1, 3, 1, 2, 1, 2, 1, 1, 1, 4, 1, 2, 1, 3, 1, 5], [2, 1, 5, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 3, 1, 3, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 7, 1, 1, 1, 2, 1, 2, 1, 1, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 7, 1, 1, 1, 3, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 4, 1, 5], [2, 1, 6, 1, 2, 1, 2, 1, 1, 1, 5, 1, 3, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 7, 1, 1, 1, 2, 1, 2, 1, 1, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 7, 1, 1, 1, 3, 1, 1, 1, 2, 1, 3, 1, 1, 1, 2, 1, 1, 1, 4, 1, 5], [12, 1, 5, 1, 4, 1, 4, 1, 3, 1, 10, 1, 4, 1, 9, 1, 14, 1, 4, 1, 8, 1, 1, 1, 8, 1, 9, 1, 4, 1, 6], [19, 1, 4, 1, 62, 1, 24, 1, 7], [19, 1, 4, 1, 62, 1, 24, 1, 7], [17, 1, 1, 1, 31, 1, 1, 1, 1, 1, 25, 1, 1, 1, 1, 1, 1, 1, 32], [17, 1, 1, 1, 31, 1, 1, 1, 1, 1, 25, 1, 1, 1, 1, 1, 1, 1, 32], [17, 1, 1, 1, 67, 1, 32], [120], [21, 1, 1, 1, 1, 1, 86, 1, 1, 1, 1, 1, 3], [120], [120]]
img = PIL.Image.new("RGB", (120, 35), "white")

column, row = 0, 0

for pixelLine in pixels:
    for pixel in pixelLine:
        if pixel > 1:
            column += pixel
        else:
            img.putpixel((int(column), int(row)), (16, 63, 145))
            column += 1
    row += 1
    column = 0

img.save("result.png")
```

运行脚本可以得到如下图片。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618575459372.a2b83c35d6d56a65ce6295a7f805dac141f8fe08.png)

```flag
Flag{93ids_sk23a_p1o23}
```

### [NPUCTF2020]回收站

AccessData FTK Imager 挂载附件给出的磁盘，在 `X:\Windows\Web\Wallpaper\Windows` 下可以找到 flag。除此之外，回收站内也有部分 flag 但是并不完整。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618662295762.4d0b2761731eb998e3b34261333b8d9ac08be468.png)

```flag
flag{e10adc3949ba59abbe56e057f20f883e}
```

### [INSHack2018]42.tar.xz

套娃解压压缩包即可得到 flag。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1618671289024.b2b2d57eda92a084a56ba7b0e71d0bf1eb2c4e68.png)

也可以脚本一把梭。

```sh
while [ "`find . -type f -name '*.tar.xz' | wc -l`" -gt 0 ]; 
do find -type f -name "*.tar.xz" -exec tar xf '{}' \; -exec rm -- '{}' \;; 
done;
```

```flag
INSA{04ebb0d6a87f9771f2eea4dce5b91a85e7623c13301a8007914085a91b3ca6d9}
```

## Summary

BUUOJ Misc 一分题冲完了，MRCTF 复现了一部分，下周继续冲。

