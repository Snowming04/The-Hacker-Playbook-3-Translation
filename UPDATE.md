# 文档更新

## 19/3/2019
1. 修复了 [Isssue#3 第1章 赛前准备——安装(商用 ATT&CK 矩阵 - Windows版，图片内容重复)](https://github.com/Snowming04/The-Hacker-Playbook-3-Translation/issues/3)。<br>修改了第一章的图片 1-2.PNG。该图片存在图片内容重复的问题，已经进行替换。<br>感谢 [@MyKings](https://github.com/MyKings) 的宝贵建议。

2. 第1章新增了一张图片 1-16.PNG。

3. 修复了 [Isssue#5 第1章 赛前准备——安装=>设置你的外部服务器(Digital Dcean应为Digital Ocean)](https://github.com/Snowming04/The-Hacker-Playbook-3-Translation/issues/5)。<br>感谢 [@WMJ](https://github.com/StefanoWen) 的宝贵建议。

4. 修复了 [Isssue#6 第1章“APT组织与方法持续更新列表”的链接有误](https://github.com/Snowming04/The-Hacker-Playbook-3-Translation/issues/6)。<br>感谢 [@dom2q](https://github.com/dom2q) 的宝贵建议。


## 23/5/2019
感谢 [@y159357](https://github.com/y159357) 的宝贵建议。


>以下是我在复现中遇到的一些问题（如果是我的错误，还请译者纠正）：<br>
>1.在pdf中34页knockpy的使用中，提到了使用-u参数，我在复现时发现貌似没有这个参数，所以我使用了-w参数<br>
>2.在pdf中36页git-all-secrets的使用中，提到了将结果文件从容器中提取到主机，我想那段代码并不完全，在那段代码结尾没有指明将目标文件提取到主机的哪个文件，我想应该改为 docker cp <container-id>:/data/results.txt ./results.txt
  
  
改正了第二章里面的两个问题。


## 3/7/2019
> 首先，我们需要设置一个 VPS 服务器，启用开放到公网的多个端口，用 **PTF** 配置 Metasploit，并用 Meterpreter 攻陷最初的受害者。我们也可以用 Cobalt Strike 或其他框架来实现这一点，但在本例中我们将使用 Meterpreter。

感谢 @蝶离飞 师傅的宝贵建议，已把 `PTF` 更正为 `PTH`。

>如果你幸运地获得了一个 SSH shell，那么我们可以通过该系统进行渗透。我们如何获得 SSH shell 呢？在许多情况下，一旦我们可以实现本地文件包含（LFI）或远程代码执行（RCE），我们可以尝试权限升级以读取 /etc/shadow 文件（和密码破解），或者我们可以利用一些 **Mimimikatz** 风格的方法。

感谢 @蝶离飞 师傅的宝贵建议，已把 `Mimimikatz` 更正为 `Mimikatz`。
