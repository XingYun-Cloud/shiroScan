# shiroScan" 

## 思路
使用`ysoserial`生成8种`payload`，每种`payload`起一个线程
共有90多个`key`，逐个爆破
使用`ping` `dnslog`来进行漏洞确认，`dnslog`收到一个请求后，终止程序，并打印利用成功的`payload`和`key`

---
## 缺点
目前只支持带`ping`命令的被检测机器，没有`ping`命令无法得到`dnslog`
代码脏差乱

---
有大佬发现`bug`或改进意见可以联系我修改：`3933074`(QQ/WeChat)

---
请勿用作非法用途，作者不承担法律责任
