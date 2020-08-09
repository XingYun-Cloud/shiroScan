# shiroScan
`shiroScan.exe url`

![image](https://github.com/XingYun-Cloud/shiroScan/blob/master/shiroScan.png)

## 更新
不再依赖dnslog，不出网也可以检测key
参考：<a href="https://mp.weixin.qq.com/s?__biz=MzIzOTE1ODczMg==&mid=2247485052&idx=1&sn=b007a722e233b45982b7a57c3788d47d">一种另类的shiro检测方式</a>

---
<s>

## 思路
使用`ysoserial`生成8种`payload`，每种`payload`起一个线程

共有90多个`key`(在零组文库复制来的)，逐个爆破

使用`ping` `dnslog`来进行漏洞确认，`dnslog`收到一个请求后，终止程序，并打印利用成功的`payload`和`key`

### 准确得到利用成功`payload`和`key`的思路
在代码里面把`payload`和`key`都写入字典

字典内的键为`payload`和`key`缩写，例如：
 - `payload`的`CommonsBeanutils1`对应键为`CB1`：`{"CB1":"CommonsBeanutils1"}`
 - `key`的`kPH+bIxk5D2deZiIxcaaaA==`对应键为`k1`（类推数字即可）
 - 然后拼接为`CB1.k1.xxxxxx.dnslog.cn`
 - 在`dnslog`收到请求后把被解析的域名拿出来分割为数组
 - 取正确的`payload`和`key`，例如(取`payload`)：`payloadList[dnslogResult.split('.')[0]]`

---
## 缺点
目前只支持带`ping`命令的被检测机器（因为使用的是`ping`命令出网检测）
</s>

---
有大佬发现`bug`或改进意见可以联系我修改：`3933074`(QQ/WeChat)

---
#### 请勿用作非法用途，作者不承担法律责任

---
using 
 - jarToDll：`https://www.cnblogs.com/codeyu/archive/2012/08/14/2639084.html`
 - key：`https://wiki.0-sec.org/#/md`
 - ysoserial：`https://github.com/frohoff/ysoserial`
 - 一种另类的shiro检测方式：`https://mp.weixin.qq.com/s?__biz=MzIzOTE1ODczMg==&mid=2247485052&idx=1&sn=b007a722e233b45982b7a57c3788d47d`
