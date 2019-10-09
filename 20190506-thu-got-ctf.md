# 权利的游戏 CTF Writeup by dram

（这个 CTF 有很多提示，为了相关信息更紧凑，所有提示信息不在发现处列出，而是在用到的时候再列出并指明来源。）

## Vale (misc)

网址是 <http://149.129.112.134>，打开一看有个小图片，还有左上角的小喇叭，点一下可以放 BGM。

看下好像 JavaScript 文件和 CSS 文件除了实现页面功能以外里面有一些奇怪的 quote。

下载 BGM <http://149.129.112.134/music/game_of_thrones.wav>，用 `strings` 看一下发现最后有一行：

```plain
hint:base64
```

但是之前并没有什么 Base64 的东西。

看到学长发的 CTF 的 `截图(朋友圈(宣传文字, 截图(HTML 源码)))` 想起哦对忘了看 HTML 了。

HTML 注释里面有一些提示这样的东西，而且如果我没看错的话好像还更新了。

> `/index.php`
>
> "Everything can be TAGGED in this world, even the magic or the music" - Bronn of the Blackwater

上面 `<audio>` 标签引用了两个音频文件，还有一个 <http://149.129.112.134/music/game_of_thrones.wav>，用 `strings` 发现我们想要的 Base64，解码后是个 PNG，里面图片写着第一个 flag：

```plain
flag{music_is_moving}
```

## Nmap

> `/index.php`
>
> The game is running in docker, only 8 ports are exposed. Not hacking other ports is a good suggestion

我好像说过这个页面有更新？

> `/index.php`
>
> 本次游戏运行在docker总共有9个端口被exposed出来

`nmap` 一下找到 4 个端口：

- `21` FTP
- `22` SSH
- `80` HTTP
- `8081` ???

UDP 端口没有扫出任何

打开 8081 端口可以看到一个 Not found 页面，看下 Header 好像是一个 Python 2 的 web app。

还在用 Python 2……

## 80 端口的隐藏文件

**直接在你最喜欢的搜索引擎里搜索** 'Game of Thrones CTF'（听说这叫社工）可以得到如下隐藏内容，里面分别有各种各样的提示：

（或者可以跑一遍 `dirb` 出来，也是同样的结果。）

- `/robots.txt`

    ```
    User-agent: Three-eyed-raven
    Allow: /the-tree/
    User-agent: *
    Disallow: /secret-island/
    Disallow: /direct-access-to-kings-landing/
    ```

- `/sitemap.xml`

    - `/index.php` 已经看过了
    - `/raven.php`

- `/h/i/d/d/e/n/index.php`

    这里提示最多，超级爽

`curl -H 'User-Agent: Three-eyed-raven'` 可以访问到 `/the-tree/`，别的好像没什么特别的。

## Reach (ftp)

> `/the-tree/`
>
> "To enter in The Reach Kingdom you must identify as Mace. You still need find the password"

> `/h/i/d/d/e/n/index.php`
>
> "My little birds are everywhere. To enter in Reach you must say: 2a213c395b9ac8253dd859648f85e5dd. Now, you owe me" - Lord (The Spider) Varys

用 `Mace:2a213c395b9ac8253dd859648f85e5dd` 登录 FTP 服务即可。

想看文件列表但是发现无论是 active 还是 passive 文件列表都出不来。

> `/h/i/d/d/e/n/index.php`
>
> And what's more, some black magic has been casted to the Reach so you cannot use some commands or you'll be rejected." - Lord (The Spider) Varys

**在当时拿到这个 flag 的时候**，手动用 `nc` 连上 FTP 发现 `PASV` 的端口连不上，`PORT` 命令被搞了，写什么都说 invalid command 之类的东西。

> `/h/i/d/d/e/n/index.php`
>
> "It is still a good idea for you to try every command when you goto Reach." - Lord (The Spider) Varys

看了一圈发现有个命令 `EPRT` 命令可以替代 `PORT`，语法是

```plain
EPRT |protocol|addr|port|
```

其中 `|` 是分割符（像 `s/pattern/replacement/` 里的 `/`），`protocol` 是网络协议，`1` 是 IPv4，`2` 是 IPv6，`addr` 和 `port` 就是“正常”的地址和 TCP 端口了。比如：

```plain
EPRT |1|192.0.2.1|3355|
```

然后手动走一下 FTP 协议，用 `LIST` 命令找到两个文件 `mysecret.mp3` 和 `new_hint.txt`。`RETR` 是好的，两个文件正常可以下载下来。

> `ftp/new_hint.txt`
>
> Reach's secret is hided in `Morse.wma`

`mysecret.mp3` 是一段摩尔斯电码，随便找了一下没找到从音频自动解码的软件，于是随便开了个音频编辑软件把长短音手动敲出来解码得到：

```
flag ftpistoo0ld
```

所以 flag 应该是

```
flag{ftp_is_too_0ld}
```

**在写 writeup 的时候**发现好像 FTP 的策略变了，`PORT` 命令放开了但是 `LIST` 被搞了，只要一 `LIST` 对面就没反应了。根据 `EPRT` 的经验我们可能需要一个 `ELST` 之类的命令。找了一下没有 `ELST` 但是有 `NLST`，也能成功获取文件列表和用 `RETR` 下载文件。

## Stormlands （web）

> `ftp/new_hint.txt`
>
> Stormlands's secret is in `storm/`

刚刚看到的 `8081` 端口的 HTTP 服务，访问 `/storm/` 果然有东西。

一看感觉被糊一脸哈希……好像是个区块链的实现。打开源码感觉又被各种类型检查糊一脸，不过好像是需要想办法给一个特定地址 shop 转入 2e6 DDCoin，而总量只有 1e6。可以通过 `/storm/create_transaction` 提交 block。

Block 的格式看了半天代码也看不明白，不过主页上不是有现成的 block 列表么，直接拿一个扔上去发现报错是 `Please provide a valid Proof-of-Work`，也就是说 `append_block` 的几乎所有的检查都是通过的。现在有了一个 block 的样例就好办多了。

观察一下代码可以得知，一个 block 本身的 `hash` 和 `height`，`transactions` 里面所有项目的 `hash` 都是代码填进去的，不是交易格式的内容，所以最终得到区块的格式如下：

```json
{
    "nonce": "<nonce>",
    "prev": "<hash of previous block>",
    "transactions": [
        {
            "input": [ "<input uuid>" ],
            "signature": [ "<signature of input utxo>" ],
            "output": [
                {
                    "amount": 999999,
                    "addr": "<dest addr>",
                    "id": "<output uuid>"
                }
            ]
        }
    ]
}
```

我们直接拿来那个 `HAHA, I AM THE BANK NOW!` 块，直接把 `output` 从给两个地址转 DDCoin，改成给 shop 转 1e6 DDCoin，`id` 随便重用一个发现也是可以过检查的（也卡在 `Please provide a valid Proof-of-Work`），像这样：

```json
{
    "amount": 1000000,
    "addr": "<shop addr>",
    "id": "<output uuid>"
}
```

也就是说，这个实现没有防止区块链分叉，并且这个 `input` 和对应的 `signature` 是可以重用的。

在 `/create_transaction` 的 handler 里面检查各地址余额是这样的：

```python
balance, utxos, tail = get_balance_of_all()
```

其中 `get_balance_of_all` 检查的是当前最长的一条链上的信息，也就是说我们只要从 bank 有 1e6 DDCoin 的位置，把这个链 fork 两次，每个 fork 都是一个“把银行的 1e6 DDCoin 转给 shop”，再跟上若干个空块超过之前链的长度即可。

```plain
--- bank -- hacker -- empty (initial chain)
       |-- transfer -- empty -- empty (fork 1)
       |-- transfer -- empty -- empty -- empty (fork 2)
```

如之前所说，这里 `transfer` 的构造方式是从 `HAHA, I AM THE BANK NOW!` 的那个块里面 `input` 和 `signature` 不变，`output` 改成只有一个，`amount` 为 `1000000`，`addr` 为 shop 的地址，`id` 随便用一个现有的 `output` 的 `id` 就可以，好像没啥用。两个 `transfer` 的 `nonce` 需要不一样，要不然 `hash` 一样的块会被拒绝。

Proof of Work 的构造通过观察源码里面的各种 hash 是如何计算出来的可以得出，参考附录 `mkblk.py`。大概 10s 以内可以出一个 PoW。

最后访问 `/storm/flag` 获得 flag：

```plain
flag{yeah_stormland!}
```

## Iron islands (dns)

> `/direct-access-to-kings-landing/`
>
> `iron.7kingdom.ctf.com` is owned by Iron Islands

其实这一个提示就够了吧，不过：

> `/h/i/d/d/e/n/index.php`
>
> "I store a TXT information in a server, which records Iron Islands's secret."

直接 `dig -t TXT iron.7kingdom.ctf.com @149.129.112.134` 连不上。

> `ftp/new_hint.txt`
>
> 53 port DNS is not our game's port

刚开始以为是 DNS over HTTPS 之类的东西，后来发现既然 Nmap 都没有找到应该不是，于是还是从 UDP 考虑，用 Scapy 构造了一个 DNS 请求

```
>>> from scapy.all import *
>>> DNS(rd=1, qd=DNSQR(qname='iron.7kingdom.ctf.com', qtype='TXT'))
<DNS  rd=1 qd=<DNSQR  qname='iron.7kingdom.ctf.com' qtype=TXT |> |>
>>> bytes(_)
b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04iron\x087kingdom\x03ctf\x03com\x00\x00\x10\x00\x01'
```

然后直接 `1` 到 `65535` 端口全发一遍，然后再收回复（毕竟 UDP），最后收到一个来自 `153` 端口的回复。参见附录 `dnsscan.py`。

然后直接读响应或者一个命令出去：

```console
$ dig -t TXT -p 153 iron.7kingdom.ctf.com @149.129.112.134 +short
```

得到我们的 flag：

```plain
"flag{dns_is_so_powerful!}"
```

为什么 nmap 扫不出来我就不知道了

## 附录

### `mkblk.py`

```python
import hashlib
import sys
import json
import itertools
import time
from functools import reduce

def hash(x):
    return hashlib.sha256(hashlib.md5(x.encode()).digest()).hexdigest()

def hash_reducer(x, y):
    return hash(hash(x)+hash(y))

EMPTY_HASH = '0'*64

def hash_utxo(utxo):
    return reduce(hash_reducer, [ utxo['id'], utxo['addr'], str(utxo['amount']) ])

def hash_tx(tx):
    return reduce(hash_reducer, [
        reduce(hash_reducer, tx['input'], EMPTY_HASH),
        reduce(hash_reducer, [ hash_utxo(utxo) for utxo in tx['output'] ], EMPTY_HASH)
    ])

def hash_txs(txs):
    return reduce(hash_reducer, [ hash_tx(tx) for tx in txs ], EMPTY_HASH)

def hash_block(prev, nonce, htxs):
    return reduce(hash_reducer, [ prev, nonce, htxs ])

DIFFICULTY = int('00000' + 'f' * 59, 16)

last_time = time.time()

if __name__ == "__main__":
    with open(sys.argv[1]) as f:
        doc = json.load(f)
    htxs = hash_txs(doc['transactions'])
    for i in itertools.count():
        nonce = 'nonce' + str(i)
        h = hash_block(doc['prev'], nonce, htxs)
        if int(h, 16) <= DIFFICULTY:
            print(nonce + ' = ' + h)
            cur_time = time.time()
            print(str(cur_time - last_time) + ' s')
            last_time = cur_time
```

### `dnsscan.py`

```python
import socket
from scapy.all import *

packet = DNS(rd=1, qd=DNSQR(qname='iron.7kingdom.ctf.com', qtype='TXT'))
packet_bytes = bytes(packet)

local_addr = ('0.0.0.0', 28800)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(local_addr)

remote_ip = '149.129.112.134'

for port in [153]:
    remote_addr = (remote_ip, port)
    sock.sendto(packet_bytes, remote_addr)

while True:
    data, addr = sock.recvfrom(4096)
    print(addr, repr(DNS(data)))
```
