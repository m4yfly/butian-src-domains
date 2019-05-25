# butian-src-domains
![](https://img.shields.io/badge/python-3-blue.svg) ![](https://img.shields.io/badge/license-GPL--3.0-orange.svg)

补天公益src域名IP地址集合

>获取补天公益src域名的小工具，子域名爆破部分主要基于[ESD](https://github.com/FeeiCN/ESD)

## 环境

python3，安装所需依赖`pip install -r requirements.txt`

## 用法

`files/out`目录下为更新源码时最新的域名与ip地址信息，可按需使用

若需要从补天src更新最新的厂商域名地址，可修改`config.py`中如下配置为自己账号的cookie

```python
BUTIAN_SRC_COOKIES = {
        "PHPSESSID":"your_phpsessid",
        "__DC_gid":"your_gid"
}
```

```shell
usage: src-domains.py [-h] [-uD] [-uDA] [-uSD] [-uA]

optional arguments:
  -h, --help            show this help message and exit
  -uD, --update-domains
                        update domains
  -uDA, --update-all-domains
                        update all domains
  -uSD, --update-subdomains
                        update subdomains
  -uA, --update-all     update all
```

设置完cookie后执行`python src-domains.py -uA` 即可开始更新过程

## Thx

* https://github.com/FeeiCN/ESD