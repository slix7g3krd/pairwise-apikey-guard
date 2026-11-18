# pairwise-apikey-guard

对外发 API Key 后，作用域和生命周期就开始失控：key 明文存库；前缀不区分环境；一个 key 能访问所有租户；scope 支持 `*`；过期时间可为空；吊销只删缓存，库里仍有效；轮换时旧 key 不失效；key 能放在 URL 里进日志；权限变更后 key 不重新鉴权；泄露检测只扫代码不扫日志。security/apikey_guard.py 是核心，tests/test_apikey_guard.py 15个红。要修的是：哈希存储；环境前缀；租户绑定；禁通配 scope；过期必填；吊销落库；轮换宽限；禁 URL 传递；每次重新鉴权；日志扫描。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：其他；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
