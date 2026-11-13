# 金银湖安全中心

包名 `com.jinyinhu.securitycenter`。施工以 [docs/安全中心代码架构.md](docs/安全中心代码架构.md) 为准。产品背景在发行版仓库 `JYH-OHSD/docs/管家级安全中心架构.md`，两份不一致时照施工规格。

现有 `probe/`、`report/`、`LiveStore` 保留。不改 P1 / P2 / P3 的 verdict。新功能按 GitHub issue 编号做，前一个 issue 的测试没过，不开始下一个。第 18 节列出的内容，任何 issue 都不要做。

界面文案只用施工规格里的句子。圆环只有「尚未体检」「有风险」「未完成」「暂无风险」。做不到的能力显示「暂不支持」，不补假数据。

## 构建

需要 OpenHarmony SDK 26、hvigor 6.26.8、JDK 17。

```bash
hvigor --mode module -p module=entry@default -p product=default -p buildMode=debug assembleHap --no-daemon
```

签名 ACL 在发行版文件 `JYH-OHSD/jyh-dist/signing/profiles/com.jinyinhu.securitycenter.profile.json`。私钥不放进本仓库。

## 已有探针

本目录从发行版 `apps/securitycenter` 迁入，版本 `1.0.5`。已有能力是 P1 安装完整性、P2 应用隔离、P3 安全控件。体检、应用信誉、清理和权限管理按 milestone 往上加，不在这一次初始提交里实现。
