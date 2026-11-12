# 第三方依赖声明（直接依赖）

本表列出 SDK `nacl-next-sdk/Cargo.toml` 的直接依赖及其声明许可；传递依赖与许可原文见 `third-party/`。

| crate | 许可 |
| --- | --- |
| serde、serde_json、uuid、tempfile、sha1、sha2、md5、reqwest、url、base64 | Apache-2.0 OR MIT |
| walkdir | Unlicense OR MIT |
| zip、ts-rs | MIT |
| windows-sys | Apache-2.0 OR MIT |

具体解析版本见 `Cargo.lock`。项目 MIT 许可不授予 Minecraft 内容、第三方资产或商标权利。

发行归档检查：`ts-rs 11.1.0` 和 `ts-rs-macros 11.1.0` 的归档未含单独 LICENSE/NOTICE/AUTHORS/COPYING/COPYRIGHT 文件；随包上游标签 LICENSE 是另一个来源。`r-efi 6.0.0` 的归档 `AUTHORS` 包含 MIT 条款及版权声明，原文保留；其他备选许可文本状态见 `third-party/README.md`。归档及锁文件哈希逐项见 `third-party/index.json`。
