# Nexus Copy

这是一个用于Nexus仓库迁移的Python工具，可以从一个Nexus仓库获取所有的jar包，并将它们上传到另一个Nexus仓库。

## 功能特性

- 支持从源Nexus仓库获取所有jar包列表
- 自动下载jar包到本地临时目录
- 支持上传到目标Nexus仓库
- 支持断点续传（跳过已下载的文件）
- 详细的日志记录和进度显示
- 支持仅下载或仅上传模式
- 支持SSL验证配置

## 安装依赖

```bash
pip install -r requirements.txt
```

## 使用方法

### UI界面用法

```bash
python nexus_copy.py --ui
```

### CLI基本用法

```bash
python nexus_copy.py \
  --source-url https://source-nexus.example.com \
  --target-url https://target-nexus.example.com \
  --source-repo maven-releases \
  --target-repo maven-releases \
  --source-user source-username \
  --source-pass source-password \
  --target-user target-username \
  --target-pass target-password
```

### 参数说明

- `--ui`: 以图形界面方式运行，这种方式下无需加入其他参数

- `--source-url`: 源Nexus仓库的URL
- `--target-url`: 目标Nexus仓库的URL
- `--source-repo`: 源仓库名称（如maven-releases）
- `--target-repo`: 目标仓库名称
- `--source-user`: 源仓库用户名（可选）
- `--source-pass`: 源仓库密码（可选）
- `--target-user`: 目标仓库用户名（可选）
- `--target-pass`: 目标仓库密码（可选）
- `--temp-dir`: 临时下载目录（默认：./temp_artifacts）
- `--verify-ssl`: 是否验证SSL证书（默认：False）
- `--download-only`: 仅下载不上传
- `--upload-only`: 仅上传不下载
- `--no-cleanup`: 不清理临时文件
- `--sync-mode` : full为全量同步（默认），incremental为增量同步

### 使用示例

1. **完整迁移**：
```bash
python nexus_copy.py \
  --source-url https://old-nexus.company.com \
  --target-url https://new-nexus.company.com \
  --source-repo maven-releases \
  --target-repo maven-releases \
  --source-user admin \
  --source-pass admin123 \
  --target-user admin \
  --target-pass admin123 \
  --sync-mode full
```

2. **仅下载jar包**：
```bash
python nexus_copy.py \
  --source-url https://old-nexus.company.com \
  --source-repo maven-releases \
  --source-user admin \
  --source-pass admin123 \
  --download-only
```

3. **仅上传jar包**（需要文件已存在）：
```bash
python nexus_copy.py \
  --target-url https://new-nexus.company.com \
  --target-repo maven-releases \
  --target-user admin \
  --target-pass admin123 \
  --upload-only
```

4. **增量同步**：
```bash
python nexus_copy.py \
  --source-url https://old-nexus.company.com \
  --target-url https://new-nexus.company.com \
  --source-repo maven-releases \
  --target-repo maven-releases \
  --source-user admin \
  --source-pass admin123 \
  --target-user admin \
  --target-pass admin123 \
  --sync-mode incremental
```

## 工作流程

1. **连接源仓库**：使用REST API获取所有jar包的列表
2. **下载jar包**：将jar包下载到本地临时目录
3. **连接目标仓库**：准备上传到目标仓库
4. **上传jar包**：使用Maven格式上传API将jar包上传到目标仓库
5. **清理临时文件**：删除临时下载的文件（可选）

## 注意事项

- 确保源和目标Nexus仓库的网络连接正常
- 确保有足够的磁盘空间存储临时文件
- 大量jar包迁移可能需要较长时间，建议在网络稳定的环境下运行
- 工具会自动跳过已下载的文件，支持断点续传
- 建议先用小量数据测试，确认配置正确后再进行完整迁移

## 日志

工具会在运行目录生成 `nexus_copy.log` 文件，记录详细的迁移过程。

## 故障排除

1. **连接超时**：检查网络连接和URL是否正确
2. **认证失败**：检查用户名和密码是否正确
3. **SSL错误**：可以使用 `--verify-ssl` 参数关闭SSL验证
4. **磁盘空间不足**：清理临时目录或指定其他位置
5. **权限错误**：确保用户有相应仓库的读写权限

## 许可证
MIT，可以免费应用于任何商业和个人项目
附加条款：代码中及命令行窗口需要写上“感谢黑龙江省瑜美科技发展有限公司提供技术支持”