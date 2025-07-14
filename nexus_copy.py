#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MIT License

Copyright (c) 2025 杨若瑜

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

感谢黑龙江省瑜美科技发展有限公司提供技术支持

Nexus Copy
从一个Nexus仓库迁移所有jar包到另一个Nexus仓库
"""

import os
import sys
import json
import logging
import argparse
import requests
from urllib.parse import urlparse, urljoin
from urllib3.exceptions import InsecureRequestWarning
import time
from pathlib import Path
import threading
import tkinter as tk
from tkinter import ttk, messagebox

# 禁用SSL警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class NexusCopy:
    def __init__(self, source_url, target_url, source_auth=None, target_auth=None, 
                 temp_dir="./temp_artifacts", verify_ssl=False, log_callback=None):
        """
        初始化Nexus迁移工具
        
        Args:
            source_url: 源Nexus仓库URL
            target_url: 目标Nexus仓库URL
            source_auth: 源仓库认证信息 (username, password)
            target_auth: 目标仓库认证信息 (username, password)
            temp_dir: 临时下载目录
            verify_ssl: 是否验证SSL证书
            log_callback: 日志回调函数（用于UI实时显示）
        """
        self.source_url = source_url.rstrip('/')
        self.target_url = target_url.rstrip('/')
        self.source_auth = source_auth
        self.target_auth = target_auth
        self.temp_dir = Path(temp_dir)
        self.verify_ssl = verify_ssl
        self.log_callback = log_callback
        
        # 创建临时目录
        self.temp_dir.mkdir(exist_ok=True)
        
        # 设置日志
        self.setup_logging()
        
        # 设置会话
        self.source_session = requests.Session()
        self.target_session = requests.Session()
        
        if source_auth:
            self.source_session.auth = source_auth
        if target_auth:
            self.target_session.auth = target_auth
            
        # 设置通用请求头
        self.source_session.headers.update({
            'User-Agent': 'Nexus-Migrator/1.0',
            'Accept': 'application/json'
        })
        self.target_session.headers.update({
            'User-Agent': 'Nexus-Migrator/1.0'
        })

    def setup_logging(self):
        """设置日志记录"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('nexus_copy.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def log(self, msg, level="info"):
        if self.log_callback:
            self.log_callback(msg)
        if level == "info":
            self.logger.info(msg)
        elif level == "error":
            self.logger.error(msg)
        else:
            self.logger.info(msg)
    
    def get_repository_artifacts(self, repository_name):
        """
        获取仓库中的所有artifact信息
        
        Args:
            repository_name: 仓库名称
            
        Returns:
            list: artifact信息列表
        """
        artifacts = []
        continuation_token = None
        exclude_exts = {'.md5', '.sha1', '.sha256', '.sha512'}
        
        while True:
            url = f"{self.source_url}/service/rest/v1/components"
            params = {
                'repository': repository_name,
                'sort': 'name'
            }
            
            if continuation_token:
                params['continuationToken'] = continuation_token
            
            try:
                response = self.source_session.get(
                    url, 
                    params=params, 
                    verify=self.verify_ssl,
                    timeout=30
                )
                response.raise_for_status()
                
                data = response.json()
                items = data.get('items', [])
                
                for item in items:
                    assets = item.get('assets', [])
                    for asset in assets:
                        path = asset.get('path', '')
                        # 排除校验文件
                        if any(path.endswith(ext) for ext in exclude_exts):
                            continue
                        # 自动提取扩展名
                        ext = os.path.splitext(path)[1][1:] if '.' in os.path.basename(path) else ''
                        artifacts.append({
                            'name': item.get('name'),
                            'version': item.get('version'),
                            'group': item.get('group'),
                            'asset_id': asset.get('id'),
                            'download_url': asset.get('downloadUrl'),
                            'path': asset.get('path'),
                            'size': asset.get('size', 0),
                            'extension': ext
                        })
                
                continuation_token = data.get('continuationToken')
                if not continuation_token:
                    break
                self.log(f"已获取 {len(artifacts)} 个artifact信息...")
                
            except requests.RequestException as e:
                self.log(f"获取artifact列表失败: {e}", level="error")
                break
        self.log(f"总共找到 {len(artifacts)} 个artifact")
        return artifacts
    
    def get_target_artifacts_set(self, repository_name):
        """
        获取目标仓库所有jar包的 groupId:artifactId:version 集合
        """
        artifacts_set = set()
        continuation_token = None
        while True:
            url = f"{self.target_url}/service/rest/v1/components"
            params = {
                'repository': repository_name,
                'sort': 'name'
            }
            if continuation_token:
                params['continuationToken'] = continuation_token
            try:
                response = self.target_session.get(
                    url,
                    params=params,
                    verify=self.verify_ssl,
                    timeout=30
                )
                response.raise_for_status()
                data = response.json()
                items = data.get('items', [])
                for item in items:
                    group = item.get('group')
                    name = item.get('name')
                    version = item.get('version')
                    if group and name and version:
                        artifacts_set.add(f"{group}:{name}:{version}")
                continuation_token = data.get('continuationToken')
                if not continuation_token:
                    break
            except requests.RequestException as e:
                self.log(f"获取目标仓库artifact列表失败: {e}", level="error")
                break
        return artifacts_set
    
    def download_artifact(self, artifact):
        """
        下载单个artifact
        
        Args:
            artifact: artifact信息字典
            
        Returns:
            str: 下载的文件路径，失败返回None
        """
        download_url = artifact['download_url']
        file_path = self.temp_dir / artifact['path']
        
        # 创建目录
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 如果文件已存在且大小匹配，跳过下载
        if file_path.exists() and file_path.stat().st_size == artifact['size']:
            self.log(f"文件已存在，跳过下载: {artifact['path']}")
            return str(file_path)
        
        try:
            self.log(f"下载: {artifact['path']}")
            response = self.source_session.get(
                download_url,
                verify=self.verify_ssl,
                stream=True,
                timeout=60
            )
            response.raise_for_status()
            
            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            self.log(f"下载完成: {artifact['path']}")
            return str(file_path)
            
        except requests.RequestException as e:
            self.log(f"下载失败 {artifact['path']}: {e}", level="error")
            return None
    
    def upload_artifact(self, artifact, file_path, target_repository):
        """
        上传artifact到目标仓库
        
        Args:
            artifact: artifact信息字典
            file_path: 本地文件路径
            target_repository: 目标仓库名称
            
        Returns:
            bool: 是否上传成功
        """
        if not os.path.exists(file_path):
            self.log(f"文件不存在: {file_path}", level="error")
            return False
        
        # 构建上传URL
        upload_url = f"{self.target_url}/service/rest/v1/components"
        
        # 自动识别扩展名
        ext = artifact.get('extension')
        if not ext:
            ext = os.path.splitext(file_path)[1][1:]  # 去掉点
        
        # content-type 统一 application/octet-stream
        files = {
            'maven2.asset1': (os.path.basename(file_path), open(file_path, 'rb'), 'application/octet-stream')
        }
        
        data = {
            'maven2.groupId': artifact['group'],
            'maven2.artifactId': artifact['name'],
            'maven2.version': artifact['version'],
            'maven2.asset1.extension': ext
        }
        
        params = {
            'repository': target_repository
        }
        
        try:
            self.log(f"上传: {artifact['group']}:{artifact['name']}:{artifact['version']} [{os.path.basename(file_path)}]")
            
            response = self.target_session.post(
                upload_url,
                files=files,
                data=data,
                params=params,
                verify=self.verify_ssl,
                timeout=120
            )
            
            files['maven2.asset1'][1].close()  # 关闭文件
            
            if response.status_code == 204:
                self.log(f"上传成功: {artifact['group']}:{artifact['name']}:{artifact['version']} [{os.path.basename(file_path)}]")
                return True
            else:
                self.log(f"上传失败: {artifact['group']}:{artifact['name']}:{artifact['version']} [{os.path.basename(file_path)}], 状态码: {response.status_code}, 响应: {response.text}", level="error")
                return False
                
        except requests.RequestException as e:
            self.log(f"上传失败 {artifact['group']}:{artifact['name']}:{artifact['version']} [{os.path.basename(file_path)}]: {e}", level="error")
            return False
        finally:
            # 确保文件被关闭
            if 'maven2.asset1' in files:
                try:
                    files['maven2.asset1'][1].close()
                except:
                    pass
    
    def migrate_repository(self, source_repository, target_repository, 
                          download_only=False, upload_only=False, sync_mode="full"):
        """
        迁移整个仓库
        Args:
            source_repository: 源仓库名称
            target_repository: 目标仓库名称
            download_only: 仅下载不上传
            upload_only: 仅上传不下载（需要文件已存在）
            sync_mode: 同步模式 full=全量 incremental=增量
        Returns:
            dict: 迁移结果统计
        """
        results = {
            'total': 0,
            'downloaded': 0,
            'uploaded': 0,
            'download_failed': 0,
            'upload_failed': 0
        }
        if not upload_only:
            # 获取artifact列表
            self.log(f"开始获取仓库 {source_repository} 的artifact列表...")
            artifacts = self.get_repository_artifacts(source_repository)
            # 增量同步过滤
            if sync_mode == "incremental":
                self.log("增量同步模式，获取目标仓库已有jar包...")
                target_set = self.get_target_artifacts_set(target_repository)
                before_count = len(artifacts)
                artifacts = [a for a in artifacts if f"{a['group']}:{a['name']}:{a['version']}" not in target_set]
                self.log(f"过滤后需同步jar包: {len(artifacts)} (原有: {before_count})")
            results['total'] = len(artifacts)
            if not artifacts:
                self.log("没有找到任何需要同步的jar包", level="error")
                return results
            # 下载artifacts
            self.log(f"开始下载 {len(artifacts)} 个jar包...")
            downloaded_files = []
            for i, artifact in enumerate(artifacts, 1):
                self.log(f"处理进度: {i}/{len(artifacts)}")
                file_path = self.download_artifact(artifact)
                if file_path:
                    downloaded_files.append((artifact, file_path))
                    results['downloaded'] += 1
                else:
                    results['download_failed'] += 1
                time.sleep(0.1)
            if download_only:
                self.log("仅下载模式，跳过上传")
                return results
        else:
            self.log("仅上传模式，扫描本地文件...")
            downloaded_files = []
            # 这里需要根据实际情况实现从本地文件构建artifact信息的逻辑
        # 上传artifacts
        if not download_only:
            self.log(f"开始上传到目标仓库 {target_repository}...")
            for artifact, file_path in downloaded_files:
                success = self.upload_artifact(artifact, file_path, target_repository)
                if success:
                    results['uploaded'] += 1
                else:
                    results['upload_failed'] += 1
                time.sleep(0.1)
        return results
    
    def cleanup(self):
        """清理临时文件"""
        try:
            import shutil
            if self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
                self.log("临时文件清理完成")
        except Exception as e:
            self.log(f"清理临时文件失败: {e}", level="error")


class NexusCopyUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Nexus Copy - 感谢黑龙江省瑜美科技发展有限公司提供技术支持")
        self.root.geometry("700x800")
        self.root.resizable(False, False)
        self.status_var = tk.StringVar()
        self.create_widgets()
        self.migrator = None
        self.sync_thread = None

    def create_widgets(self):
        pad = 8
        # 顶部大标题
        title = tk.Label(self.root, text="Nexus Copy", font=("微软雅黑", 20, "bold"), fg="#1a237e")
        title.pack(pady=(18, 6))

        # 源仓库分组
        frm_source = ttk.LabelFrame(self.root, text="源仓库参数", padding=pad)
        frm_source.pack(fill=tk.X, padx=20, pady=(0, 10))
        ttk.Label(frm_source, text="URL:").grid(row=0, column=0, sticky=tk.W, pady=pad)
        self.source_url = ttk.Entry(frm_source, width=55)
        self.source_url.insert(0, "http://127.0.0.1:8080/")
        self.source_url.grid(row=0, column=1, pady=pad, sticky=tk.W)
        self.btn_test_source = ttk.Button(frm_source, text="测试连接", command=self.test_source)
        self.btn_test_source.grid(row=0, column=2, padx=pad)
        ttk.Label(frm_source, text="仓库名:").grid(row=1, column=0, sticky=tk.W, pady=pad)
        self.source_repo = ttk.Entry(frm_source, width=20)
        self.source_repo.insert(0, "maven-releases")
        self.source_repo.grid(row=1, column=1, pady=pad, sticky=tk.W)
        ttk.Label(frm_source, text="用户名:").grid(row=2, column=0, sticky=tk.W, pady=pad)
        self.source_user = ttk.Entry(frm_source, width=15)
        self.source_user.insert(0, "admin")
        self.source_user.grid(row=2, column=1, pady=pad, sticky=tk.W)
        ttk.Label(frm_source, text="密码:").grid(row=2, column=2, sticky=tk.E)
        self.source_pass = ttk.Entry(frm_source, width=15, show="*")
        self.source_pass.grid(row=2, column=3, pady=pad, sticky=tk.W)

        # 目标仓库分组
        frm_target = ttk.LabelFrame(self.root, text="目标仓库参数", padding=pad)
        frm_target.pack(fill=tk.X, padx=20, pady=(0, 10))
        ttk.Label(frm_target, text="URL:").grid(row=0, column=0, sticky=tk.W, pady=pad)
        self.target_url = ttk.Entry(frm_target, width=55)
        self.target_url.insert(0, "http://127.0.0.1:8080/")
        self.target_url.grid(row=0, column=1, pady=pad, sticky=tk.W)
        self.btn_test_target = ttk.Button(frm_target, text="测试连接", command=self.test_target)
        self.btn_test_target.grid(row=0, column=2, padx=pad)
        ttk.Label(frm_target, text="仓库名:").grid(row=1, column=0, sticky=tk.W, pady=pad)
        self.target_repo = ttk.Entry(frm_target, width=20)
        self.target_repo.insert(0, "maven-releases")
        self.target_repo.grid(row=1, column=1, pady=pad, sticky=tk.W)
        ttk.Label(frm_target, text="用户名:").grid(row=2, column=0, sticky=tk.W, pady=pad)
        self.target_user = ttk.Entry(frm_target, width=15)
        self.target_user.insert(0, "admin")
        self.target_user.grid(row=2, column=1, pady=pad, sticky=tk.W)
        ttk.Label(frm_target, text="密码:").grid(row=2, column=2, sticky=tk.E)
        self.target_pass = ttk.Entry(frm_target, width=15, show="*")
        self.target_pass.grid(row=2, column=3, pady=pad, sticky=tk.W)

        # 同步参数分组
        frm_param = ttk.LabelFrame(self.root, text="同步参数", padding=pad)
        frm_param.pack(fill=tk.X, padx=20, pady=(0, 10))
        ttk.Label(frm_param, text="同步模式:").grid(row=0, column=0, sticky=tk.W, pady=pad)
        self.sync_mode = ttk.Combobox(frm_param, values=["full", "incremental"], width=15, state="readonly")
        self.sync_mode.set("full")
        self.sync_mode.grid(row=0, column=1, pady=pad, sticky=tk.W)
        self.verify_ssl = tk.BooleanVar()
        ttk.Checkbutton(frm_param, text="验证SSL证书", variable=self.verify_ssl).grid(row=0, column=2, sticky=tk.W, pady=pad)
        self.download_only = tk.BooleanVar()
        ttk.Checkbutton(frm_param, text="仅下载不上传", variable=self.download_only).grid(row=0, column=3, sticky=tk.W, pady=pad)
        self.upload_only = tk.BooleanVar()
        ttk.Checkbutton(frm_param, text="仅上传不下载", variable=self.upload_only).grid(row=0, column=4, sticky=tk.W, pady=pad)
        ttk.Label(frm_param, text="临时目录:").grid(row=1, column=0, sticky=tk.W, pady=pad)
        self.temp_dir = ttk.Entry(frm_param, width=30)
        self.temp_dir.insert(0, "./temp_artifacts")
        self.temp_dir.grid(row=1, column=1, pady=pad, sticky=tk.W)

        # 操作按钮
        frm_btn = ttk.Frame(self.root)
        frm_btn.pack(fill=tk.X, padx=20, pady=(0, 8))
        self.btn_start = tk.Button(frm_btn, text="开始同步", command=self.start_sync, bg="#1976d2", fg="white", font=("微软雅黑", 13, "bold"), height=1, width=12)
        self.btn_start.pack(pady=4)

        # 进度条
        frm_prog = ttk.Frame(self.root)
        frm_prog.pack(fill=tk.X, padx=20, pady=(0, 2))
        self.progress = ttk.Progressbar(frm_prog, mode="determinate")
        self.progress.pack(fill=tk.X, expand=True, padx=(0, 10), pady=2)

        # 日志区
        frm_log = ttk.LabelFrame(self.root, text="同步日志", padding=pad)
        frm_log.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 8))
        log_frame = tk.Frame(frm_log)
        log_frame.pack(fill=tk.BOTH, expand=True)
        self.log_text = tk.Text(log_frame, height=10, width=80, font=("Consolas", 10), bg="#f5f5f5")
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)
        log_scroll = tk.Scrollbar(log_frame, command=self.log_text.yview)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=log_scroll.set)

        # 品牌信息
        brand = tk.Label(self.root, text="黑龙江省瑜美科技发展有限公司出品", font=("微软雅黑", 9), fg="#888888")
        brand.pack(pady=(0, 8))

    def log(self, msg):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.status_var.set(msg if (msg and len(msg) < 40) else "")

    def test_source(self):
        url = self.source_url.get().strip()
        user = self.source_user.get().strip()
        pwd = self.source_pass.get().strip()
        repo = self.source_repo.get().strip()
        if not url or not repo:
            messagebox.showwarning("提示", "请填写源仓库URL和仓库名称")
            return
        try:
            session = requests.Session()
            if user and pwd:
                session.auth = (user, pwd)
            session.headers.update({'User-Agent': 'Nexus-Migrator/1.0', 'Accept': 'application/json'})
            api = f"{url.rstrip('/')}/service/rest/v1/components"
            resp = session.get(api, params={'repository': repo, 'limit': 1}, verify=not not self.verify_ssl.get(), timeout=10)
            resp.raise_for_status()
            messagebox.showinfo("连接成功", "源仓库连接正常！")
        except Exception as e:
            messagebox.showerror("连接失败", f"源仓库连接失败: {e}")

    def test_target(self):
        url = self.target_url.get().strip()
        user = self.target_user.get().strip()
        pwd = self.target_pass.get().strip()
        repo = self.target_repo.get().strip()
        if not url or not repo:
            messagebox.showwarning("提示", "请填写目标仓库URL和仓库名称")
            return
        try:
            session = requests.Session()
            if user and pwd:
                session.auth = (user, pwd)
            session.headers.update({'User-Agent': 'Nexus-Migrator/1.0', 'Accept': 'application/json'})
            api = f"{url.rstrip('/')}/service/rest/v1/components"
            resp = session.get(api, params={'repository': repo, 'limit': 1}, verify=not not self.verify_ssl.get(), timeout=10)
            resp.raise_for_status()
            messagebox.showinfo("连接成功", "目标仓库连接正常！")
        except Exception as e:
            messagebox.showerror("连接失败", f"目标仓库连接失败: {e}")

    def start_sync(self):
        if self.sync_thread and self.sync_thread.is_alive():
            messagebox.showinfo("提示", "同步正在进行中，请稍候...")
            return
        params = self.get_params()
        if not params:
            return
        self.progress['value'] = 0
        # 不再自动清空日志，用户可手动清空
        self.sync_thread = threading.Thread(target=self.do_sync, args=(params,))
        self.sync_thread.start()

    def get_params(self):
        try:
            params = {
                'source_url': self.source_url.get().strip(),
                'target_url': self.target_url.get().strip(),
                'source_repo': self.source_repo.get().strip(),
                'target_repo': self.target_repo.get().strip(),
                'source_user': self.source_user.get().strip(),
                'source_pass': self.source_pass.get().strip(),
                'target_user': self.target_user.get().strip(),
                'target_pass': self.target_pass.get().strip(),
                'temp_dir': self.temp_dir.get().strip(),
                'verify_ssl': self.verify_ssl.get(),
                'download_only': self.download_only.get(),
                'upload_only': self.upload_only.get(),
                'sync_mode': self.sync_mode.get()
            }
            for k in ['source_url', 'target_url', 'source_repo', 'target_repo']:
                if not params[k]:
                    messagebox.showwarning("提示", f"请填写 {k.replace('_', ' ')}")
                    return None
            return params
        except Exception as e:
            messagebox.showerror("参数错误", str(e))
            return None

    def log_to_ui(self, msg):
        # 线程安全地写入UI
        self.root.after(0, self.log, msg)

    def set_progress(self, value, maximum=None):
        def _set():
            if maximum is not None:
                self.progress['maximum'] = maximum
            self.progress['value'] = value
        self.root.after(0, _set)

    def do_sync(self, params):
        self.log("开始同步...")
        source_auth = (params['source_user'], params['source_pass']) if params['source_user'] and params['source_pass'] else None
        target_auth = (params['target_user'], params['target_pass']) if params['target_user'] and params['target_pass'] else None
        # 包装 log_callback 以便统计进度
        progress_info = {'current': 0, 'total': 1}
        def log_and_progress(msg):
            self.log_to_ui(msg)
            # 进度条只在处理artifact时更新
            if msg.startswith('下载:') or msg.startswith('上传:'):
                progress_info['current'] += 1
                self.set_progress(progress_info['current'], progress_info['total'])
        migrator = NexusCopy(
            source_url=params['source_url'],
            target_url=params['target_url'],
            source_auth=source_auth,
            target_auth=target_auth,
            temp_dir=params['temp_dir'],
            verify_ssl=params['verify_ssl'],
            log_callback=log_and_progress
        )
        try:
            # 先获取artifact总数
            artifacts = migrator.get_repository_artifacts(params['source_repo']) if not params['upload_only'] else []
            total = len(artifacts)
            if not params['download_only'] and not params['upload_only']:
                total = total * 2  # 下载+上传
            elif params['download_only'] or params['upload_only']:
                total = len(artifacts)
            progress_info['total'] = max(total, 1)
            self.set_progress(0, progress_info['total'])
            # 重新执行迁移（带进度）
            results = migrator.migrate_repository(
                source_repository=params['source_repo'],
                target_repository=params['target_repo'],
                download_only=params['download_only'],
                upload_only=params['upload_only'],
                sync_mode=params['sync_mode']
            )
            self.log_to_ui("\n同步完成！")
            self.log_to_ui(f"总计artifact: {results['total']}")
            self.log_to_ui(f"成功下载: {results['downloaded']}")
            self.log_to_ui(f"下载失败: {results['download_failed']}")
            self.log_to_ui(f"成功上传: {results['uploaded']}")
            self.log_to_ui(f"上传失败: {results['upload_failed']}")
        except Exception as e:
            self.log_to_ui(f"同步出错: {e}")
        finally:
            migrator.cleanup()

    def run(self):
        self.root.mainloop()


def main():
    parser = argparse.ArgumentParser(description="Nexus Copy")
    parser.add_argument("--source-url", required=False, help="源Nexus仓库URL")
    parser.add_argument("--target-url", required=False, help="目标Nexus仓库URL")
    parser.add_argument("--source-repo", required=False, help="源仓库名称")
    parser.add_argument("--target-repo", required=False, help="目标仓库名称")
    parser.add_argument("--source-user", help="源仓库用户名")
    parser.add_argument("--source-pass", help="源仓库密码")
    parser.add_argument("--target-user", help="目标仓库用户名")
    parser.add_argument("--target-pass", help="目标仓库密码")
    parser.add_argument("--temp-dir", default="./temp_artifacts", help="临时目录")
    parser.add_argument("--verify-ssl", action="store_true", help="验证SSL证书")
    parser.add_argument("--download-only", action="store_true", help="仅下载不上传")
    parser.add_argument("--upload-only", action="store_true", help="仅上传不下载")
    parser.add_argument("--no-cleanup", action="store_true", help="不清理临时文件")
    parser.add_argument("--sync-mode", choices=["full", "incremental"], default="full", help="同步模式: full=全量, incremental=增量")
    parser.add_argument("--ui", action="store_true", help="以图形界面模式启动")
    args = parser.parse_args()

    # 如果没有参数，友好提示
    if not args.ui and not (args.source_url and args.target_url and args.source_repo and args.target_repo):
        print("请用 --ui 启动图形界面，或用 --help 查看命令行用法")
        return
    
    if args.ui:
        NexusCopyUI().run()
        return
    
    # 设置认证信息
    source_auth = None
    target_auth = None
    print("感谢黑龙江省瑜美科技发展有限公司提供技术支持")
    
    if args.source_user and args.source_pass:
        source_auth = (args.source_user, args.source_pass)
    
    if args.target_user and args.target_pass:
        target_auth = (args.target_user, args.target_pass)
    
    # 创建迁移工具实例
    migrator = NexusCopy(
        source_url=args.source_url,
        target_url=args.target_url,
        source_auth=source_auth,
        target_auth=target_auth,
        temp_dir=args.temp_dir,
        verify_ssl=args.verify_ssl
    )
    
    try:
        # 执行迁移
        results = migrator.migrate_repository(
            source_repository=args.source_repo,
            target_repository=args.target_repo,
            download_only=args.download_only,
            upload_only=args.upload_only,
            sync_mode=args.sync_mode
        )
        
        # 打印结果
        print("\n" + "="*50)
        print("迁移结果统计:")
        print(f"总计jar包: {results['total']}")
        print(f"成功下载: {results['downloaded']}")
        print(f"下载失败: {results['download_failed']}")
        print(f"成功上传: {results['uploaded']}")
        print(f"上传失败: {results['upload_failed']}")
        print("="*50)
        
    except KeyboardInterrupt:
        print("\n用户中断迁移过程")
    except Exception as e:
        print(f"迁移过程中发生错误: {e}")
    finally:
        # 清理临时文件
        if not args.no_cleanup:
            migrator.cleanup()


if __name__ == "__main__":
    main() 