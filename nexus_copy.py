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

# 禁用SSL警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class NexusCopy:
    def __init__(self, source_url, target_url, source_auth=None, target_auth=None, 
                 temp_dir="./temp_artifacts", verify_ssl=False):
        """
        初始化Nexus迁移工具
        
        Args:
            source_url: 源Nexus仓库URL
            target_url: 目标Nexus仓库URL
            source_auth: 源仓库认证信息 (username, password)
            target_auth: 目标仓库认证信息 (username, password)
            temp_dir: 临时下载目录
            verify_ssl: 是否验证SSL证书
        """
        self.source_url = source_url.rstrip('/')
        self.target_url = target_url.rstrip('/')
        self.source_auth = source_auth
        self.target_auth = target_auth
        self.temp_dir = Path(temp_dir)
        self.verify_ssl = verify_ssl
        
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
                    # 只处理jar包
                    assets = item.get('assets', [])
                    for asset in assets:
                        if asset.get('path', '').endswith('.jar'):
                            artifacts.append({
                                'name': item.get('name'),
                                'version': item.get('version'),
                                'group': item.get('group'),
                                'asset_id': asset.get('id'),
                                'download_url': asset.get('downloadUrl'),
                                'path': asset.get('path'),
                                'size': asset.get('size', 0)
                            })
                
                continuation_token = data.get('continuationToken')
                if not continuation_token:
                    break
                    
                self.logger.info(f"已获取 {len(artifacts)} 个jar包信息...")
                
            except requests.RequestException as e:
                self.logger.error(f"获取artifact列表失败: {e}")
                break
        
        self.logger.info(f"总共找到 {len(artifacts)} 个jar包")
        return artifacts
    
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
            self.logger.info(f"文件已存在，跳过下载: {artifact['path']}")
            return str(file_path)
        
        try:
            self.logger.info(f"下载: {artifact['path']}")
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
            
            self.logger.info(f"下载完成: {artifact['path']}")
            return str(file_path)
            
        except requests.RequestException as e:
            self.logger.error(f"下载失败 {artifact['path']}: {e}")
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
            self.logger.error(f"文件不存在: {file_path}")
            return False
        
        # 构建上传URL
        upload_url = f"{self.target_url}/service/rest/v1/components"
        
        # 准备上传数据
        files = {
            'maven2.asset1': (os.path.basename(file_path), open(file_path, 'rb'), 'application/java-archive')
        }
        
        data = {
            'maven2.groupId': artifact['group'],
            'maven2.artifactId': artifact['name'],
            'maven2.version': artifact['version'],
            'maven2.asset1.extension': 'jar'
        }
        
        params = {
            'repository': target_repository
        }
        
        try:
            self.logger.info(f"上传: {artifact['group']}:{artifact['name']}:{artifact['version']}")
            
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
                self.logger.info(f"上传成功: {artifact['group']}:{artifact['name']}:{artifact['version']}")
                return True
            else:
                self.logger.error(f"上传失败: {artifact['group']}:{artifact['name']}:{artifact['version']}, "
                                f"状态码: {response.status_code}, 响应: {response.text}")
                return False
                
        except requests.RequestException as e:
            self.logger.error(f"上传失败 {artifact['group']}:{artifact['name']}:{artifact['version']}: {e}")
            return False
        finally:
            # 确保文件被关闭
            if 'maven2.asset1' in files:
                try:
                    files['maven2.asset1'][1].close()
                except:
                    pass
    
    def migrate_repository(self, source_repository, target_repository, 
                          download_only=False, upload_only=False):
        """
        迁移整个仓库
        
        Args:
            source_repository: 源仓库名称
            target_repository: 目标仓库名称
            download_only: 仅下载不上传
            upload_only: 仅上传不下载（需要文件已存在）
            
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
            self.logger.info(f"开始获取仓库 {source_repository} 的artifact列表...")
            artifacts = self.get_repository_artifacts(source_repository)
            results['total'] = len(artifacts)
            
            if not artifacts:
                self.logger.warning("没有找到任何jar包")
                return results
            
            # 下载artifacts
            self.logger.info(f"开始下载 {len(artifacts)} 个jar包...")
            downloaded_files = []
            
            for i, artifact in enumerate(artifacts, 1):
                self.logger.info(f"处理进度: {i}/{len(artifacts)}")
                
                file_path = self.download_artifact(artifact)
                if file_path:
                    downloaded_files.append((artifact, file_path))
                    results['downloaded'] += 1
                else:
                    results['download_failed'] += 1
                
                # 添加短暂延迟，避免过度请求
                time.sleep(0.1)
            
            if download_only:
                self.logger.info("仅下载模式，跳过上传")
                return results
        else:
            # 仅上传模式，从本地文件系统构建artifact列表
            self.logger.info("仅上传模式，扫描本地文件...")
            downloaded_files = []
            # 这里需要根据实际情况实现从本地文件构建artifact信息的逻辑
            
        # 上传artifacts
        if not download_only:
            self.logger.info(f"开始上传到目标仓库 {target_repository}...")
            
            for artifact, file_path in downloaded_files:
                success = self.upload_artifact(artifact, file_path, target_repository)
                if success:
                    results['uploaded'] += 1
                else:
                    results['upload_failed'] += 1
                
                # 添加短暂延迟，避免过度请求
                time.sleep(0.1)
        
        return results
    
    def cleanup(self):
        """清理临时文件"""
        try:
            import shutil
            if self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
                self.logger.info("临时文件清理完成")
        except Exception as e:
            self.logger.error(f"清理临时文件失败: {e}")


def main():
    parser = argparse.ArgumentParser(description="Nexus Copy")
    parser.add_argument("--source-url", required=True, help="源Nexus仓库URL")
    parser.add_argument("--target-url", required=True, help="目标Nexus仓库URL")
    parser.add_argument("--source-repo", required=True, help="源仓库名称")
    parser.add_argument("--target-repo", required=True, help="目标仓库名称")
    parser.add_argument("--source-user", help="源仓库用户名")
    parser.add_argument("--source-pass", help="源仓库密码")
    parser.add_argument("--target-user", help="目标仓库用户名")
    parser.add_argument("--target-pass", help="目标仓库密码")
    parser.add_argument("--temp-dir", default="./temp_artifacts", help="临时目录")
    parser.add_argument("--verify-ssl", action="store_true", help="验证SSL证书")
    parser.add_argument("--download-only", action="store_true", help="仅下载不上传")
    parser.add_argument("--upload-only", action="store_true", help="仅上传不下载")
    parser.add_argument("--no-cleanup", action="store_true", help="不清理临时文件")
    
    args = parser.parse_args()
    
    # 设置认证信息
    source_auth = None
    target_auth = None
    
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
            upload_only=args.upload_only
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