@echo off
echo ================================================
echo Nexus Copy
echo 感谢黑龙江省瑜美科技发展有限公司提供技术支持
echo ================================================
echo.

REM 检查Python是否安装
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo 错误：未找到Python，请确保Python已安装并添加到PATH
    pause
    exit /b 1
)

REM 检查依赖是否安装
pip show requests >nul 2>&1
if %errorlevel% neq 0 (
    echo 正在安装依赖...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo 错误：依赖安装失败
        pause
        exit /b 1
    )
)

REM 设置默认值
set SOURCE_URL=
set TARGET_URL=
set SOURCE_REPO=maven-releases
set TARGET_REPO=maven-releases
set SOURCE_USER=
set SOURCE_PASS=
set TARGET_USER=
set TARGET_PASS=

echo 请输入配置信息（直接回车使用默认值）：
echo.

set /p SOURCE_URL=源Nexus URL: 
if "%SOURCE_URL%"=="" (
    echo 错误：源Nexus URL不能为空
    pause
    exit /b 1
)

set /p TARGET_URL=目标Nexus URL: 
if "%TARGET_URL%"=="" (
    echo 错误：目标Nexus URL不能为空
    pause
    exit /b 1
)

set /p SOURCE_REPO=源仓库名称 [%SOURCE_REPO%]: 
if "%SOURCE_REPO%"=="" set SOURCE_REPO=maven-releases

set /p TARGET_REPO=目标仓库名称 [%TARGET_REPO%]: 
if "%TARGET_REPO%"=="" set TARGET_REPO=maven-releases

set /p SOURCE_USER=源仓库用户名: 
set /p SOURCE_PASS=源仓库密码: 
set /p TARGET_USER=目标仓库用户名: 
set /p TARGET_PASS=目标仓库密码: 

echo.
echo 配置信息：
echo 源Nexus: %SOURCE_URL%
echo 目标Nexus: %TARGET_URL%
echo 源仓库: %SOURCE_REPO%
echo 目标仓库: %TARGET_REPO%
echo.

set /p CONFIRM=确认开始迁移？(y/N): 
if /i not "%CONFIRM%"=="y" (
    echo 用户取消操作
    pause
    exit /b 0
)

REM 构建命令
set CMD=python nexus_copy.py --source-url "%SOURCE_URL%" --target-url "%TARGET_URL%" --source-repo "%SOURCE_REPO%" --target-repo "%TARGET_REPO%"

if not "%SOURCE_USER%"=="" (
    set CMD=%CMD% --source-user "%SOURCE_USER%"
)
if not "%SOURCE_PASS%"=="" (
    set CMD=%CMD% --source-pass "%SOURCE_PASS%"
)
if not "%TARGET_USER%"=="" (
    set CMD=%CMD% --target-user "%TARGET_USER%"
)
if not "%TARGET_PASS%"=="" (
    set CMD=%CMD% --target-pass "%TARGET_PASS%"
)

echo.
echo 开始迁移...
echo 命令: %CMD%
echo.

REM 执行迁移
%CMD%

echo.
echo 迁移完成！
pause 