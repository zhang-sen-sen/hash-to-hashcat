@echo off
rem 一键转Hash工具 - 源码运行启动器
rem 用法1：把文件拖到这个bat上松开  用法2：双击后输入文件路径
rem 说明：仓库仅含源码；若旁边有 转Hash工具.exe 则优先用它，否则用 Python 直接运行源码。
cd /d "%~dp0"
set "EXE=%~dp0转Hash工具.exe"
if exist "%EXE%" (
  if "%~1"=="" ("%EXE%") else ("%EXE%" %*)
  goto :end
)
where python >nul 2>nul
if %errorlevel%==0 (
  python -u "%~dp0tohash.py" %*
  goto :end
)
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 -u "%~dp0tohash.py" %*
  goto :end
)
echo.
echo  未找到可执行程序：旁边没有 转Hash工具.exe，且系统未安装 Python。
echo  请安装 Python 3.8+（勾选 "Add Python to PATH"）： https://www.python.org/downloads/
echo  或从 Releases 下载绿色版 exe： https://github.com/zhang-sen-sen/hash-to-hashcat/releases
echo.
pause
:end
endlocal
