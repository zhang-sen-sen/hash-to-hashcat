@echo off
rem 一键转Hash工具 - 备用启动器（主程序是 转Hash工具.exe，直接拖文件上去更快）
rem 用法1：把文件拖到这个bat上松开  用法2：双击后输入文件路径
cd /d "%~dp0"
set "EXE=%~dp0转Hash工具.exe"
if not exist "%EXE%" (
  echo 找不到 转Hash工具.exe，请确认本文件与exe在同一文件夹。
  pause
  exit /b 1
)
if "%~1"=="" (
  "%EXE%"
) else (
  "%EXE%" %*
)
