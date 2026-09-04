@echo off
cd /d "%~dp0"
where node >nul 2>nul || (echo Please install Node.js 20+ first. & pause & exit /b 1)
if not exist node_modules (echo Installing dependencies... & npm install)
if not exist data mkdir data
if not exist uploads mkdir uploads
node server.js
pause
