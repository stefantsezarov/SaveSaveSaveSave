@echo off
cd /d "%~dp0"
echo === Applying font patch ===
git pull
git am fonts.patch
if errorlevel 1 (echo. & echo PATCH FAILED - nothing pushed. & git am --abort & goto end)
git log --oneline -1
echo === Pushing ===
git push
del fonts.patch
echo. & echo DONE.
:end
echo.
pause
del "%~f0"
