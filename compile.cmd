del /f /s /q dist 1>nul
rmdir /s /q dist
mkdir dist
mkdir dist\graphics

python -m nuitka --follow-imports wallet.py --windows-icon-from-ico=graphics\icon.ico --standalone --show-progress -j 8 --plugin-enable=tk-inter

robocopy "C:\Python39\Lib\site-packages\Cryptodome" dist\Cryptodome /MIR
robocopy "C:\Python39\Lib\site-packages\coincurve" dist\coincurve /MIR

copy config.txt dist\config.txt
copy  graphics\icon.ico dist\graphics\icon.ico
copy  graphics\icon.jpg dist\graphics\icon.jpg
copy  graphics\logo.png dist\graphics\logo.png

robocopy wallet.dist dist /MOVE /E
robocopy themes dist\themes /MIR

"C:\Program Files (x86)\Inno Setup 6\iscc" /q "setup.iss"
pause

