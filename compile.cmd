del /f /s /q dist 1>nul
rmdir /s /q dist
mkdir dist
mkdir dist\graphics

python -m nuitka --follow-imports wallet.py --windows-icon=graphics\icon.ico --standalone --show-progress -j 8 --recurse-all --plugin-enable=tk-inter

robocopy "C:\Program Files\Python37\Lib\site-packages\Cryptodome" dist\Cryptodome /MIR
robocopy "C:\Program Files\Python37\Lib\site-packages\coincurve" dist\coincurve /MIR

copy config.txt dist\config.txt
copy  graphics\icon.ico dist\graphics\icon.ico
copy  graphics\icon.jpg dist\graphics\icon.jpg
copy  graphics\logo.png dist\graphics\logo.png

robocopy wallet.dist dist /MOVE /E
robocopy themes dist\themes /MIR

"C:\Program Files (x86)\Inno Setup 5\iscc" /q "setup.iss"
pause

