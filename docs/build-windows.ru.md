# ����������� ������ �� Windows

������ �������� ������ QEMU-������� ���� � ���������� ELF. �� �� ������������ � ������, �� ���������� SD-����� � �� ������ ������������ ZIP.

�����:

- ARM GNU Toolchain 13.3.Rel1, Windows ZIP �� Arm, ������������� � ������� ������������.
- GNU Make ��� Windows (� ����������� ����� � mingw32-make 4.2.1).
- Python 3.13 � Git � PATH.
- BusyBox Windows �� https://frippery.org/busybox/ . � �������� ������������ ������� ����� busybox.exe � ������� sh.exe, pwd.exe, mkdir.exe, cp.exe, mv.exe, stat.exe, grep.exe, awk.exe, date.exe, whoami.exe, printf.exe, touch.exe, sort.exe, which.exe, cat.exe, echo.exe, rm.exe, head.exe, tail.exe, sed.exe, wc.exe, ls.exe, cmp.exe, find.exe.
- ��������� ����� python.exe ��� ������ python3.exe; PythonHome ������ ��������� �� �������� ������� ��������� Python.
- ����� arm-none-eabi-readelf.exe ��� ������ readelf.exe; hostname.exe � ������� Windows hostname, � �� BusyBox.

��������� ��������� ������ �� ���������. ������� ������������ � Git �� ����������. ������ �������� ������ PATH/PYTHONHOME �������� � ����� ��������������� ��.

������ � ������ ������:

```powershell
./scripts/build-windows.ps1 -ToolsDir C:/dev/tools -MakePath C:/dev/make/mingw32-make.exe -PythonHome C:/Python313
```

�����: `magiclantern/platform/750D.110/build-pc-full/autoexec` (ELF). ���� ������� ����� ��������� �� Git ������ ���������, ���� �� ���������� ��� ���������. ��� ��������� ������ ����������� �����������; ��� ��������� CONFIG-���������� ������� ������������ ��������� ������� ��� ������ ������.

��� �������� ������������ ����������, ����������� �������������� � Canon:

```powershell
python scripts/inspect_750d_fir.py C:/private/CCF23110.FIR
```

��� ����������� ��������, �� ����������� � �� �������� �������� �������. ���� �� ���������� � �� �����������.
