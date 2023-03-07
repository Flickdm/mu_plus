# Requirements for FormatAuthenticatedVariable.py

## Install the pip requirements

```bash
pip install -r requirements.txt
```

### Install openssl (Windows)
[vcpkg](https://github.com/Microsoft/vcpkg)

```bash
# clone vcpkg
# open directory where you've cloned vcpkg
$ run ./bootstrap-vcpkg.bat
$ run ./vcpkg.exe install openssl-windows:x64-windows
$ run ./vcpkg.exe install openssl:x64-windows-static
$ run ./vcpkg.exe integrate install
$ run set VCPKGRS_DYNAMIC=1 (or simply set it as your environment variable)
```