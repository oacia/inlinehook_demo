yet just a very simple inline hook.

Before building, these cmake options below are required for building android target, pass them in via cmdline.

```bash 
-DCMAKE_TOOLCHAIN_FILE=D:\Android-sdk\ndk\25.2.9519653\build\cmake\android.toolchain.cmake -DCMAKE_SYSTEM_NAME=Android -DANDROID_ABI=arm64-v8a -DCMAKE_ANDROID_NDK=D:\Android-sdk\ndk\25.2.9519653 -DCMAKE_SYSTEM_VERSION=25 -DCMAKE_C_FLAGS= -DCMAKE_CXX_FLAGS= -DCMAKE_ANDROID_NDK_TOOLCHAIN_VERSION=clang
```

for more infomation, see here https://oacia.dev/frida-inline-hook/ , this could help you learn some interesting tips about inlinehook.