"E:\Program Files\CLion 2024.1\bin\cmake\win\x64\bin\cmake.exe" --build E:\analysis\frida-inline-hook\self_hook\cmake-build-android --target hook-agent -j 14
adb push .\cmake-build-android\libhook-agent.so /data/local/tmp
adb shell "chmod 777 /data/local/tmp/libhook-agent.so"
"E:\Program Files\CLion 2024.1\bin\cmake\win\x64\bin\cmake.exe" --build E:\analysis\frida-inline-hook\self_hook\cmake-build-android --target hook-server -j 14
adb push .\cmake-build-android\hook-server /data/local/tmp
adb shell "chmod 777 /data/local/tmp/hook-server"
adb shell su -c "/data/local/tmp/hook-server"