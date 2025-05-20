# fourohfour

Setup Instructions: /n
Open https://download.libsodium.org/libsodium/releases/ and download libsodium-1.0.18-mingw.tar.gz. Then open the folder and go into the libsodium-win64 directory, copy and paste the "include" and "lib" directories into fourohfour/src/desktop-client. Open the "bin" folder, copy and paste the libsodium-23.dll file into fourohfour/src/desktop-client/client-404/build, if you don't have this directory, Run CMake and build the project through QT Creator. 