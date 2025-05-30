# fourohfour – Desktop Client Setup

## Directory Preparation

Create the following folders if they don't exist:

```
fourohfour/src/desktop-client/include
fourohfour/src/desktop-client/lib
```

## Libsodium Setup (Windows)

1. **Download:**

   * Go to [Libsodium Releases](https://download.libsodium.org/libsodium/releases/)
   * Download `libsodium-1.0.18-mingw.tar.gz`

2. **Extract & Copy:**

   * Open the `libsodium-win64` folder
   * Copy the contents of:

     * `include/` → `fourohfour/src/desktop-client/include`
     * `lib/` → `fourohfour/src/desktop-client/lib`

3. **DLL Placement:**

   * Copy `libsodium-23.dll` from `bin/` and paste it into:

     ```
     fourohfour/src/desktop-client/client-404/build
     ```
   * If the `build` directory doesn't exist, see **Building the Project** below.

---

## Libcurl Setup (Windows)

1. **Download:**

   * Go to [curl.se](https://curl.se/windows/)
   * Download the zip file that matches your architecture (e.g., `curl-8.14.0_1-win64-mingw.zip`)

2. **Extract & Copy:**

   * Open the extracted `curl-*/` folder
   * Copy:

     * `include/` → `fourohfour/src/desktop-client/include`
     * `lib/` → `fourohfour/src/desktop-client/lib`

3. **DLL Placement:**

   * Copy `libcurl-x64.dll` from `bin/` and paste it into:

     ```
     fourohfour/src/desktop-client/client-404/build
     ```

---

## Building the Project

If `client-404/build` does not exist:

1. Open **Qt Creator**
2. Open the project
3. Run **CMake**
4. Build the project — this will create the required `build` directory
