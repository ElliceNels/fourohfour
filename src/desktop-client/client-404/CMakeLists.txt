cmake_minimum_required(VERSION 3.5)

project(client-404 VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add Network and Test to the required components
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets Network Test)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets Network Test)

# Set libsodium paths to local directories
set(SODIUM_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/../include")
set(SODIUM_LIBRARY "${CMAKE_SOURCE_DIR}/../lib/libsodium.dll.a")

# Set libcurl paths to local directories 
set(CURL_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/../include")
set(CURL_LIBRARY "${CMAKE_SOURCE_DIR}/../lib/libcurl.dll.a")


set(PROJECT_SOURCES
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
    password_utils.cpp
    password_utils.h
    registerpage.cpp
    registerpage.h
    registerpage.ui
    key_utils.cpp
    key_utils.h
    loginpage.cpp
    loginpage.h
    loginpage.ui
)

# Main application target
if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(client-404
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
        password_utils.h
        password_utils.h
        password_utils.cpp
        resource.qrc
        registerpage.ui
        registerpage.ui
        key_utils.h
        key_utils.cpp
        titlepage.h
        titlepage.cpp
        titlepage.ui
        pages.h
        verifypage.h
        verifypage.cpp
        verifypage.ui
        uploadfilepage.h
        uploadfilepage.cpp
        uploadfilepage.ui
        constants.h
        encryptionhelper.h
        encryptionhelper.cpp
        mainmenu.h
        mainmenu.cpp
        mainmenu.ui
        loginsessionmanager.h
        loginsessionmanager.cpp
        fileitemwidget.h
        fileitemwidget.cpp
        viewfilespage.h
        viewfilespage.cpp
        viewfilespage.ui
        basepage.h
        basepage.cpp
        securevector.h
        securevector.cpp
        securebufferutils.h
            )
else()
    if(ANDROID)
        add_library(client-404 SHARED
            ${PROJECT_SOURCES}
        )
    else()
        add_executable(client-404
            ${PROJECT_SOURCES}
        )
    endif()
endif()

# Test target
add_executable(tst_key_utils
    tst_key_utils.cpp
    tst_key_utils.h
    key_utils.cpp
    key_utils.h
    securevector.h
    securevector.cpp
    securebufferutils.h
    encryptionhelper.h
    encryptionhelper.cpp
    loginsessionmanager.h
    loginsessionmanager.cpp  # Added this file
)

# Link libraries for main application
target_include_directories(client-404 PRIVATE
    "${CMAKE_SOURCE_DIR}/../include"
    ${SODIUM_INCLUDE_DIR}
)
target_link_directories(client-404 PRIVATE
    "${CMAKE_SOURCE_DIR}/../lib"
)
target_link_libraries(client-404 PRIVATE
    Qt${QT_VERSION_MAJOR}::Widgets
    Qt${QT_VERSION_MAJOR}::Network
    ${SODIUM_LIBRARY}
    ${CURL_LIBRARY}  
)

# Link libraries for test target
target_include_directories(tst_key_utils PRIVATE
    "${CMAKE_SOURCE_DIR}/../include"
    ${SODIUM_INCLUDE_DIR}
)
target_link_directories(tst_key_utils PRIVATE
    "${CMAKE_SOURCE_DIR}/../lib"
)
target_link_libraries(tst_key_utils PRIVATE
    Qt${QT_VERSION_MAJOR}::Core
    Qt${QT_VERSION_MAJOR}::Test
    Qt${QT_VERSION_MAJOR}::Widgets
    ${SODIUM_LIBRARY}
)

# Enable testing
enable_testing()
add_test(NAME key_utils_test COMMAND tst_key_utils)

# Qt for iOS sets MACOSX_BUNDLE_GUI_IDENTIFIER automatically since Qt 6.1.
if(${QT_VERSION} VERSION_LESS 6.1.0)
  set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.client-404)
endif()

set_target_properties(client-404 PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
install(TARGETS client-404
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(client-404)
endif()
