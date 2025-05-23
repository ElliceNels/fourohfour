cmake_minimum_required(VERSION 3.5)

project(client-404 VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add Network to the required components
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets Network)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets Network)

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

target_include_directories(client-404 PRIVATE "../include")
target_link_directories(client-404 PRIVATE "../lib")
target_link_libraries(client-404 PRIVATE sodium)

# Link both Widgets and Network modules
target_link_libraries(client-404 PRIVATE Qt${QT_VERSION_MAJOR}::Widgets Qt${QT_VERSION_MAJOR}::Network)

# Qt for iOS sets MACOSX_BUNDLE_GUI_IDENTIFIER automatically since Qt 6.1.
# If you are developing for iOS or macOS you should consider setting an
# explicit, fixed bundle identifier manually though.
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
