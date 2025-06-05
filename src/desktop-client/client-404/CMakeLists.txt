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

# Set source files by category
set(UI_SOURCES
    ui/mainwindow.cpp
    ui/mainwindow.h
    ui/mainwindow.ui
    ui/registerpage.cpp
    ui/registerpage.h
    ui/registerpage.ui
    ui/loginpage.cpp
    ui/loginpage.h
    ui/loginpage.ui
    ui/titlepage.h
    ui/titlepage.cpp
    ui/titlepage.ui
    ui/verifypage.h
    ui/verifypage.cpp
    ui/verifypage.ui
    ui/uploadfilepage.h
    ui/uploadfilepage.cpp
    ui/uploadfilepage.ui
    ui/mainmenu.h
    ui/mainmenu.cpp
    ui/mainmenu.ui
    ui/fileitemwidget.h
    ui/fileitemwidget.cpp
    ui/frienditemwidget.h
    ui/frienditemwidget.cpp
    ui/viewfilespage.h
    ui/viewfilespage.cpp
    ui/viewfilespage.ui
    ui/basepage.h
    ui/basepage.cpp
    ui/resetpasswordpage.ui
    ui/resetpasswordpage.h
    ui/resetpasswordpage.cpp
)

set(CRYPTO_SOURCES
    crypto/key_utils.cpp
    crypto/key_utils.h
    crypto/encryptionhelper.h
    crypto/encryptionhelper.cpp
)

set(UTILS_SOURCES
    utils/password_utils.cpp
    utils/password_utils.h
    utils/securevector.h
    utils/securevector.cpp
    utils/securebufferutils.h
    utils/request_utils.h
    utils/request_utils.cpp
    utils/custom_deleter.h
    utils/json_sanitizer.h
    utils/json_sanitizer.cpp
    utils/file_sharing_utils.h
    utils/file_sharing_utils.cpp
    utils/friend_storage_utils.h
    utils/friend_storage_utils.cpp
    utils/file_crypto_utils.h
    utils/file_crypto_utils.cpp
    utils/widget_utils.h
    utils/widget_utils.cpp
    utils/shared_secret_utils.h
    utils/shared_secret_utils.cpp
    utils/x3dh_network_utils.h
    utils/x3dh_network_utils.cpp
    utils/file_sharing_manager_utils.h
    utils/file_sharing_manager_utils.cpp
)

set(CORE_SOURCES
    core/loginsessionmanager.h
    core/loginsessionmanager.cpp
)

set(PROJECT_SOURCES
    main.cpp
    pages.h
    constants.h
    ${UI_SOURCES}
    ${CRYPTO_SOURCES}
    ${UTILS_SOURCES}
    ${CORE_SOURCES}
)

# Main application target
if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(client-404
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
        resource.qrc
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

# Test source files
set(TEST_SOURCES
    tests/tst_key_utils.cpp
    tests/tst_key_utils.h
)

# Test target
add_executable(tst_key_utils
    ${TEST_SOURCES}
    crypto/key_utils.cpp
    crypto/key_utils.h
    utils/securevector.h
    utils/securevector.cpp
    utils/securebufferutils.h
    utils/request_utils.h
    utils/request_utils.cpp
    crypto/encryptionhelper.h
    crypto/encryptionhelper.cpp
    core/loginsessionmanager.h
    core/loginsessionmanager.cpp
    utils/json_sanitizer.h
    utils/json_sanitizer.cpp
)

# Include directories for the whole project
include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/ui
    ${CMAKE_SOURCE_DIR}/crypto
    ${CMAKE_SOURCE_DIR}/utils
    ${CMAKE_SOURCE_DIR}/core
    ${SODIUM_INCLUDE_DIR}  # Add libsodium include directory globally
    ${CURL_INCLUDE_DIR} #Add libcurrl include directory globally
    "${CMAKE_SOURCE_DIR}/../include"  # Also add this explicit path
)

# Add preprocessor definitions to prevent Windows byte conflicts
add_definitions(
    -DWIN32_LEAN_AND_MEAN
    -DNOMINMAX
    -DNO_MIN_MAX
    -DNOCRYPT
    -D_CRT_SECURE_NO_WARNINGS
    -DNOGDI
)

# Link libraries for main application
target_link_libraries(client-404 PRIVATE
    Qt${QT_VERSION_MAJOR}::Widgets
    Qt${QT_VERSION_MAJOR}::Network
    ${SODIUM_LIBRARY}
    ${CURL_LIBRARY}
)

# Link libraries for test target
target_link_libraries(tst_key_utils PRIVATE
    Qt${QT_VERSION_MAJOR}::Core
    Qt${QT_VERSION_MAJOR}::Test
    Qt${QT_VERSION_MAJOR}::Widgets
    ${SODIUM_LIBRARY}
    ${CURL_LIBRARY}
)

# Create source groups for IDE organization
source_group("UI" FILES ${UI_SOURCES})
source_group("Crypto" FILES ${CRYPTO_SOURCES})
source_group("Utils" FILES ${UTILS_SOURCES})
source_group("Core" FILES ${CORE_SOURCES})
source_group("Tests" FILES ${TEST_SOURCES})

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
