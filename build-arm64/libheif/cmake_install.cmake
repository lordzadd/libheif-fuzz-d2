# Install script for directory: /repo/libheif/libheif

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "RelWithDebInfo")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/llvm-objdump-18")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/repo/build-arm64/libheif/plugins/cmake_install.cmake")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/repo/build-arm64/libheif/libheif.a")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/libheif" TYPE FILE FILES
    "/repo/libheif/libheif/api/libheif/heif.h"
    "/repo/libheif/libheif/api/libheif/heif_export.h"
    "/repo/libheif/libheif/api/libheif/heif_library.h"
    "/repo/libheif/libheif/api/libheif/heif_image.h"
    "/repo/libheif/libheif/api/libheif/heif_color.h"
    "/repo/libheif/libheif/api/libheif/heif_error.h"
    "/repo/libheif/libheif/api/libheif/heif_plugin.h"
    "/repo/libheif/libheif/api/libheif/heif_properties.h"
    "/repo/libheif/libheif/api/libheif/heif_regions.h"
    "/repo/libheif/libheif/api/libheif/heif_items.h"
    "/repo/libheif/libheif/api/libheif/heif_sequences.h"
    "/repo/libheif/libheif/api/libheif/heif_tai_timestamps.h"
    "/repo/libheif/libheif/api/libheif/heif_brands.h"
    "/repo/libheif/libheif/api/libheif/heif_metadata.h"
    "/repo/libheif/libheif/api/libheif/heif_aux_images.h"
    "/repo/libheif/libheif/api/libheif/heif_entity_groups.h"
    "/repo/libheif/libheif/api/libheif/heif_security.h"
    "/repo/libheif/libheif/api/libheif/heif_encoding.h"
    "/repo/libheif/libheif/api/libheif/heif_decoding.h"
    "/repo/libheif/libheif/api/libheif/heif_image_handle.h"
    "/repo/libheif/libheif/api/libheif/heif_context.h"
    "/repo/libheif/libheif/api/libheif/heif_tiling.h"
    "/repo/libheif/libheif/api/libheif/heif_components.h"
    "/repo/libheif/libheif/api/libheif/heif_uncompressed.h"
    "/repo/libheif/libheif/api/libheif/heif_text.h"
    "/repo/libheif/libheif/api/libheif/heif_omaf.h"
    "/repo/libheif/libheif/api/libheif/heif_cxx.h"
    "/repo/build-arm64/libheif/heif_version.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/libheif/libheif-config.cmake")
    file(DIFFERENT _cmake_export_file_changed FILES
         "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/libheif/libheif-config.cmake"
         "/repo/build-arm64/libheif/CMakeFiles/Export/5cd8613eea38798f9c35b1a25e1b106b/libheif-config.cmake")
    if(_cmake_export_file_changed)
      file(GLOB _cmake_old_config_files "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/libheif/libheif-config-*.cmake")
      if(_cmake_old_config_files)
        string(REPLACE ";" ", " _cmake_old_config_files_text "${_cmake_old_config_files}")
        message(STATUS "Old export file \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/libheif/libheif-config.cmake\" will be replaced.  Removing files [${_cmake_old_config_files_text}].")
        unset(_cmake_old_config_files_text)
        file(REMOVE ${_cmake_old_config_files})
      endif()
      unset(_cmake_old_config_files)
    endif()
    unset(_cmake_export_file_changed)
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/libheif" TYPE FILE FILES "/repo/build-arm64/libheif/CMakeFiles/Export/5cd8613eea38798f9c35b1a25e1b106b/libheif-config.cmake")
  if(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/libheif" TYPE FILE FILES "/repo/build-arm64/libheif/CMakeFiles/Export/5cd8613eea38798f9c35b1a25e1b106b/libheif-config-relwithdebinfo.cmake")
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/libheif" TYPE FILE FILES "/repo/build-arm64/libheif/libheif-config-version.cmake")
endif()

