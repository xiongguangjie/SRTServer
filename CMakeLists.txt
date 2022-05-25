project(SRTServer)
cmake_minimum_required(VERSION 3.1.3)
include(CheckStructHasMember)
include(CheckSymbolExists)

# 检查sendmmsg相关依赖并设置对应的宏
list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
check_struct_has_member("struct mmsghdr" msg_hdr sys/socket.h HAVE_MMSG_HDR)
check_symbol_exists(sendmmsg sys/socket.h HAVE_SENDMMSG_API)
check_symbol_exists(recvmmsg sys/socket.h HAVE_RECVMMSG_API)

if(HAVE_MMSG_HDR)
    add_definitions(-DHAVE_MMSG_HDR)
endif()
if(HAVE_SENDMMSG_API)
    add_definitions(-DHAVE_SENDMMSG_API)
endif()
if(HAVE_RECVMMSG_API)
    add_definitions(-DHAVE_RECVMMSG_API)
endif()
#使能c++11
set(CMAKE_CXX_STANDARD 11)

find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif(CCACHE_FOUND)

#add_compile_options(-D__STDC_FORMAT_MACROS)
if(CMAKE_COMPILER_IS_GNUCXX)
    add_compile_options(-D__STDC_FORMAT_MACROS)
    message(STATUS "-D__STDC_FORMAT_MACROS")
endif(CMAKE_COMPILER_IS_GNUCXX)

#set(CMAKE_BUILD_TYPE "Release")
if ("${CMAKE_BUILD_TYPE}" STREQUAL "")
    set(CMAKE_BUILD_TYPE "Debug")
endif ()

message(STATUS "编译类型:${CMAKE_BUILD_TYPE}")

#设置bin和lib库目录
set(RELEASE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/release)

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    SET(LIBRARY_OUTPUT_PATH ${RELEASE_DIR}/linux/${CMAKE_BUILD_TYPE})
    SET(EXECUTABLE_OUTPUT_PATH ${RELEASE_DIR}/linux/${CMAKE_BUILD_TYPE})
    add_compile_options(-fPIC -Wall -Wno-unused-variable -Wno-unused-value)
elseif (CMAKE_SYSTEM_NAME MATCHES "Windows")
    if (CMAKE_CL_64)
        set(CL_32_64 64)
    else ()
        set(CL_32_64 32)
    endif ()
    SET(LIBRARY_OUTPUT_PATH ${RELEASE_DIR}/windows${CL_32_64}/${CMAKE_BUILD_TYPE})
    SET(EXECUTABLE_OUTPUT_PATH ${RELEASE_DIR}/windows${CL_32_64}/${CMAKE_BUILD_TYPE})
elseif (CMAKE_SYSTEM_NAME MATCHES "Darwin")
    SET(LIBRARY_OUTPUT_PATH ${RELEASE_DIR}/mac/${CMAKE_BUILD_TYPE})
    SET(EXECUTABLE_OUTPUT_PATH ${RELEASE_DIR}/mac/${CMAKE_BUILD_TYPE})
    add_compile_options(-Wall -Wno-unused-variable -Wno-unused-value)
endif ()

LINK_DIRECTORIES(${LIBRARY_OUTPUT_PATH})

#设置工程源码根目录
set(ToolKit_Root ${CMAKE_CURRENT_SOURCE_DIR}/3rdpart/ZLToolKit/src)
set(SRT_Root ${CMAKE_CURRENT_SOURCE_DIR}/src )

#设置头文件目录
INCLUDE_DIRECTORIES(${ToolKit_Root})
INCLUDE_DIRECTORIES(${SRT_Root})
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/3rdpart)


option(ENABLE_OPENSSL "Enable OpenSSL" true)
option(ENABLE_CXX_API "Enable C++ API SDK" false)
option(ENABLE_ASAN "Enable Address Sanitize" false)
option(ENABLE_MSVC_MT "Enable MSVC Mt/Mtd lib" true)
option(USE_SOLUTION_FOLDERS "Enable solution dir supported" ON)


if (MSVC AND ENABLE_MSVC_MT)
    set(CompilerFlags
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE
        )
    foreach(CompilerFlag ${CompilerFlags})
        string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
    endforeach()
endif()


if (ENABLE_ASAN)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    message(STATUS "已启用Address Sanitize")
endif ()

set(LINK_LIB_LIST zltoolkit srt)

#默认链接jemalloc库避免内存碎片
find_package(JEMALLOC QUIET)
if (JEMALLOC_FOUND)
    message(STATUS "found library:\"${JEMALLOC_LIBRARIES}\"")
    include_directories(${JEMALLOC_INCLUDE_DIR})
    list(APPEND LINK_LIB_LIST ${JEMALLOC_LIBRARIES})
endif ()

#查找openssl是否安装
find_package(OpenSSL QUIET)
if (OPENSSL_FOUND AND ENABLE_OPENSSL)
    message(STATUS "found library:${OPENSSL_LIBRARIES},ENABLE_OPENSSL defined")
    include_directories(${OPENSSL_INCLUDE_DIR})
    add_definitions(-DENABLE_OPENSSL)
    list(APPEND LINK_LIB_LIST ${OPENSSL_LIBRARIES})
    if (CMAKE_SYSTEM_NAME MATCHES "Linux" AND OPENSSL_USE_STATIC_LIBS)
        list(APPEND LINK_LIB_LIST dl)
    endif ()
else ()
    set(ENABLE_OPENSSL off)
    message(WARNING "openssl未找到，rtmp将不支持flash播放器，https/wss/rtsps/rtmps也将失效")
endif ()


#set(VS_FALGS "/wd4819 /wd4996 /wd4018 /wd4267 /wd4244 /wd4101 /wd4828 /wd4309 /wd4573 /wd4996" )
set(VS_FALGS "/wd4819")

#收集源代码
file(GLOB ToolKit_src_list ${ToolKit_Root}/*/*.cpp ${ToolKit_Root}/*/*.h ${ToolKit_Root}/*/*.c)
file(GLOB SRT_src_list ${SRT_Root}/*.cpp ${SRT_Root}/*.hpp)

#去除win32的适配代码
if (NOT WIN32)
    list(REMOVE_ITEM ToolKit_src_list ${ToolKit_Root}/win32/getopt.c)
else ()
    #防止Windows.h包含Winsock.h
    add_definitions(-DWIN32_LEAN_AND_MEAN -DMP4V2_NO_STDINT_DEFS -D_CRT_SECURE_NO_WARNINGS -D_WINSOCK_DEPRECATED_NO_WARNINGS)
endif ()

#添加库
add_library(zltoolkit STATIC ${ToolKit_src_list})
add_library(srt STATIC ${SRT_src_list})

list(APPEND CXX_API_TARGETS zltoolkit srt)

#安装目录
if (WIN32)
    set(INSTALL_PATH_LIB $ENV{HOME}/${CMAKE_PROJECT_NAME}/lib)
    set(INSTALL_PATH_INCLUDE $ENV{HOME}/${CMAKE_PROJECT_NAME}/include)
else ()
    set(INSTALL_PATH_LIB lib${LIB_SUFFIX})
    set(INSTALL_PATH_INCLUDE include)
    set(INSTALL_PATH_EXECUTABLE bin)
endif ()

if (ENABLE_CXX_API)
    # 保留目录结构
    install(DIRECTORY ${ToolKit_Root}/ DESTINATION ${INSTALL_PATH_INCLUDE}/ZLToolKit REGEX "(.*[.](md|cpp)|win32)$" EXCLUDE)
    install(DIRECTORY ${SRT_Root}/ DESTINATION ${INSTALL_PATH_INCLUDE}/srt REGEX ".*[.](md|cpp)$" EXCLUDE)
    install(TARGETS ${CXX_API_TARGETS} DESTINATION ${INSTALL_PATH_LIB})
endif ()

if (WIN32)
    list(APPEND LINK_LIB_LIST WS2_32 Iphlpapi shlwapi)
    if (MSVC)
        set_target_properties(zltoolkit PROPERTIES COMPILE_FLAGS ${VS_FALGS})
        set_target_properties(srt PROPERTIES COMPILE_FLAGS ${VS_FALGS})
    endif ()
elseif (NOT ANDROID OR IOS)
    list(APPEND LINK_LIB_LIST pthread)
endif ()


#测试服务器
add_executable(srtServer main.cpp)
target_link_libraries(srtServer -Wl,--start-group ${LINK_LIB_LIST} -Wl,--end-group)