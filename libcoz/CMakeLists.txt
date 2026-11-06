if(WIN32)
set(sources
    ${PROJECT_SOURCE_DIR}/include/coz.h
    coz.def
    inspect.cpp
    inspect.h
    inspect_pdb.cpp
    libcoz.cpp
    perf.h
    perf_win.cpp
    perf_win.h
    profiler.cpp
    profiler.h
    progress_point.h
    thread_state.h
    util.h
    win_hooks.cpp
    win_hooks.h
    )
else()
set(sources
    ${PROJECT_SOURCE_DIR}/include/coz.h
    inspect.cpp
    inspect.h
    lief_loader.cpp
    lief_loader.h
    libcoz.cpp
    perf.cpp
    perf.h
    profiler.cpp
    profiler.h
    progress_point.h
    real.cpp
    real.h
    thread_state.h
    util.h
    )
endif()

# Add macOS-specific files on Apple platforms
if(APPLE)
    list(APPEND sources
        perf_macos.cpp
        perf_macos.h
        mac_interpose.cpp
        mac_interpose.h
    )
endif()

if(APPLE)
    # On macOS, use SHARED to create a dylib that can be injected with DYLD_INSERT_LIBRARIES
    add_library(coz SHARED ${sources} ${public_headers})
    set_target_properties(coz PROPERTIES SUFFIX ".so")
else()
    # On Linux, use MODULE for LD_PRELOAD
    add_library(coz MODULE ${sources} ${public_headers})
endif()
if(CONAN_PACKAGE_VERSION)
    set_target_properties(coz PROPERTIES VERSION ${CONAN_PACKAGE_VERSION})
endif()
target_include_directories(coz
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)
# Go's linker and GNU ld emit zlib-compressed DWARF; lief_loader inflates it.
if(NOT WIN32)
    find_package(ZLIB REQUIRED)
endif()

# Platform-specific libraries
if(WIN32)
    target_link_libraries(coz PRIVATE detours dbghelp)
    # NOMINMAX: windows.h would otherwise break std::min/std::max
    target_compile_definitions(coz PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
    target_compile_options(coz PRIVATE /Z7)

    # Launches the profiled program with coz.dll injected
    add_executable(coz-launch ../tools/coz-launch.cpp)
    target_link_libraries(coz-launch PRIVATE detours)
elseif(APPLE)
    target_link_libraries(coz PRIVATE ZLIB::ZLIB ${CMAKE_DL_LIBS} Threads::Threads libelfin::libelfin LIEF::LIEF)
else()
    target_link_libraries(coz PRIVATE ZLIB::ZLIB ${CMAKE_DL_LIBS} rt Threads::Threads libelfin::libelfin LIEF::LIEF)
endif()

add_library(coz-instrumentation INTERFACE)
target_include_directories(coz-instrumentation
    INTERFACE
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

# Platform-specific linker flags
if(APPLE)
    target_link_libraries(coz-instrumentation INTERFACE ${CMAKE_DL_LIBS})
elseif(NOT WIN32)
    target_link_libraries(coz-instrumentation INTERFACE -Wl,--push-state,--no-as-needed ${CMAKE_DL_LIBS} -Wl,--pop-state)
endif()

if(INSTALL_COZ)
    install(TARGETS coz
        EXPORT coz-profilerTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/. DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif()
