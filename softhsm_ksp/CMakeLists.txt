cmake_minimum_required(VERSION 3.20)
project(softhsm_ksp C)

set(CMAKE_C_STANDARD 11)

# Optional: path to a SoftHSM2 2.7.0 installation built from source.
# If provided, the install-time DLL path is embedded as the compile-time default.
# Example: cmake .. -DSOFTHSM2_DIR=C:/path/to/softhsm2-install
set(SOFTHSM2_DIR "" CACHE PATH "SoftHSM2 2.7.0 install directory (optional)")

if(SOFTHSM2_DIR)
    # Locate the built DLL under the install tree
    file(GLOB_RECURSE _hsm_dll LIST_DIRECTORIES false
         "${SOFTHSM2_DIR}/*softhsm2*.dll"
         "${SOFTHSM2_DIR}/*softhsm2*.so")
    if(_hsm_dll)
        list(GET _hsm_dll 0 _hsm_dll_path)
        # Normalise path separators for the C string literal
        string(REPLACE "/" "\\\\" _hsm_dll_escaped "${_hsm_dll_path}")
        message(STATUS "SoftHSM2 DLL: ${_hsm_dll_path}")
        add_compile_definitions(SOFTHSM2_LIB_DEFAULT_OVERRIDE="${_hsm_dll_escaped}")
    else()
        message(WARNING "SOFTHSM2_DIR set but no softhsm2 DLL found under ${SOFTHSM2_DIR}")
    endif()
endif()

# ncrypt_provider.h declares NCRYPT_KEY_STORAGE_FUNCTION_TABLE and is needed
# only by ksp_main.c. It is NOT in the Windows SDK, and installing the WDK on
# a clean windows-latest runner did not supply it either. It is associated
# with the Cryptographic Provider Development Kit, but that is unconfirmed —
# so rather than hardcode a guess, point this at wherever your copy lives.
# Example: cmake .. -DCPDK_INCLUDE_DIR="C:/.../Cryptographic Provider Development Kit/Include/um"
set(CPDK_INCLUDE_DIR "" CACHE PATH
    "Directory containing ncrypt_provider.h")

if(WIN32)
    # Fail at configure time with an explanation, rather than a hundred lines
    # into the build with a bare C1083 on a header most people have never
    # heard of.
    # No speculative PATHS here. Two guesses at where this header lives have
    # already been wrong, so the search is CPDK_INCLUDE_DIR plus whatever the
    # compiler's own include path provides — nothing invented.
    find_file(NCRYPT_PROVIDER_H ncrypt_provider.h
        HINTS "${CPDK_INCLUDE_DIR}"
        DOC "ncrypt_provider.h - declares NCRYPT_KEY_STORAGE_FUNCTION_TABLE")

    if(NCRYPT_PROVIDER_H)
        get_filename_component(_npdir "${NCRYPT_PROVIDER_H}" DIRECTORY)
        message(STATUS "ncrypt_provider.h: ${NCRYPT_PROVIDER_H}")
        include_directories("${_npdir}")
    else()
        message(FATAL_ERROR
            "\n"
            "ncrypt_provider.h was not found.\n"
            "\n"
            "It declares NCRYPT_KEY_STORAGE_FUNCTION_TABLE, the CNG function\n"
            "table this provider exports, and only src/ksp/ksp_main.c needs\n"
            "it. The other nine source files build without it.\n"
            "\n"
            "It is NOT part of the Windows SDK, and installing the Windows\n"
            "Driver Kit does not supply it either — both verified on a clean\n"
            "windows-latest runner. If you have a copy, point the build at\n"
            "the directory holding it:\n"
            "\n"
            "    cmake .. -A x64 -DCPDK_INCLUDE_DIR=<directory>\n")
    endif()
endif()

# MSVC: /W3 warning level, treat warnings as errors
if(MSVC)
    add_compile_options(/W3 /WX)
    # Suppress secure CRT warnings (we use _s variants throughout)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS=1)
    add_compile_definitions(WIN32_LEAN_AND_MEAN=1)
    add_compile_definitions(UNICODE=1 _UNICODE=1)
endif()

# KSP source files
set(KSP_SOURCES
    src/pkcs11/p11_context.c
    src/pkcs11/p11_session.c
    src/pkcs11/p11_utils.c
    src/ksp/ksp_main.c
    src/ksp/ksp_provider.c
    src/ksp/ksp_key.c
    src/ksp/ksp_crypto.c
    src/ksp/ksp_properties.c
    src/common/logging.c
    src/common/memory.c
)

# Main KSP DLL
add_library(softhsm_ksp SHARED
    ${KSP_SOURCES}
    softhsm_ksp.def
)

target_include_directories(softhsm_ksp PRIVATE
    src/pkcs11
    src/ksp
    src/common
)

# CNG Windows libraries; softhsm2.dll is loaded dynamically (LoadLibrary only)
target_link_libraries(softhsm_ksp PRIVATE
    ncrypt
    bcrypt
)

# ── PKCS#11 layer unit tests ─────────────────────────────────────────────────
add_executable(test_p11_layer
    tests/test_p11_layer.c
    src/pkcs11/p11_context.c
    src/pkcs11/p11_session.c
    src/pkcs11/p11_utils.c
    src/common/logging.c
    src/common/memory.c
)

target_include_directories(test_p11_layer PRIVATE
    src/pkcs11
    src/ksp
    src/common
)

target_link_libraries(test_p11_layer PRIVATE ncrypt bcrypt)

if(MSVC)
    target_compile_options(test_p11_layer PRIVATE /W3 /WX)
    target_compile_definitions(test_p11_layer PRIVATE
        _CRT_SECURE_NO_WARNINGS=1 WIN32_LEAN_AND_MEAN=1 UNICODE=1 _UNICODE=1)
endif()

# ── KSP integration tests (tests 1-14 + HLK scenarios 15-21) ─────────────────
add_executable(test_ksp_integration
    tests/test_ksp_integration.c
    ${KSP_SOURCES}
)

target_include_directories(test_ksp_integration PRIVATE
    src/pkcs11
    src/ksp
    src/common
)

target_link_libraries(test_ksp_integration PRIVATE ncrypt bcrypt)

if(MSVC)
    target_compile_options(test_ksp_integration PRIVATE /W3 /WX)
    target_compile_definitions(test_ksp_integration PRIVATE
        _CRT_SECURE_NO_WARNINGS=1 WIN32_LEAN_AND_MEAN=1 UNICODE=1 _UNICODE=1)
endif()

# Installation (optional)
install(TARGETS softhsm_ksp
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)
