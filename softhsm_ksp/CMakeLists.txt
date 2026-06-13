cmake_minimum_required(VERSION 3.20)
project(softhsm_ksp C)

set(CMAKE_C_STANDARD 11)

# Avertissements MSVC niveau /W3 sans erreurs parasites
if(MSVC)
    add_compile_options(/W3 /WX)
    # Désactive les avertissements de sécurité CRT (on utilise les variantes _s)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS=1)
    add_compile_definitions(WIN32_LEAN_AND_MEAN=1)
    add_compile_definitions(UNICODE=1 _UNICODE=1)
endif()

# Sources du KSP
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

# DLL principale
add_library(softhsm_ksp SHARED
    ${KSP_SOURCES}
    softhsm_ksp.def
)

target_include_directories(softhsm_ksp PRIVATE
    src/pkcs11
    src/ksp
    src/common
)

# Liens vers les bibliothèques CNG Windows
# softhsm2.dll est chargé dynamiquement (LoadLibrary), pas de lien statique
target_link_libraries(softhsm_ksp PRIVATE
    ncrypt
    bcrypt
)

# ── Tests unitaires couche PKCS#11 ──────────────────────────────────────────
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

# ── Tests d'intégration KSP ─────────────────────────────────────────────────
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

# Installation (optionnelle)
install(TARGETS softhsm_ksp
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)
