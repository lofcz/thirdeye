if(NOT DEFINED BINARY OR NOT EXISTS "${BINARY}")
    message(FATAL_ERROR "BINARY not set or missing: ${BINARY}")
endif()

execute_process(
    COMMAND python "${PATCH_SCRIPT}" "${BINARY}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error
)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "patch_toolchain.py failed: ${error}")
endif()
