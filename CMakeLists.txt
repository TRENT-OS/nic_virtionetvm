#
# NIC VirtioNetVm driver
#
# Copyright (C) 2023, HENSOLDT Cyber GmbH
#

cmake_minimum_required(VERSION 3.17)


#-------------------------------------------------------------------------------
#
# Declare VirtioNetVm NIC CAmkES Component
#
# Parameters:
#
#   <name>
#       component instance name
#
function(NIC_VirtioNetVm_DeclareCAmkESComponent
    name
)

    DeclareCAmkESComponent(
        ${name}
        SOURCES
            ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/driver.c
        C_FLAGS
            -Wall
            -Werror
        LIBS
            os_core_api
            lib_debug
    )

endfunction()
