/**
 * @file neoc_vm_state_type_alt.c
 * @brief Neo VM state type implementation
 */

#include "neoc/types/neoc_vm_state_type.h"
#include "neoc/neoc_memory.h"
#include <string.h>
#include <stdio.h>

int neoc_vm_state_to_int(neoc_vm_state_t state) {
    return (int)state;
}

neoc_error_t neoc_vm_state_from_int(int value, neoc_vm_state_t *state) {
    if (!state) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "State pointer is null");
    }
    
    switch (value) {
        case 0: *state = NEOC_VM_STATE_NONE; break;
        case 1: *state = NEOC_VM_STATE_HALT; break;
        case 2: *state = NEOC_VM_STATE_FAULT; break;
        case 4: *state = NEOC_VM_STATE_BREAK; break;
        default:
            return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, 
                                 "Invalid VM state integer value");
    }
    
    return NEOC_SUCCESS;
}

const char* neoc_vm_state_to_string(neoc_vm_state_t state) {
    switch (state) {
        case NEOC_VM_STATE_NONE:  return "None";
        case NEOC_VM_STATE_HALT:  return "Halt";
        case NEOC_VM_STATE_FAULT: return "Fault";
        case NEOC_VM_STATE_BREAK: return "Break";
        default:                  return "Unknown";
    }
}

neoc_error_t neoc_vm_state_from_string(const char *str, neoc_vm_state_t *state) {
    if (!str || !state) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (strcmp(str, "None") == 0 || strlen(str) == 0) {
        *state = NEOC_VM_STATE_NONE;
    } else if (strcmp(str, "Halt") == 0) {
        *state = NEOC_VM_STATE_HALT;
    } else if (strcmp(str, "Fault") == 0) {
        *state = NEOC_VM_STATE_FAULT;
    } else if (strcmp(str, "Break") == 0) {
        *state = NEOC_VM_STATE_BREAK;
    } else {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, 
                             "Unknown VM state string");
    }
    
    return NEOC_SUCCESS;
}

const char* neoc_vm_state_to_json_value(neoc_vm_state_t state) {
    switch (state) {
        case NEOC_VM_STATE_NONE:  return "NONE";
        case NEOC_VM_STATE_HALT:  return "HALT";
        case NEOC_VM_STATE_FAULT: return "FAULT";
        case NEOC_VM_STATE_BREAK: return "BREAK";
        default:                  return "NONE";
    }
}

neoc_error_t neoc_vm_state_from_json_value(const char *json_value, neoc_vm_state_t *state) {
    if (!json_value || !state) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (strcmp(json_value, "NONE") == 0 || strlen(json_value) == 0) {
        *state = NEOC_VM_STATE_NONE;
    } else if (strcmp(json_value, "HALT") == 0) {
        *state = NEOC_VM_STATE_HALT;
    } else if (strcmp(json_value, "FAULT") == 0) {
        *state = NEOC_VM_STATE_FAULT;
    } else if (strcmp(json_value, "BREAK") == 0) {
        *state = NEOC_VM_STATE_BREAK;
    } else {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, 
                             "Unknown VM state JSON value");
    }
    
    return NEOC_SUCCESS;
}

bool neoc_vm_state_is_successful(neoc_vm_state_t state) {
    return state == NEOC_VM_STATE_HALT;
}

bool neoc_vm_state_is_error(neoc_vm_state_t state) {
    return state == NEOC_VM_STATE_FAULT;
}
