#ifndef NEOC_INVOCATION_RESULT_H
#define NEOC_INVOCATION_RESULT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "neoc/protocol/stack_item.h"
#include "notification.h"
#include "diagnostics.h"

#ifdef __cplusplus
extern "C" {
#endif

// VM State enumeration
typedef enum {
    NEO_VM_STATE_NONE = 0x00,
    NEO_VM_STATE_HALT = 0x01,
    NEO_VM_STATE_FAULT = 0x02,
    NEO_VM_STATE_BREAK = 0x04
} neoc_vm_state_t;

// Invocation result structure
typedef struct neoc_invocation_result {
    char* script;                           // Script hash
    neoc_vm_state_t state;                  // VM execution state
    uint64_t gas_consumed;                  // GAS consumed
    char* exception;                        // Exception message (if any)
    neoc_stack_item_t** stack;              // Result stack
    size_t stack_count;                     // Stack items count
    neoc_notification_t** notifications;    // Notifications
    size_t notifications_count;             // Notifications count
    neoc_diagnostics_t* diagnostics;        // Diagnostics info
    char* session_id;                        // Session ID
    char** storage_changes;                  // Storage changes
    size_t storage_changes_count;           // Storage changes count
} neoc_invocation_result_t;

// Create invocation result
neoc_invocation_result_t* neoc_invocation_result_create(void);

// Free invocation result
void neoc_invocation_result_free(neoc_invocation_result_t* result);

// Clone invocation result
neoc_invocation_result_t* neoc_invocation_result_clone(const neoc_invocation_result_t* result);

// Set script
void neoc_invocation_result_set_script(neoc_invocation_result_t* result, const char* script);

// Set state
void neoc_invocation_result_set_state(neoc_invocation_result_t* result, neoc_vm_state_t state);

// Set gas consumed
void neoc_invocation_result_set_gas_consumed(neoc_invocation_result_t* result, uint64_t gas);

// Set exception
void neoc_invocation_result_set_exception(neoc_invocation_result_t* result, const char* exception);

// Add stack item
void neoc_invocation_result_add_stack_item(neoc_invocation_result_t* result, neoc_stack_item_t* item);

// Add notification
void neoc_invocation_result_add_notification(neoc_invocation_result_t* result, neoc_notification_t* notification);

// Parse from JSON
neoc_invocation_result_t* neoc_invocation_result_from_json(const char* json_str);

// Convert to JSON
char* neoc_invocation_result_to_json(const neoc_invocation_result_t* result);

// Check if execution was successful
bool neoc_invocation_result_is_successful(const neoc_invocation_result_t* result);

// Get first stack item (convenience function)
neoc_stack_item_t* neoc_invocation_result_get_first_stack_item(const neoc_invocation_result_t* result);

#ifdef __cplusplus
}
#endif

#endif // NEOC_INVOCATION_RESULT_H
