#include "neoc/protocol/core/response/diagnostics.h"
#include "neoc/utils/json.h"
#include "neoc/utils/neoc_hex.h"
#include <string.h>

neoc_error_t neoc_invoked_contract_create(
    const neoc_hash160_t *hash,
    const neoc_invoked_contract_t *invoked_contracts,
    size_t invoked_contracts_count,
    neoc_invoked_contract_t **contract) {
    if (!hash || !contract) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid invoked contract arguments");
    }
    *contract = NULL;

    neoc_invoked_contract_t *obj = neoc_calloc(1, sizeof(neoc_invoked_contract_t));
    if (!obj) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate invoked contract");
    }

    obj->hash = neoc_calloc(1, sizeof(neoc_hash160_t));
    if (!obj->hash) {
        neoc_invoked_contract_free(obj);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate contract hash");
    }
    memcpy(obj->hash, hash, sizeof(neoc_hash160_t));

    if (invoked_contracts_count > 0 && invoked_contracts) {
        obj->invoked_contracts = neoc_calloc(invoked_contracts_count, sizeof(neoc_invoked_contract_t));
        if (!obj->invoked_contracts) {
            neoc_invoked_contract_free(obj);
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate nested contracts");
        }
        for (size_t i = 0; i < invoked_contracts_count; ++i) {
            neoc_invoked_contract_t *tmp = NULL;
            neoc_error_t err = neoc_invoked_contract_copy(&invoked_contracts[i], &tmp);
            if (err != NEOC_SUCCESS) {
                obj->invoked_contracts_count = i;
                neoc_invoked_contract_free(obj);
                return err;
            }
            obj->invoked_contracts[i] = *tmp;
            neoc_free(tmp);
        }
        obj->invoked_contracts_count = invoked_contracts_count;
    }

    *contract = obj;
    return NEOC_SUCCESS;
}

void neoc_invoked_contract_free(
    neoc_invoked_contract_t *contract) {
    if (!contract) {
        return;
    }
    if (contract->hash) {
        neoc_free(contract->hash);
    }
    if (contract->invoked_contracts) {
        for (size_t i = 0; i < contract->invoked_contracts_count; ++i) {
            neoc_invoked_contract_free(&contract->invoked_contracts[i]);
        }
        neoc_free(contract->invoked_contracts);
    }
    memset(contract, 0, sizeof(*contract));
}

neoc_error_t neoc_invoked_contract_copy(
    const neoc_invoked_contract_t *src,
    neoc_invoked_contract_t **dest) {
    if (!src || !dest) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid contract copy arguments");
    }
    *dest = NULL;

    neoc_invoked_contract_t *copy = neoc_calloc(1, sizeof(neoc_invoked_contract_t));
    if (!copy) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate contract copy");
    }

    if (src->hash) {
        copy->hash = neoc_calloc(1, sizeof(neoc_hash160_t));
        if (!copy->hash) {
            neoc_invoked_contract_free(copy);
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to copy hash");
        }
        memcpy(copy->hash, src->hash, sizeof(neoc_hash160_t));
    }

    if (src->invoked_contracts && src->invoked_contracts_count > 0) {
        copy->invoked_contracts = neoc_calloc(src->invoked_contracts_count, sizeof(neoc_invoked_contract_t));
        if (!copy->invoked_contracts) {
            neoc_invoked_contract_free(copy);
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to copy nested contracts");
        }
        for (size_t i = 0; i < src->invoked_contracts_count; ++i) {
            neoc_invoked_contract_t *tmp = NULL;
            neoc_error_t err = neoc_invoked_contract_copy(&src->invoked_contracts[i], &tmp);
            if (err != NEOC_SUCCESS) {
                copy->invoked_contracts_count = i;
                neoc_invoked_contract_free(copy);
                return err;
            }
            copy->invoked_contracts[i] = *tmp;
            neoc_free(tmp);
        }
        copy->invoked_contracts_count = src->invoked_contracts_count;
    }

    *dest = copy;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_storage_change_create(
    const char *state,
    const char *key,
    const char *value,
    neoc_storage_change_t **change) {
    if (!change || !state || !key || !value) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid storage change arguments");
    }
    *change = NULL;

    neoc_storage_change_t *obj = neoc_calloc(1, sizeof(neoc_storage_change_t));
    if (!obj) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate storage change");
    }

    obj->state = neoc_strdup(state);
    obj->key = neoc_strdup(key);
    obj->value = neoc_strdup(value);
    if (!obj->state || !obj->key || !obj->value) {
        neoc_storage_change_free(obj);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate storage change fields");
    }

    *change = obj;
    return NEOC_SUCCESS;
}

void neoc_storage_change_free(
    neoc_storage_change_t *change) {
    if (!change) {
        return;
    }
    neoc_free(change->state);
    neoc_free(change->key);
    neoc_free(change->value);
    neoc_free(change);
}

neoc_error_t neoc_storage_change_copy(
    const neoc_storage_change_t *src,
    neoc_storage_change_t **dest) {
    if (!src || !dest) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid storage change copy arguments");
    }
    *dest = NULL;

    return neoc_storage_change_create(src->state ? src->state : "",
                                      src->key ? src->key : "",
                                      src->value ? src->value : "",
                                      dest);
}

neoc_error_t neoc_diagnostics_create(
    const neoc_invoked_contract_t *invoked_contracts,
    const neoc_storage_change_t *storage_changes,
    size_t storage_changes_count,
    neoc_diagnostics_t **diagnostics) {
    if (!diagnostics) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Diagnostics output is NULL");
    }
    *diagnostics = NULL;

    neoc_diagnostics_t *diag = neoc_calloc(1, sizeof(neoc_diagnostics_t));
    if (!diag) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate diagnostics");
    }

    if (invoked_contracts) {
        neoc_error_t err = neoc_invoked_contract_copy(invoked_contracts, &diag->invoked_contracts);
        if (err != NEOC_SUCCESS) {
            neoc_diagnostics_free(diag);
            return err;
        }
    }

    if (storage_changes && storage_changes_count > 0) {
        diag->storage_changes = neoc_calloc(storage_changes_count, sizeof(neoc_storage_change_t));
        if (!diag->storage_changes) {
            neoc_diagnostics_free(diag);
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate storage changes");
        }
        for (size_t i = 0; i < storage_changes_count; ++i) {
            neoc_storage_change_t *tmp = NULL;
            neoc_error_t err = neoc_storage_change_copy(&storage_changes[i], &tmp);
            if (err != NEOC_SUCCESS) {
                diag->storage_changes_count = i;
                neoc_diagnostics_free(diag);
                return err;
            }
            diag->storage_changes[i] = *tmp;
            neoc_free(tmp);
        }
        diag->storage_changes_count = storage_changes_count;
    }

    *diagnostics = diag;
    return NEOC_SUCCESS;
}

void neoc_diagnostics_free(
    neoc_diagnostics_t *diagnostics) {
    if (!diagnostics) {
        return;
    }
    if (diagnostics->invoked_contracts) {
        neoc_invoked_contract_free(diagnostics->invoked_contracts);
        neoc_free(diagnostics->invoked_contracts);
    }
    if (diagnostics->storage_changes) {
        for (size_t i = 0; i < diagnostics->storage_changes_count; ++i) {
            neoc_storage_change_free(&diagnostics->storage_changes[i]);
        }
        neoc_free(diagnostics->storage_changes);
    }
    neoc_free(diagnostics);
}

neoc_diagnostics_t* neoc_diagnostics_clone(const neoc_diagnostics_t *diagnostics) {
    if (!diagnostics) {
        return NULL;
    }

    neoc_diagnostics_t *clone = NULL;
    neoc_error_t err = neoc_diagnostics_create(diagnostics->invoked_contracts,
                                               diagnostics->storage_changes,
                                               diagnostics->storage_changes_count,
                                               &clone);
    if (err != NEOC_SUCCESS) {
        return NULL;
    }
    return clone;
}

#ifdef HAVE_CJSON
static neoc_error_t parse_invoked_contract_json(neoc_json_t *json, neoc_invoked_contract_t **out) {
    if (!json || !out) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid invoked contract JSON");
    }
    const char *hash_str = neoc_json_get_string(json, "hash");
    if (!hash_str) {
        return neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invoked contract missing hash");
    }

    neoc_hash160_t hash = {{0}};
    neoc_error_t err = neoc_hash160_from_string(hash_str, &hash);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    neoc_invoked_contract_t *children = NULL;
    size_t child_count = 0;
    neoc_json_t *invoked_array = neoc_json_get_array(json, "invokedContracts");
    if (invoked_array) {
        child_count = neoc_json_array_size(invoked_array);
        if (child_count > 0) {
            children = neoc_calloc(child_count, sizeof(neoc_invoked_contract_t));
            if (!children) {
                return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate invoked contracts");
            }
            for (size_t i = 0; i < child_count; ++i) {
                neoc_json_t *child_json = neoc_json_array_get(invoked_array, i);
                neoc_invoked_contract_t *child_copy = NULL;
                neoc_error_t child_err = parse_invoked_contract_json(child_json, &child_copy);
                if (child_err != NEOC_SUCCESS) {
                    for (size_t j = 0; j < i; ++j) {
                        neoc_invoked_contract_free(&children[j]);
                    }
                    neoc_free(children);
                    return child_err;
                }
                children[i] = *child_copy;
                neoc_free(child_copy);
            }
        }
    }

    neoc_invoked_contract_t *contract = NULL;
    err = neoc_invoked_contract_create(&hash, children, child_count, &contract);
    if (children) {
        for (size_t i = 0; i < child_count; ++i) {
            neoc_invoked_contract_free(&children[i]);
        }
        neoc_free(children);
    }
    if (err != NEOC_SUCCESS) {
        return err;
    }
    *out = contract;
    return NEOC_SUCCESS;
}
#endif

neoc_error_t neoc_diagnostics_from_json(
    const char *json_str,
    neoc_diagnostics_t **diagnostics) {
    if (!json_str || !diagnostics) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid diagnostics JSON input");
    }
    *diagnostics = NULL;

#ifndef HAVE_CJSON
    return neoc_error_set(NEOC_ERROR_NOT_IMPLEMENTED, "cJSON not available");
#else
    neoc_json_t *root = neoc_json_parse(json_str);
    if (!root) {
        return neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Failed to parse diagnostics JSON");
    }

    neoc_invoked_contract_t *invoked = NULL;
    neoc_json_t *invoked_json = neoc_json_get_object(root, "invokedContracts");
    if (invoked_json) {
        neoc_error_t err = parse_invoked_contract_json(invoked_json, &invoked);
        if (err != NEOC_SUCCESS) {
            neoc_json_free(root);
            return err;
        }
    }

    neoc_storage_change_t *changes = NULL;
    size_t change_count = 0;
    neoc_json_t *changes_array = neoc_json_get_array(root, "storageChanges");
    if (changes_array) {
        change_count = neoc_json_array_size(changes_array);
        if (change_count > 0) {
            changes = neoc_calloc(change_count, sizeof(neoc_storage_change_t));
            if (!changes) {
                neoc_invoked_contract_free(invoked);
                neoc_free(invoked);
                neoc_json_free(root);
                return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate storage changes");
            }
            for (size_t i = 0; i < change_count; ++i) {
                neoc_json_t *change_json = neoc_json_array_get(changes_array, i);
                const char *state = neoc_json_get_string(change_json, "state");
                const char *key = neoc_json_get_string(change_json, "key");
                const char *value = neoc_json_get_string(change_json, "value");
                neoc_storage_change_t *tmp = NULL;
                neoc_error_t err = neoc_storage_change_create(state ? state : "",
                                                              key ? key : "",
                                                              value ? value : "",
                                                              &tmp);
                if (err != NEOC_SUCCESS) {
                    for (size_t j = 0; j < i; ++j) {
                        neoc_storage_change_free(&changes[j]);
                    }
                    neoc_free(changes);
                    neoc_invoked_contract_free(invoked);
                    neoc_free(invoked);
                    neoc_json_free(root);
                    return err;
                }
                changes[i] = *tmp;
                neoc_free(tmp);
            }
        }
    }

    neoc_error_t err = neoc_diagnostics_create(invoked, changes, change_count, diagnostics);
    if (invoked) {
        neoc_invoked_contract_free(invoked);
        neoc_free(invoked);
    }
    if (changes) {
        for (size_t i = 0; i < change_count; ++i) {
            neoc_storage_change_free(&changes[i]);
        }
        neoc_free(changes);
    }
    neoc_json_free(root);
    return err;
#endif
}

neoc_error_t neoc_diagnostics_to_json(
    const neoc_diagnostics_t *diagnostics,
    char **json_str) {
    if (!diagnostics || !json_str) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid diagnostics object");
    }
    *json_str = NULL;

#ifndef HAVE_CJSON
    return neoc_error_set(NEOC_ERROR_NOT_IMPLEMENTED, "cJSON not available");
#else
    neoc_json_t *root = neoc_json_create_object();
    if (!root) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate diagnostics JSON");
    }

    if (diagnostics->invoked_contracts) {
        char hash_hex[NEOC_HASH160_STRING_LENGTH] = {0};
        if (diagnostics->invoked_contracts->hash &&
            neoc_hash160_to_hex(diagnostics->invoked_contracts->hash,
                                hash_hex, sizeof(hash_hex), false) == NEOC_SUCCESS) {
            neoc_json_t *invoked_root = neoc_json_create_object();
            if (!invoked_root) {
                neoc_json_free(root);
                return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate invoked contract JSON");
            }
            char prefixed[NEOC_HASH160_STRING_LENGTH + 3];
            snprintf(prefixed, sizeof(prefixed), "0x%s", hash_hex);
            neoc_json_add_string(invoked_root, "hash", prefixed);
            neoc_json_add_object(root, "invokedContracts", invoked_root);
        }
    }

    if (diagnostics->storage_changes && diagnostics->storage_changes_count > 0) {
        neoc_json_t *array = neoc_json_create_array();
        if (!array) {
            neoc_json_free(root);
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate storage change array");
        }
        for (size_t i = 0; i < diagnostics->storage_changes_count; ++i) {
            const neoc_storage_change_t *chg = &diagnostics->storage_changes[i];
            neoc_json_t *obj = neoc_json_create_object();
            if (!obj) {
                neoc_json_free(array);
                neoc_json_free(root);
                return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate storage change object");
            }
            neoc_json_add_string(obj, "state", chg->state ? chg->state : "");
            neoc_json_add_string(obj, "key", chg->key ? chg->key : "");
            neoc_json_add_string(obj, "value", chg->value ? chg->value : "");
            neoc_json_array_add(array, obj);
        }
        neoc_json_add_object(root, "storageChanges", array);
    }

    char *serialized = neoc_json_to_string(root);
    neoc_json_free(root);
    if (!serialized) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to serialize diagnostics JSON");
    }
    *json_str = serialized;
    return NEOC_SUCCESS;
#endif
}

size_t neoc_invoked_contract_get_total_count(
    const neoc_invoked_contract_t *contract) {
    if (!contract) return 0;
    size_t count = 1;
    for (size_t i = 0; i < contract->invoked_contracts_count; ++i) {
        count += neoc_invoked_contract_get_total_count(&contract->invoked_contracts[i]);
    }
    return count;
}

bool neoc_invoked_contract_was_invoked(
    const neoc_invoked_contract_t *contract,
    const neoc_hash160_t *hash) {
    if (!contract || !hash) {
        return false;
    }
    if (contract->hash && memcmp(contract->hash, hash, sizeof(neoc_hash160_t)) == 0) {
        return true;
    }
    for (size_t i = 0; i < contract->invoked_contracts_count; ++i) {
        if (neoc_invoked_contract_was_invoked(&contract->invoked_contracts[i], hash)) {
            return true;
        }
    }
    return false;
}
