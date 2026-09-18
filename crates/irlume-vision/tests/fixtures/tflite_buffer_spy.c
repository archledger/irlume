/* SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
 * Test-only forwarding shim. All inference still runs in the real library.
 */
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct TfLiteModel TfLiteModel;
typedef struct TfLiteInterpreter TfLiteInterpreter;

static uintptr_t model_pointer;
static size_t model_length;
static size_t model_creations;
static size_t event_number;
static size_t interpreter_deleted;
static size_t model_deleted;

static void *resolve(const char *name) {
    static void *library;
    if (!library) library = dlopen(IRLUME_REAL_TFLITE, RTLD_NOW | RTLD_LOCAL);
    if (!library) abort();
    void *symbol = dlsym(library, name);
    if (!symbol) abort();
    return symbol;
}

TfLiteModel *TfLiteModelCreate(const void *bytes, size_t length) {
    typedef TfLiteModel *(*create_fn)(const void *, size_t);
    model_pointer = (uintptr_t)bytes;
    model_length = length;
    model_creations++;
    return ((create_fn)resolve("TfLiteModelCreate"))(bytes, length);
}

void TfLiteInterpreterDelete(TfLiteInterpreter *interpreter) {
    typedef void (*delete_fn)(TfLiteInterpreter *);
    ((delete_fn)resolve("TfLiteInterpreterDelete"))(interpreter);
    interpreter_deleted = ++event_number;
}

void TfLiteModelDelete(TfLiteModel *model) {
    typedef void (*delete_fn)(TfLiteModel *);
    model_deleted = ++event_number;
    ((delete_fn)resolve("TfLiteModelDelete"))(model);
}

uintptr_t irlume_test_model_pointer(void) { return model_pointer; }
size_t irlume_test_model_length(void) { return model_length; }
size_t irlume_test_model_creations(void) { return model_creations; }
size_t irlume_test_interpreter_deleted(void) { return interpreter_deleted; }
size_t irlume_test_model_deleted(void) { return model_deleted; }
