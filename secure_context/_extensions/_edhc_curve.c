#include <Python.h>
#include <openssl/ssl.h>

// This partial definition is 12 years old according to git blame
// https://github.com/python/cpython/blame/cfc9154121e2d677b782cfadfc90b949b1259332/Modules/_ssl.c#L278-L280
typedef struct {
  PyObject_HEAD;
  SSL_CTX *ctx;
} PySSLContext;

/**
 * Courtesy of https://github.com/sruester
 * Original:
 *  https://github.com/python/cpython/pull/5771
 * Licensed under:
 *  Python Software Foundation License Version 2
 * (https://github.com/python/cpython/blob/main/LICENSE)
 */
static PyObject *_ssl__SSLContext_set_ecdh_curve(PySSLContext *self,
                                                 PyObject *name) {
  PyObject *name_bytes;

  if (!PyUnicode_FSConverter(name, &name_bytes)) return NULL;
  assert(PyBytes_Check(name_bytes));

  if (SSL_CTX_set1_curves_list(self->ctx, PyBytes_AS_STRING(name_bytes))) {
    Py_DECREF(name_bytes);
    Py_RETURN_NONE;
  }

  Py_DECREF(name_bytes);
  PyErr_Format(PyExc_ValueError, "invalid elliptic curves list %R", name);
  return NULL;
}

static PyMethodDef edhc_curve_methods[] = {
    {"set_ecdh_curve", (PyCFunction)_ssl__SSLContext_set_ecdh_curve,
     METH_VARARGS, PyDoc_STR("Checks if a year is a leap year.")},
    {NULL}};

/* ---------------------------Module Definition------------------------------ */

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    "_edhc_curve",
    NULL,
    -1,
    edhc_curve_methods,
    NULL,
    NULL,
    NULL,
    NULL,
};

PyMODINIT_FUNC PyInit__edhc_curve(void) {
  PyObject *module;

  module = PyModule_Create(&moduledef);

  if (module == NULL) return NULL;

  return module;
}
