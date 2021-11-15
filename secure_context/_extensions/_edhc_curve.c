#define PY_SSIZE_T_CLEAN
#define Py_LIMITED_API 0x03060000

#include <Python.h>
#include <openssl/ssl.h>

// This partial definition is, at least, 12 years old according to git blame
// https://github.com/python/cpython/blame/cfc9154121e2d677b782cfadfc90b949b1259332/Modules/_ssl.c#L278-L280
typedef struct {
  PyObject_HEAD;
  SSL_CTX* ctx;
} PySSLContext;

/**
 * Courtesy of https://github.com/sruester
 * Original:
 *  https://github.com/python/cpython/pull/5771
 * Licensed under:
 *  Python Software Foundation License Version 2
 * (https://github.com/python/cpython/blob/main/LICENSE)
 */
static PyObject* _ssl__SSLContext_set_ecdh_curve(PyObject* self,
                                                 PyObject* args) {
  PyObject* name;
  PySSLContext* ssl;

  if (!PyArg_ParseTuple(args, "OO&", &ssl, &PyUnicode_FSConverter, &name)) {
    PyErr_SetString(PyExc_ValueError, "Invalid parameters");
    return NULL;
  }

  if (SSL_CTX_set1_curves_list(ssl->ctx, PyBytes_AsString(name))) {
    Py_DECREF(name);
    Py_RETURN_NONE;
  }

  Py_DECREF(name);
  return PyErr_Format(PyExc_ValueError, "invalid elliptic curves list %s",
                      name);
}

static PyMethodDef edhc_curve_methods[] = {
    {"set_ecdh_curve", (PyCFunction)_ssl__SSLContext_set_ecdh_curve,
     METH_VARARGS, PyDoc_STR("Register ECDH curve selection in ssl context.")},
    {NULL, NULL} /* Sentinel */
};

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
  PyObject* module;

  module = PyModule_Create(&moduledef);

  if (module == NULL) return NULL;

  return module;
}
