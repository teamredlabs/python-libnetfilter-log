#include <Python.h>
#include <structmember.h>

#include <string.h>
#include <sys/time.h>

#include <linux/netfilter.h>
#include <libnetfilter_log/libnetfilter_log.h>

// START: NetfilterLogData

typedef struct {
    PyObject_HEAD
    struct nflog_data* data;
} NetfilterLogData;

static PyObject* NetfilterLogData_new (PyTypeObject* type, PyTupleObject* args) {
    NetfilterLogData* self;
    self = (NetfilterLogData*) type->tp_alloc(type, 0);
    self->data = NULL;
    return (PyObject*) self;
}

static int NetfilterLogData_init (NetfilterLogData* self, PyTupleObject* args) {
    return 0;
}

static void NetfilterLogData_dealloc (NetfilterLogData* self) {
    Py_TYPE(self)->tp_free((PyObject*) self);
}

static PyObject* NetfilterLogData_get_hwtype (NetfilterLogData* self) {
    return PyInt_FromLong((long) nflog_get_hwtype(self->data));
}

static PyObject* NetfilterLogData_get_msg_packet_hwhdr (NetfilterLogData* self) {
    return PyString_FromStringAndSize(nflog_get_msg_packet_hwhdr(self->data), nflog_get_msg_packet_hwhdrlen(self->data));
}

static PyObject* NetfilterLogData_get_packet_hw (NetfilterLogData* self) {
    struct nfulnl_msg_packet_hw* msg_packet_hw = nflog_get_packet_hw(self->data);
    if (msg_packet_hw)
        return PyString_FromStringAndSize((char*) msg_packet_hw->hw_addr, 8);
    Py_RETURN_NONE;
}

static PyObject* NetfilterLogData_get_nfmark (NetfilterLogData* self) {
    return PyInt_FromLong((long) nflog_get_nfmark(self->data));
}

static PyObject* NetfilterLogData_get_timestamp (NetfilterLogData* self) {
    PyLongObject* tv_sec_object;
    PyLongObject* tv_usec_object;
    PyTupleObject* tv_object;
    struct timeval tv;
    if (nflog_get_timestamp(self->data, &tv)) {
        PyErr_SetString(PyExc_OSError, "Call to nflog_get_timestamp failed");
        return NULL;
    }
    tv_sec_object = (PyLongObject*) PyLong_FromLong((long) tv.tv_sec);
    tv_usec_object = (PyLongObject*) PyLong_FromLong((long) tv.tv_usec);
    tv_object = (PyTupleObject*) PyTuple_Pack(2, tv_sec_object, tv_usec_object);
    Py_DECREF(tv_sec_object);
    Py_DECREF(tv_usec_object);
    return (PyObject*) tv_object;
}

static PyObject* NetfilterLogData_get_indev (NetfilterLogData* self) {
    return PyInt_FromLong((long) nflog_get_indev(self->data));
}

static PyObject* NetfilterLogData_get_physindev (NetfilterLogData* self) {
    return PyInt_FromLong((long) nflog_get_physindev(self->data));
}

static PyObject* NetfilterLogData_get_outdev (NetfilterLogData* self) {
    return PyInt_FromLong((long) nflog_get_outdev(self->data));
}

static PyObject* NetfilterLogData_get_physoutdev (NetfilterLogData* self) {
    return PyInt_FromLong((long) nflog_get_physoutdev(self->data));
}

static PyObject* NetfilterLogData_get_payload (NetfilterLogData* self) {
    int length;
    char* data;
    length = nflog_get_payload(self->data, &data);
    if (length < 0) {
        PyErr_SetString(PyExc_OSError, "Call to nflog_get_payload failed");
        return NULL;
    }
    return PyString_FromStringAndSize(data, length);
}

static PyObject* NetfilterLogData_get_prefix (NetfilterLogData* self) {
    return PyString_FromString(nflog_get_prefix(self->data));
}

static PyObject* NetfilterLogData_get_uid (NetfilterLogData* self) {
    uint32_t uid;
    if (nflog_get_uid(self->data, &uid)) {
        PyErr_SetString(PyExc_OSError, "Call to nflog_get_uid failed");
        return NULL;
    }
    return PyInt_FromLong((long) uid);
}

static PyObject* NetfilterLogData_get_gid (NetfilterLogData* self) {
    uint32_t gid;
    if (nflog_get_gid(self->data, &gid)) {
        PyErr_SetString(PyExc_OSError, "Call to nflog_get_gid failed");
        return NULL;
    }
    return PyInt_FromLong((long) gid);
}

static PyObject* NetfilterLogData_get_seq (NetfilterLogData* self) {
    uint32_t seq;
    if (nflog_get_seq(self->data, &seq)) {
        PyErr_SetString(PyExc_OSError, "Call to nflog_get_seq failed");
        return NULL;
    }
    return PyInt_FromLong((long) seq);
}

static PyObject* NetfilterLogData_get_seq_global (NetfilterLogData* self) {
    uint32_t seq;
    if (nflog_get_seq_global(self->data, &seq)) {
        PyErr_SetString(PyExc_OSError, "Call to nflog_get_seq_global failed");
        return NULL;
    }
    return PyInt_FromLong((long) seq);
}

static PyMemberDef NetfilterLogData_members[] = {
    {NULL}
};

static PyMethodDef NetfilterLogData_methods[] = {
    {"get_hwtype", (PyCFunction) NetfilterLogData_get_hwtype, METH_NOARGS, NULL},
    {"get_msg_packet_hwhdr", (PyCFunction) NetfilterLogData_get_msg_packet_hwhdr, METH_NOARGS, NULL},
    {"get_packet_hw", (PyCFunction) NetfilterLogData_get_packet_hw, METH_NOARGS, NULL},
    {"get_nfmark", (PyCFunction) NetfilterLogData_get_nfmark, METH_NOARGS, NULL},
    {"get_timestamp", (PyCFunction) NetfilterLogData_get_timestamp, METH_NOARGS, NULL},
    {"get_indev", (PyCFunction) NetfilterLogData_get_indev, METH_NOARGS, NULL},
    {"get_physindev", (PyCFunction) NetfilterLogData_get_physindev, METH_NOARGS, NULL},
    {"get_outdev", (PyCFunction) NetfilterLogData_get_outdev, METH_NOARGS, NULL},
    {"get_physoutdev", (PyCFunction) NetfilterLogData_get_physoutdev, METH_NOARGS, NULL},
    {"get_payload", (PyCFunction) NetfilterLogData_get_payload, METH_NOARGS, NULL},
    {"get_prefix", (PyCFunction) NetfilterLogData_get_prefix, METH_NOARGS, NULL},
    {"get_uid", (PyCFunction) NetfilterLogData_get_uid, METH_NOARGS, NULL},
    {"get_gid", (PyCFunction) NetfilterLogData_get_gid, METH_NOARGS, NULL},
    {"get_seq", (PyCFunction) NetfilterLogData_get_seq, METH_NOARGS, NULL},
    {"get_seq_global", (PyCFunction) NetfilterLogData_get_seq_global, METH_NOARGS, NULL},
    {NULL}
};

static PyTypeObject NetfilterLogDataType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "libnetfilterlog.NetfilterLogData",       /* tp_name */
    sizeof(NetfilterLogData),                 /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor) NetfilterLogData_dealloc,    /* tp_dealloc */
    0,                                        /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_compare */
    0,                                        /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash */
    0,                                        /* tp_call */
    0,                                        /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    "Wrapper for (struct nflog_data *)",      /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    NetfilterLogData_methods,                 /* tp_methods */
    NetfilterLogData_members,                 /* tp_members */
    0,                                        /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    (initproc) NetfilterLogData_init,         /* tp_init */
    0,                                        /* tp_alloc */
    (newfunc) NetfilterLogData_new,           /* tp_new */
};

// END: NetfilterLogData

// BEGIN: NetfilterLogGroupHandle

typedef struct {
    PyObject_HEAD
    struct nflog_g_handle* group;
    PyObject* callback;
} NetfilterLogGroupHandle;

static PyObject* NetfilterLogGroupHandle_new (PyTypeObject* type, PyTupleObject* args) {
    NetfilterLogGroupHandle* self;
    self = (NetfilterLogGroupHandle*) type->tp_alloc(type, 0);
    self->group = NULL;
    self->callback = NULL;
    return (PyObject*) self;
}

static int NetfilterLogGroupHandle_init (NetfilterLogGroupHandle* self, PyTupleObject* args) {
    return 0;
}

static void NetfilterLogGroupHandle_dealloc (NetfilterLogGroupHandle* self) {
    Py_TYPE(self)->tp_free((PyObject*) self);
}

static int NetfilterLogGroupHandle_callback (struct nflog_g_handle *gh, struct nfgenmsg *nfmsg, struct nflog_data *nfd, void *data) {
    PyObject* args;
    NetfilterLogGroupHandle* self;
    NetfilterLogData* data_object;
    PyObject* result_object;

    self = (NetfilterLogGroupHandle*) data;

    if (self->callback) {
        args = PyTuple_New(0);
        data_object = (NetfilterLogData*) PyObject_CallObject((PyObject*) &NetfilterLogDataType, args);
        Py_DECREF(args);

        data_object->data = nfd;

        args = PyTuple_Pack(1, data_object);
        result_object = PyObject_CallObject(self->callback, args);
        Py_DECREF(args);

        Py_DECREF(data_object);

        if (PyErr_Occurred()) {
            PyErr_PrintEx(1);
            return -1;
        }

        Py_DECREF(result_object);
    }

    return 0;
}

static PyObject* NetfilterLogGroupHandle_set_callback(NetfilterLogGroupHandle* self, PyTupleObject* args) {
    PyObject* callback;
    if (!PyArg_ParseTuple((PyObject*) args, "O", &callback)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (function callback)");
        return NULL;
    }
    if (!PyCallable_Check(callback)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (function callback)");
        return NULL;
    }
    if (self->callback) {
        PyErr_SetString(PyExc_ValueError, "Group callback already set");
        return NULL;
    }
    self->callback = callback;
    Py_INCREF(callback);
    if (nflog_callback_register(self->group, &NetfilterLogGroupHandle_callback, self)) {
        Py_DECREF(callback);
        self->callback = NULL;
        PyErr_SetString(PyExc_OSError, "Call to nflog_callback_register failed");
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject* NetfilterLogGroupHandle_set_mode (NetfilterLogGroupHandle* self, PyTupleObject* args) {
    uint8_t mode;
    uint32_t range;
    if (!PyArg_ParseTuple((PyObject*) args, "bI", &mode, &range)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (uint8_t mode, uint32_t range)");
        return NULL;
    }
    if (nflog_set_mode(self->group, mode, range)) {
        PyErr_SetString(PyExc_OSError, "Call to nflog_set_mode failed");
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject* NetfilterLogGroupHandle_set_timeout (NetfilterLogGroupHandle* self, PyTupleObject* args) {
    uint32_t timeout;
    if (!PyArg_ParseTuple((PyObject*) args, "I", &timeout)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (uint32_t timeout)");
        return NULL;
    }
    if (nflog_set_timeout(self->group, timeout)) {
        PyErr_SetString(PyExc_OSError, "Call to nflog_set_timeout failed");
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject* NetfilterLogGroupHandle_set_qthresh (NetfilterLogGroupHandle* self, PyTupleObject* args) {
    uint32_t qthresh;
    if (!PyArg_ParseTuple((PyObject*) args, "I", &qthresh)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (uint32_t qthresh)");
        return NULL;
    }
    if (nflog_set_qthresh(self->group, qthresh)) {
        PyErr_SetString(PyExc_OSError, "Call to nflog_set_qthresh failed");
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject* NetfilterLogGroupHandle_set_nlbufsiz (NetfilterLogGroupHandle* self, PyTupleObject* args) {
    uint32_t nlbufsiz;
    if (!PyArg_ParseTuple((PyObject*) args, "I", &nlbufsiz)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (uint32_t nlbufsiz)");
        return NULL;
    }
    if (nflog_set_nlbufsiz(self->group, nlbufsiz)) {
        PyErr_SetString(PyExc_OSError, "Call to nflog_set_nlbufsiz failed");
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *NetfilterLogGroupHandle_set_flags (NetfilterLogGroupHandle* self, PyTupleObject* args) {
    uint16_t flags;
    if (!PyArg_ParseTuple((PyObject*) args, "H", &flags)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (uint32_t flags)");
        return NULL;
    }
    if (nflog_set_flags(self->group, flags)) {
        PyErr_SetString(PyExc_OSError, "Call to nflog_set_flags failed");
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject* NetfilterLogGroupHandle_unbind (NetfilterLogGroupHandle* self) {
    if (self->group == NULL) {
        PyErr_SetString(PyExc_ValueError, "Group handle pointer not initialized");
        return NULL;
    }
    if (nflog_unbind_group(self->group)) {
        PyErr_SetString(PyExc_OSError, "Call to nflog_unbind_group failed");
        return NULL;
    }
    self->group = NULL;
    if (self->callback) {
        Py_DECREF(self->callback);
        self->callback = NULL;
    }
    Py_RETURN_NONE;
}

static PyMemberDef NetfilterLogGroupHandle_members[] = {
    {NULL}
};

static PyMethodDef NetfilterLogGroupHandle_methods[] = {
    {"set_callback", (PyCFunction) NetfilterLogGroupHandle_set_callback, METH_VARARGS, NULL},
    {"set_mode", (PyCFunction) NetfilterLogGroupHandle_set_mode, METH_VARARGS, NULL},
    {"set_timeout", (PyCFunction) NetfilterLogGroupHandle_set_timeout, METH_VARARGS, NULL},
    {"set_qthresh", (PyCFunction) NetfilterLogGroupHandle_set_qthresh, METH_VARARGS, NULL},
    {"set_nlbufsiz", (PyCFunction) NetfilterLogGroupHandle_set_nlbufsiz, METH_VARARGS, NULL},
    {"set_flags", (PyCFunction) NetfilterLogGroupHandle_set_flags, METH_VARARGS, NULL},
    {"unbind", (PyCFunction) NetfilterLogGroupHandle_unbind, METH_NOARGS, NULL},
    {NULL}
};

static PyTypeObject NetfilterLogGroupHandleType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "libnetfilterlog.NetfilterLogGroupHandle",    /* tp_name */
    sizeof(NetfilterLogGroupHandle),              /* tp_basicsize */
    0,                                            /* tp_itemsize */
    (destructor) NetfilterLogGroupHandle_dealloc, /* tp_dealloc */
    0,                                            /* tp_print */
    0,                                            /* tp_getattr */
    0,                                            /* tp_setattr */
    0,                                            /* tp_compare */
    0,                                            /* tp_repr */
    0,                                            /* tp_as_number */
    0,                                            /* tp_as_sequence */
    0,                                            /* tp_as_mapping */
    0,                                            /* tp_hash */
    0,                                            /* tp_call */
    0,                                            /* tp_str */
    0,                                            /* tp_getattro */
    0,                                            /* tp_setattro */
    0,                                            /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,     /* tp_flags */
    "Wrapper for (struct nflog_g_handle *)",      /* tp_doc */
    0,                                            /* tp_traverse */
    0,                                            /* tp_clear */
    0,                                            /* tp_richcompare */
    0,                                            /* tp_weaklistoffset */
    0,                                            /* tp_iter */
    0,                                            /* tp_iternext */
    NetfilterLogGroupHandle_methods,              /* tp_methods */
    NetfilterLogGroupHandle_members,              /* tp_members */
    0,                                            /* tp_getset */
    0,                                            /* tp_base */
    0,                                            /* tp_dict */
    0,                                            /* tp_descr_get */
    0,                                            /* tp_descr_set */
    0,                                            /* tp_dictoffset */
    (initproc) NetfilterLogGroupHandle_init,      /* tp_init */
    0,                                            /* tp_alloc */
    (newfunc) NetfilterLogGroupHandle_new,        /* tp_new */
};

// END: NetfilterLogGroupHandle

// BEGIN: NetfilterLogHandle

typedef struct {
    PyObject_HEAD
    struct nflog_handle* handle;
} NetfilterLogHandle;

static PyObject* NetfilterLogHandle_new (PyTypeObject* type, PyTupleObject* args) {
    NetfilterLogHandle* self;
    self = (NetfilterLogHandle*) type->tp_alloc(type, 0);
    self->handle = NULL;
    return (PyObject*) self;
}

static int NetfilterLogHandle_init (NetfilterLogHandle* self, PyTupleObject* args) {
    return 0;
}

static void NetfilterLogHandle_dealloc (NetfilterLogHandle* self) {
    Py_TYPE(self)->tp_free((PyObject*) self);
}

static PyObject* NetfilterLogHandle_bind_pf (NetfilterLogHandle* self, PyTupleObject* args) {
    uint16_t pf;
    if (!PyArg_ParseTuple((PyObject*) args, "H", &pf)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (uint16_t pf)");
        return NULL;
    }
    if (nflog_bind_pf(self->handle, pf)) {
        PyErr_SetString(PyExc_OSError, "Call to nflog_bind_pf failed");
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject* NetfilterLogHandle_unbind_pf (NetfilterLogHandle* self, PyTupleObject* args) {
    uint16_t pf;
    if (!PyArg_ParseTuple((PyObject*) args, "H", &pf)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (uint16_t pf)");
        return NULL;
    }
    if (nflog_unbind_pf(self->handle, pf)) {
        PyErr_SetString(PyExc_OSError, "Call to nflog_unbind_pf failed");
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject* NetfilterLogHandle_bind_group (NetfilterLogHandle* self, PyTupleObject* args) {
    PyObject* empty;
    NetfilterLogGroupHandle* group_object;
    struct nflog_g_handle* group_struct;
    uint16_t num;
    if (!PyArg_ParseTuple((PyObject*) args, "H", &num)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (uint16_t num)");
        return NULL;
    }
    group_struct = nflog_bind_group(self->handle, num);
    if (!group_struct) {
        PyErr_SetString(PyExc_OSError, "Call to nflog_bind_group failed");
        return NULL;
    }
    empty = PyTuple_New(0);
    group_object = (NetfilterLogGroupHandle*) PyObject_CallObject((PyObject*) &NetfilterLogGroupHandleType, empty);
    Py_DECREF(empty);
    group_object->group = group_struct;
    return (PyObject*) group_object;
}

static PyObject* NetfilterLogHandle_handle_packet(NetfilterLogHandle* self, PyTupleObject* args) {
    char* data;
    int length;
    if (!PyArg_ParseTuple((PyObject*) args, "s#", &data, &length)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (char* data)");
        return NULL;
    }
    nflog_handle_packet(self->handle, data, length);
    Py_RETURN_NONE;
}

static PyObject* NetfilterLogHandle_fd (NetfilterLogHandle* self) {
    return PyInt_FromLong(nflog_fd(self->handle));
}

static PyObject* NetfilterLogHandle_close (NetfilterLogHandle* self) {
    if (nflog_close(self->handle)) {
        PyErr_SetString(PyExc_OSError, "Call to nflog_close failed");
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyMemberDef NetfilterLogHandle_members[] = {
    {NULL}
};

static PyMethodDef NetfilterLogHandle_methods[] = {
    {"bind_pf", (PyCFunction) NetfilterLogHandle_bind_pf, METH_VARARGS, NULL},
    {"unbind_pf", (PyCFunction) NetfilterLogHandle_unbind_pf, METH_VARARGS, NULL},
    {"bind_group", (PyCFunction) NetfilterLogHandle_bind_group, METH_VARARGS, NULL},
    {"handle_packet", (PyCFunction) NetfilterLogHandle_handle_packet, METH_VARARGS, NULL},
    {"fd", (PyCFunction) NetfilterLogHandle_fd, METH_NOARGS, NULL},
    {"close", (PyCFunction) NetfilterLogHandle_close, METH_NOARGS, NULL},
    {NULL}
};

static PyTypeObject NetfilterLogHandleType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "libnetfilterlog.NetfilterLogHandle",     /* tp_name */
    sizeof(NetfilterLogHandle),               /* tp_basicsize */
    0,                                        /* tp_itemsize */
    (destructor) NetfilterLogHandle_dealloc,  /* tp_dealloc */
    0,                                        /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_compare */
    0,                                        /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash */
    0,                                        /* tp_call */
    0,                                        /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    "Wrapper for (struct nflog_data *)",      /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    NetfilterLogHandle_methods,               /* tp_methods */
    NetfilterLogHandle_members,               /* tp_members */
    0,                                        /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    (initproc) NetfilterLogHandle_init,       /* tp_init */
    0,                                        /* tp_alloc */
    (newfunc) NetfilterLogHandle_new,         /* tp_new */
};

// END: NetfilterLogHandle

static PyObject* libnetfilterlog_open (PyObject *self) {
    PyObject* empty;
    NetfilterLogHandle* handle_object;
    struct nflog_handle* handle_struct;
    handle_struct = nflog_open();
    if (!handle_struct) {
        PyErr_SetString(PyExc_OSError, "Call to nflog_open failed");
        return NULL;
    }
    empty = PyTuple_New(0);
    handle_object = (NetfilterLogHandle*) PyObject_CallObject((PyObject*) &NetfilterLogHandleType, empty);
    Py_DECREF(empty);
    handle_object->handle = handle_struct;
    return (PyObject*) handle_object;
}

static PyMethodDef libnetfilterlog_methods[] = {
    {"open", (PyCFunction) libnetfilterlog_open, METH_NOARGS, NULL},
    {NULL}
};

PyMODINIT_FUNC initlibnetfilterlog (void) {
    PyObject* module;

    if (PyType_Ready(&NetfilterLogDataType) < 0)
        return;
    if (PyType_Ready(&NetfilterLogGroupHandleType) < 0)
        return;
    if (PyType_Ready(&NetfilterLogHandleType) < 0)
        return;

    module = Py_InitModule("libnetfilterlog", libnetfilterlog_methods);
    if (module == NULL)
        return;

    Py_INCREF((PyObject*) &NetfilterLogDataType);
    PyModule_AddObject(module, "NetfilterLogData", (PyObject*) &NetfilterLogDataType);

    Py_INCREF((PyObject*) &NetfilterLogGroupHandleType);
    PyModule_AddObject(module, "NetfilterLogGroupHandle", (PyObject*) &NetfilterLogGroupHandleType);

    Py_INCREF((PyObject*) &NetfilterLogHandleType);
    PyModule_AddObject(module, "NetfilterLogHandle", (PyObject*) &NetfilterLogHandleType);

    PyModule_AddIntConstant(module, "NFULNL_COPY_NONE", NFULNL_COPY_NONE);
    PyModule_AddIntConstant(module, "NFULNL_COPY_META", NFULNL_COPY_META);
    PyModule_AddIntConstant(module, "NFULNL_COPY_PACKET", NFULNL_COPY_PACKET);

    PyModule_AddIntConstant(module, "NFULNL_CFG_F_SEQ", NFULNL_CFG_F_SEQ);
    PyModule_AddIntConstant(module, "NFULNL_CFG_F_SEQ_GLOBAL", NFULNL_CFG_F_SEQ_GLOBAL);
}
