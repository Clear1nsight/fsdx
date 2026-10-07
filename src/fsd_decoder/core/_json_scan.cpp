#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <new>
#include <memory>
#include <charconv>
// Predicate only: syntax parsing, policies, integrity and file access stay Python.
// No allocation, state retention, input mutation or pointers returned to callers.
extern "C" int fsdx_depth_scan(const unsigned char* p, std::size_t n, std::size_t max_depth) noexcept {
    if ((!p && n) || n > static_cast<std::size_t>(std::numeric_limits<std::int64_t>::max())) return 3;
    // Strict UTF-8 first: its error must precede depth errors, matching bytes.decode.
    for (std::size_t i=0; i<n;) {
        const unsigned char c=p[i++];
        if (c < 0x80) continue;
        unsigned count=0; unsigned char low=0x80, high=0xbf;
        if (c>=0xc2 && c<=0xdf) count=1;
        else if (c>=0xe0 && c<=0xef) {count=2; if(c==0xe0) low=0xa0; if(c==0xed) high=0x9f;}
        else if (c>=0xf0 && c<=0xf4) {count=3; if(c==0xf0) low=0x90; if(c==0xf4) high=0x8f;}
        else return 2;
        if (n-i<count || p[i]<low || p[i]>high) return 2;
        ++i;
        for (unsigned j=1;j<count;++j,++i) if (p[i]<0x80 || p[i]>0xbf) return 2;
    }
    bool quoted=false; std::int64_t depth=0;
    for (std::size_t i=0;i<n;++i) {
        const unsigned char c=p[i];
        if (quoted) {
            if (c=='\\') {if(i+1<n) ++i;}
            else if (c=='"') quoted=false;
        } else if (c=='"') quoted=true;
        else if (c=='[' || c=='{') {
            ++depth;
            if(depth>0 && static_cast<std::uint64_t>(depth)>max_depth) return 1;
        } else if (c==']' || c=='}') --depth;
    }
    return 0;
}

// CPython stable ABI (3.12+). The borrowed bytes stay alive for the whole call.
#define PY_SSIZE_T_CLEAN
#include <Python.h>
static PyObject* check(PyObject*, PyObject* args) {
    const char* data;
    Py_ssize_t length, depth;
    if (!PyArg_ParseTuple(args, "y#n", &data, &length, &depth)) return nullptr;
    if (depth < 1 || depth > 256) {
        PyErr_SetString(PyExc_ValueError, "JSON depth must be in 1..256");
        return nullptr;
    }
    return PyLong_FromLong(fsdx_depth_scan(
        reinterpret_cast<const unsigned char*>(data),
        static_cast<std::size_t>(length), static_cast<std::size_t>(depth)));
}


static constexpr std::size_t MAX_ROW_BATCH_BYTES = 1024 * 1024;
// Size admission only; unsupported objects retain Python length/error semantics.
static PyObject* estimate_row(PyObject*, PyObject* row) {
    if (!PyTuple_CheckExact(row)) Py_RETURN_NONE;
    std::size_t bound = 10;
    for (Py_ssize_t i=0; i<PyTuple_Size(row); ++i) {
        PyObject* value = PyTuple_GetItem(row, i);
        std::size_t term;
        if (PyUnicode_CheckExact(value)) {
            const Py_ssize_t n = PyUnicode_GetLength(value);
            if (n < 0) return nullptr;
            term = static_cast<std::size_t>(n) > (MAX_ROW_BATCH_BYTES-3)/6
                ? MAX_ROW_BATCH_BYTES+1 : 6*static_cast<std::size_t>(n)+3;
        } else if (PyBytes_CheckExact(value)) {
            const Py_ssize_t n = PyBytes_Size(value);
            if (n < 0) return nullptr;
            term = static_cast<std::size_t>(n) > (MAX_ROW_BATCH_BYTES-32)/2
                ? MAX_ROW_BATCH_BYTES+1 : 2*static_cast<std::size_t>(n)+32;
        } else if (PyLong_CheckExact(value) || PyFloat_CheckExact(value) ||
                   value == Py_None || PyBool_Check(value)) term = 32;
        else Py_RETURN_NONE;
        // Saturate safely, but inspect all fields: a late unsupported scalar
        // must still trigger Python fallback even after an oversized value.
        if (term > MAX_ROW_BATCH_BYTES || bound > MAX_ROW_BATCH_BYTES-term)
            bound = MAX_ROW_BATCH_BYTES+1;
        else bound += term;
    }
    return PyLong_FromSize_t(bound);
}

// Only exact portable SQL scalars are accepted. Returning None asks Python to
// retain its canonical conversion/error semantics for unsupported values.
static bool scalar_json(PyObject* value, std::string& out) {
    if (value == Py_None) { out += "null"; return true; }
    if (PyLong_CheckExact(value)) {
        int overflow = 0;
        const long long integer = PyLong_AsLongLongAndOverflow(value, &overflow);
        if (overflow) return false;
        if (PyErr_Occurred()) return false;
        char digits[21];
        const auto result = std::to_chars(digits, digits + sizeof(digits), integer);
        if (result.ec != std::errc{}) {
            PyErr_SetString(PyExc_RuntimeError, "Integer framing conversion failed");
            return false;
        }
        out.append(digits, result.ptr);
        return true;
    }
    if (PyUnicode_CheckExact(value)) {
        Py_ssize_t n;
        const char* p = PyUnicode_AsUTF8AndSize(value, &n);
        if (!p) return false;
        out += '"';
        const char* hex = "0123456789abcdef";
        for (Py_ssize_t i=0; i<n; ++i) {
            unsigned char c = static_cast<unsigned char>(p[i]);
            if (c == '"' || c == '\\') { out += '\\'; out += c; }
            else if (c == '\b') out += "\\b";
            else if (c == '\f') out += "\\f";
            else if (c == '\n') out += "\\n";
            else if (c == '\r') out += "\\r";
            else if (c == '\t') out += "\\t";
            else if (c < 32) { out += "\\u00"; out += hex[c >> 4]; out += hex[c & 15]; }
            else out += c;
        }
        out += '"'; return true;
    }
    if (PyBytes_CheckExact(value)) {
        char* p; Py_ssize_t n;
        if (PyBytes_AsStringAndSize(value, &p, &n) < 0) return false;
        out += "{\"data\":\"";
        const char* hex = "0123456789abcdef";
        for (Py_ssize_t i=0; i<n; ++i) {
            unsigned char c = static_cast<unsigned char>(p[i]);
            out += hex[c >> 4]; out += hex[c & 15];
        }
        out += "\",\"encoding\":\"hex\"}"; return true;
    }
    return false;
}

static PyObject* frame_rows(PyObject*, PyObject* rows) {
    if (!PyList_CheckExact(rows) || PyList_Size(rows) > 256) Py_RETURN_NONE;
    try {
        std::string framed;
        const Py_ssize_t count = PyList_Size(rows);
        for (Py_ssize_t i=0; i<count; ++i) {
            PyObject* row = PyList_GetItem(rows, i);
            if (!PyTuple_CheckExact(row)) Py_RETURN_NONE;
            // Bound encoded expansion before allocating any native output.
            std::size_t bound = framed.size() + 10;
            for (Py_ssize_t j=0; j<PyTuple_Size(row); ++j) {
                PyObject* value = PyTuple_GetItem(row, j);
                if (PyUnicode_CheckExact(value)) bound += 6 * PyUnicode_GetLength(value) + 3;
                else if (PyBytes_CheckExact(value)) bound += 2 * PyBytes_Size(value) + 32;
                else if (PyLong_CheckExact(value) || value == Py_None) bound += 32;
                else Py_RETURN_NONE;
                if (bound > MAX_ROW_BATCH_BYTES) Py_RETURN_NONE;
            }
            std::string raw = "[";
            for (Py_ssize_t j=0; j<PyTuple_Size(row); ++j) {
                if (j) raw += ',';
                if (!scalar_json(PyTuple_GetItem(row, j), raw)) {
                    if (PyErr_ExceptionMatches(PyExc_UnicodeEncodeError)) PyErr_Clear();
                    else if (PyErr_Occurred()) return nullptr;
                    Py_RETURN_NONE;
                }
            }
            raw += ']';
            std::uint64_t n = raw.size();
            for (int shift=56; shift>=0; shift-=8) framed += static_cast<char>((n >> shift) & 255);
            framed += raw;
        }
        return PyBytes_FromStringAndSize(framed.data(), framed.size());
    } catch (const std::bad_alloc&) { return PyErr_NoMemory(); }
}

// Bounded exact-builtin record frames. Conservative whole-tree admission
// precedes all native output allocation; unsupported values use Python.
static bool record_bound(PyObject* v, unsigned depth, std::size_t& size) {
    if (depth > 64 || size > MAX_ROW_BATCH_BYTES) return false;
    if (PyDict_CheckExact(v)) {
        size += 2;
        Py_ssize_t pos = 0; PyObject *key, *value;
        while (PyDict_Next(v, &pos, &key, &value)) {
            if (!PyUnicode_CheckExact(key)) return false;
            size += 2;
            if (!record_bound(key, depth+1, size) || !record_bound(value, depth+1, size)) return false;
        }
    } else if (PyList_CheckExact(v) || PyTuple_CheckExact(v)) {
        size += 2;
        const Py_ssize_t n = PyList_CheckExact(v) ? PyList_Size(v) : PyTuple_Size(v);
        for (Py_ssize_t i=0; i<n; ++i) {
            size += 1;
            PyObject* child = PyList_CheckExact(v) ? PyList_GetItem(v,i) : PyTuple_GetItem(v,i);
            if (!record_bound(child,depth+1,size)) return false;
        }
    } else if (PyUnicode_CheckExact(v)) {
        const Py_ssize_t n=PyUnicode_GetLength(v);
        if (n < 0 || static_cast<std::size_t>(n) > (MAX_ROW_BATCH_BYTES-3)/6) return false;
        size += 6*static_cast<std::size_t>(n)+3;
    } else if (PyBytes_CheckExact(v)) {
        const Py_ssize_t n=PyBytes_Size(v);
        if (n < 0 || static_cast<std::size_t>(n) > (MAX_ROW_BATCH_BYTES-32)/2) return false;
        size += 2*static_cast<std::size_t>(n)+32;
    } else if (PyLong_CheckExact(v) || PyBool_Check(v) || v==Py_None) size += 32;
    else return false; // Float spelling, subclasses and conversion hooks stay Python.
    return size <= MAX_ROW_BATCH_BYTES;
}
static bool record_json(PyObject* v, std::string& out) {
    if (PyBool_Check(v)) {out += (v==Py_True ? "true" : "false"); return true;}
    if (PyDict_CheckExact(v)) {
        std::unique_ptr<PyObject, decltype(&Py_DecRef)> keys(PyDict_Keys(v), Py_DecRef);
        if (!keys) return false;
        if (PyList_Sort(keys.get())<0) return false;
        out += '{'; bool good=true;
        for (Py_ssize_t i=0; i<PyList_Size(keys.get()); ++i) {
            if(i) out += ',';
            PyObject* key=PyList_GetItem(keys.get(),i);
            PyObject* value=PyDict_GetItemWithError(v,key);
            if (!value || !scalar_json(key,out)) {good=false; break;}
            out += ':';
            if (!record_json(value,out)) {good=false; break;}
        }
        if (!good) return false;
        out += '}'; return true;
    }
    if (PyList_CheckExact(v) || PyTuple_CheckExact(v)) {
        out += '[';
        const Py_ssize_t n=PyList_CheckExact(v) ? PyList_Size(v) : PyTuple_Size(v);
        for (Py_ssize_t i=0; i<n; ++i) {
            if(i) out += ',';
            PyObject* child=PyList_CheckExact(v) ? PyList_GetItem(v,i) : PyTuple_GetItem(v,i);
            if (!record_json(child,out)) return false;
        }
        out += ']'; return true;
    }
    return scalar_json(v,out);
}
static PyObject* frame_records(PyObject*, PyObject* records) {
    if (!PyList_CheckExact(records) || PyList_Size(records)>64) Py_RETURN_NONE;
    std::size_t bound=0;
    for (Py_ssize_t i=0; i<PyList_Size(records); ++i) {
        bound += 8;
        PyObject* value=PyList_GetItem(records,i);
        if (!PyDict_CheckExact(value) || !record_bound(value,0,bound)) Py_RETURN_NONE;
    }
    try {
        std::string framed;
        for (Py_ssize_t i=0; i<PyList_Size(records); ++i) {
            std::string raw;
            if(!record_json(PyList_GetItem(records,i),raw)) {
                if (PyErr_ExceptionMatches(PyExc_UnicodeEncodeError)) PyErr_Clear();
                else if (PyErr_Occurred()) return nullptr;
                Py_RETURN_NONE;
            }
            const std::uint64_t n=raw.size();
            for(int shift=56;shift>=0;shift-=8) framed += static_cast<char>((n>>shift)&255);
            framed += raw;
        }
        return PyBytes_FromStringAndSize(framed.data(),framed.size());
    } catch(const std::bad_alloc&) {return PyErr_NoMemory();}
}

static PyMethodDef methods[] = {
    {"frame_records", frame_records, METH_O, "Frame bounded exact-builtin record trees or request Python fallback."},
    {"estimate_row", estimate_row, METH_O, "Estimate bounded SQL row size or request Python fallback."},
    {"check", check, METH_VARARGS, "Validate UTF-8 and screen JSON nesting."},
    {"frame_rows", frame_rows, METH_O, "Frame bounded canonical portable SQL rows or return None."},
    {nullptr, nullptr, 0, nullptr}
};
static PyModuleDef module = {
    PyModuleDef_HEAD_INIT, "_json_scan", nullptr, -1, methods,
    nullptr, nullptr, nullptr, nullptr
};
PyMODINIT_FUNC PyInit__json_scan() { return PyModule_Create(&module); }
