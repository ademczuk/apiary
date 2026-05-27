// DEMO RECONSTRUCTION - stub for the lodash 4.17.21 known-good baseline.
// The real package ships several thousand lines of utility helpers; the
// stub exists only so file enumeration in the audit prompt has something
// to chew on.

'use strict';

module.exports = {
    VERSION: '4.17.21',
    chunk: function (array, size) {
        size = Math.max(parseInt(size, 10) || 0, 0);
        const length = array ? array.length : 0;
        if (!length || size < 1) {
            return [];
        }
        const out = [];
        for (let i = 0; i < length; i += size) {
            out.push(array.slice(i, i + size));
        }
        return out;
    },
};
