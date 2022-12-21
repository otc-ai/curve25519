// ==================================================================================================
// START INCLUDE FILE curve25519_.js
// ==================================================================================================

// Copyright (c) 2007 Michele Bini
// Konstantin Welke, 2008:
// - moved into .js file, renamed all c255lname to curve25519_name
// - added curve25519_clamp()
// - functions to read from/to 8bit string
// - removed base32/hex functions (cleanup)
// - removed setbit function (cleanup, had a bug anyway)
// BloodyRookie 2014:
// - ported part of the java implementation by Dmitry Skiba to js and merged into this file
// - profiled for higher speed
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA. */
//
// The original curve25519 library was released into the public domain
// by Daniel J. Bernstein

var curve25519_zero = function() {
  return [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

var curve25519_one = function() {
  return [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

var curve25519_nine = function() {
  return [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

var curve25519_486671 = function() {
  return [27919, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

var curve25519_39420360 = function() {
  return [33224, 601, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

var curve25519_r2y = function() {
  return [
    0x1670,
    0x4000,
    0xf219,
    0xd369,
    0x2248,
    0x4845,
    0x679a,
    0x884d,
    0x5d19,
    0x16bf,
    0xda74,
    0xe57d,
    0x5e53,
    0x3705,
    0x3526,
    0x17c0
  ]
}

export var curve25519_clamp = function(curve: any) {
  curve[0] &= 0xfff8
  curve[15] &= 0x7fff
  curve[15] |= 0x4000
  return curve
}

var curve25519_getbit = function(curve: any, c: any) {
  return ~~(curve[~~(c / 16)] / Math.pow(2, c % 16)) % 2
}

/* group order (a prime near 2^252+2^124) */
var curve25519_order = [
  237,
  211,
  245,
  92,
  26,
  99,
  18,
  88,
  214,
  156,
  247,
  162,
  222,
  249,
  222,
  20,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  16
]

var curve25519_order_times_8 = [
  104,
  159,
  174,
  231,
  210,
  24,
  147,
  192,
  178,
  230,
  188,
  23,
  245,
  206,
  247,
  166,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  128
]

var curve25519_convertToByteArray = function(a: any) {
  var b = new Int8Array(32)
  var i
  for (i = 0; i < 16; i++) {
    b[2 * i] = a[i] & 0xff
    b[2 * i + 1] = a[i] >> 8
  }

  return b
}

var curve25519_convertToShortArray = function(a: any) {
  var b = new Array(16)
  var i, val1, val2
  for (i = 0; i < 16; i++) {
    val1 = a[i * 2]
    if (val1 < 0) {
      val1 += 256
    }
    val2 = a[i * 2 + 1]
    if (val2 < 0) {
      val2 += 256
    }
    b[i] = val1 + val2 * 256
  }
  return b
}

var curve25519_fillShortArray = function(src: any, dest: any) {
  var i
  for (i = 0; i < 16; i++) {
    dest[i] = src[i]
  }
}

var curve25519_cpy32 = function(a: any) {
  var b = new Int8Array(32)
  for (var i = 0; i < 32; i++) {
    b[i] = a[i]
  }
  return b
}

var curve25519_mula_small = function(p: any, q: any, m: any, x: any, n: any, z: any) {
  var v = 0
  for (var j = 0; j < n; ++j) {
    v += (q[j + m] & 0xff) + z * (x[j] & 0xff)
    p[j + m] = v & 0xff
    v >>= 8
  }
  return v
}

var curve25519_mula32 = function(p: any, x: any, y: any, t: any, z: any) {
  var n = 31
  var w = 0
  for (var i = 0; i < t; i++) {
    var zy = z * (y[i] & 0xff)
    w += curve25519_mula_small(p, p, i, x, n, zy) + (p[i + n] & 0xff) + zy * (x[n] & 0xff)
    p[i + n] = w & 0xff
    w >>= 8
  }
  p[i + n] = (w + (p[i + n] & 0xff)) & 0xff
  return w >> 8
}

var curve25519_divmod = function(q: any, r: any, n: any, d: any, t: any) {
  var rn = 0,
    z = 0
  var dt = (d[t - 1] & 0xff) << 8
  if (t > 1) {
    dt |= d[t - 2] & 0xff
  }
  while (n-- >= t) {
    z = (rn << 16) | ((r[n] & 0xff) << 8)
    if (n > 0) {
      z |= r[n - 1] & 0xff
    }
    z = parseInt("" + z / dt)
    rn += curve25519_mula_small(r, r, n - t + 1, d, t, -z)
    q[n - t + 1] = (z + rn) & 0xff // rn is 0 or -1 (underflow)
    curve25519_mula_small(r, r, n - t + 1, d, t, -rn)
    rn = r[n] & 0xff
    r[n] = 0
  }
  r[t - 1] = rn & 0xff
}

var curve25519_numsize = function(x: any, n: any) {
  while (n-- != 0 && x[n] == 0);
  return n + 1
}

var curve25519_egcd32 = function(x: any, y: any, a: any, b: any) {
  var an = 0,
    bn = 32,
    qn = 0,
    i = 0
  for (i = 0; i < 32; i++) {
    x[i] = y[i] = 0
  }
  x[0] = 1
  an = curve25519_numsize(a, 32)
  if (an == 0) {
    return y // division by zero
  }
  var temp = new Int8Array(32)
  while (true) {
    qn = bn - an + 1
    curve25519_divmod(temp, b, bn, a, an)
    bn = curve25519_numsize(b, bn)
    if (bn == 0) {
      return x
    }
    curve25519_mula32(y, x, temp, qn, -1)

    qn = an - bn + 1
    curve25519_divmod(temp, a, an, b, bn)
    an = curve25519_numsize(a, an)
    if (an == 0) {
      return y
    }
    curve25519_mula32(x, y, temp, qn, -1)
  }
}

var curve25519_cpy16 = function(a: any) {
  var r = new Array(16)
  var i
  for (i = 0; i < 16; i++) {
    r[i] = a[i]
  }
  return r
}

/***
 * BloodyRookie: odd numbers are negativ
 */
var curve25519_isNegative = function(x: any) {
  return x[0] & 1
}

var curve25519_sqr8h = function(
  r: any,
  a7: any,
  a6: any,
  a5: any,
  a4: any,
  a3: any,
  a2: any,
  a1: any,
  a0: any
) {
  var v = 0
  r[0] = (v = a0 * a0) & 0xffff
  r[1] = (v = ~~(v / 0x10000) + 2 * a0 * a1) & 0xffff
  r[2] = (v = ~~(v / 0x10000) + 2 * a0 * a2 + a1 * a1) & 0xffff
  r[3] = (v = ~~(v / 0x10000) + 2 * a0 * a3 + 2 * a1 * a2) & 0xffff
  r[4] = (v = ~~(v / 0x10000) + 2 * a0 * a4 + 2 * a1 * a3 + a2 * a2) & 0xffff
  r[5] = (v = ~~(v / 0x10000) + 2 * a0 * a5 + 2 * a1 * a4 + 2 * a2 * a3) & 0xffff
  r[6] = (v = ~~(v / 0x10000) + 2 * a0 * a6 + 2 * a1 * a5 + 2 * a2 * a4 + a3 * a3) & 0xffff
  r[7] = (v = ~~(v / 0x10000) + 2 * a0 * a7 + 2 * a1 * a6 + 2 * a2 * a5 + 2 * a3 * a4) & 0xffff
  r[8] = (v = ~~(v / 0x10000) + 2 * a1 * a7 + 2 * a2 * a6 + 2 * a3 * a5 + a4 * a4) & 0xffff
  r[9] = (v = ~~(v / 0x10000) + 2 * a2 * a7 + 2 * a3 * a6 + 2 * a4 * a5) & 0xffff
  r[10] = (v = ~~(v / 0x10000) + 2 * a3 * a7 + 2 * a4 * a6 + a5 * a5) & 0xffff
  r[11] = (v = ~~(v / 0x10000) + 2 * a4 * a7 + 2 * a5 * a6) & 0xffff
  r[12] = (v = ~~(v / 0x10000) + 2 * a5 * a7 + a6 * a6) & 0xffff
  r[13] = (v = ~~(v / 0x10000) + 2 * a6 * a7) & 0xffff
  r[14] = (v = ~~(v / 0x10000) + a7 * a7) & 0xffff
  r[15] = ~~(v / 0x10000)
}

var curve25519_sqrmodp = function(r: any, a: any) {
  var x = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var y = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var z = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  curve25519_sqr8h(x, a[15], a[14], a[13], a[12], a[11], a[10], a[9], a[8])
  curve25519_sqr8h(z, a[7], a[6], a[5], a[4], a[3], a[2], a[1], a[0])
  curve25519_sqr8h(
    y,
    a[15] + a[7],
    a[14] + a[6],
    a[13] + a[5],
    a[12] + a[4],
    a[11] + a[3],
    a[10] + a[2],
    a[9] + a[1],
    a[8] + a[0]
  )
  var v = 0
  r[0] = (v = 0x800000 + z[0] + (y[8] - x[8] - z[8] + x[0] - 0x80) * 38) & 0xffff
  r[1] = (v = 0x7fff80 + ~~(v / 0x10000) + z[1] + (y[9] - x[9] - z[9] + x[1]) * 38) & 0xffff
  r[2] = (v = 0x7fff80 + ~~(v / 0x10000) + z[2] + (y[10] - x[10] - z[10] + x[2]) * 38) & 0xffff
  r[3] = (v = 0x7fff80 + ~~(v / 0x10000) + z[3] + (y[11] - x[11] - z[11] + x[3]) * 38) & 0xffff
  r[4] = (v = 0x7fff80 + ~~(v / 0x10000) + z[4] + (y[12] - x[12] - z[12] + x[4]) * 38) & 0xffff
  r[5] = (v = 0x7fff80 + ~~(v / 0x10000) + z[5] + (y[13] - x[13] - z[13] + x[5]) * 38) & 0xffff
  r[6] = (v = 0x7fff80 + ~~(v / 0x10000) + z[6] + (y[14] - x[14] - z[14] + x[6]) * 38) & 0xffff
  r[7] = (v = 0x7fff80 + ~~(v / 0x10000) + z[7] + (y[15] - x[15] - z[15] + x[7]) * 38) & 0xffff
  r[8] = (v = 0x7fff80 + ~~(v / 0x10000) + z[8] + y[0] - x[0] - z[0] + x[8] * 38) & 0xffff
  r[9] = (v = 0x7fff80 + ~~(v / 0x10000) + z[9] + y[1] - x[1] - z[1] + x[9] * 38) & 0xffff
  r[10] = (v = 0x7fff80 + ~~(v / 0x10000) + z[10] + y[2] - x[2] - z[2] + x[10] * 38) & 0xffff
  r[11] = (v = 0x7fff80 + ~~(v / 0x10000) + z[11] + y[3] - x[3] - z[3] + x[11] * 38) & 0xffff
  r[12] = (v = 0x7fff80 + ~~(v / 0x10000) + z[12] + y[4] - x[4] - z[4] + x[12] * 38) & 0xffff
  r[13] = (v = 0x7fff80 + ~~(v / 0x10000) + z[13] + y[5] - x[5] - z[5] + x[13] * 38) & 0xffff
  r[14] = (v = 0x7fff80 + ~~(v / 0x10000) + z[14] + y[6] - x[6] - z[6] + x[14] * 38) & 0xffff
  r[15] = 0x7fff80 + ~~(v / 0x10000) + z[15] + y[7] - x[7] - z[7] + x[15] * 38
  curve25519_reduce(r)
}

var curve25519_mul8h = function(
  r: any,
  a7: any,
  a6: any,
  a5: any,
  a4: any,
  a3: any,
  a2: any,
  a1: any,
  a0: any,
  b7: any,
  b6: any,
  b5: any,
  b4: any,
  b3: any,
  b2: any,
  b1: any,
  b0: any
) {
  var v = 0
  r[0] = (v = a0 * b0) & 0xffff
  r[1] = (v = ~~(v / 0x10000) + a0 * b1 + a1 * b0) & 0xffff
  r[2] = (v = ~~(v / 0x10000) + a0 * b2 + a1 * b1 + a2 * b0) & 0xffff
  r[3] = (v = ~~(v / 0x10000) + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0) & 0xffff
  r[4] = (v = ~~(v / 0x10000) + a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0) & 0xffff
  r[5] = (v = ~~(v / 0x10000) + a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0) & 0xffff
  r[6] =
    (v = ~~(v / 0x10000) + a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0) &
    0xffff
  r[7] =
    (v =
      ~~(v / 0x10000) +
      a0 * b7 +
      a1 * b6 +
      a2 * b5 +
      a3 * b4 +
      a4 * b3 +
      a5 * b2 +
      a6 * b1 +
      a7 * b0) & 0xffff
  r[8] =
    (v = ~~(v / 0x10000) + a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2 + a7 * b1) &
    0xffff
  r[9] = (v = ~~(v / 0x10000) + a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 + a6 * b3 + a7 * b2) & 0xffff
  r[10] = (v = ~~(v / 0x10000) + a3 * b7 + a4 * b6 + a5 * b5 + a6 * b4 + a7 * b3) & 0xffff
  r[11] = (v = ~~(v / 0x10000) + a4 * b7 + a5 * b6 + a6 * b5 + a7 * b4) & 0xffff
  r[12] = (v = ~~(v / 0x10000) + a5 * b7 + a6 * b6 + a7 * b5) & 0xffff
  r[13] = (v = ~~(v / 0x10000) + a6 * b7 + a7 * b6) & 0xffff
  r[14] = (v = ~~(v / 0x10000) + a7 * b7) & 0xffff
  r[15] = ~~(v / 0x10000)
}

var curve25519_mulmodp = function(r: any, a: any, b: any) {
  var x = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var y = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var z = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  curve25519_mul8h(
    x,
    a[15],
    a[14],
    a[13],
    a[12],
    a[11],
    a[10],
    a[9],
    a[8],
    b[15],
    b[14],
    b[13],
    b[12],
    b[11],
    b[10],
    b[9],
    b[8]
  )
  curve25519_mul8h(
    z,
    a[7],
    a[6],
    a[5],
    a[4],
    a[3],
    a[2],
    a[1],
    a[0],
    b[7],
    b[6],
    b[5],
    b[4],
    b[3],
    b[2],
    b[1],
    b[0]
  )
  curve25519_mul8h(
    y,
    a[15] + a[7],
    a[14] + a[6],
    a[13] + a[5],
    a[12] + a[4],
    a[11] + a[3],
    a[10] + a[2],
    a[9] + a[1],
    a[8] + a[0],
    b[15] + b[7],
    b[14] + b[6],
    b[13] + b[5],
    b[12] + b[4],
    b[11] + b[3],
    b[10] + b[2],
    b[9] + b[1],
    b[8] + b[0]
  )
  var v = 0
  r[0] = (v = 0x800000 + z[0] + (y[8] - x[8] - z[8] + x[0] - 0x80) * 38) & 0xffff
  r[1] = (v = 0x7fff80 + ~~(v / 0x10000) + z[1] + (y[9] - x[9] - z[9] + x[1]) * 38) & 0xffff
  r[2] = (v = 0x7fff80 + ~~(v / 0x10000) + z[2] + (y[10] - x[10] - z[10] + x[2]) * 38) & 0xffff
  r[3] = (v = 0x7fff80 + ~~(v / 0x10000) + z[3] + (y[11] - x[11] - z[11] + x[3]) * 38) & 0xffff
  r[4] = (v = 0x7fff80 + ~~(v / 0x10000) + z[4] + (y[12] - x[12] - z[12] + x[4]) * 38) & 0xffff
  r[5] = (v = 0x7fff80 + ~~(v / 0x10000) + z[5] + (y[13] - x[13] - z[13] + x[5]) * 38) & 0xffff
  r[6] = (v = 0x7fff80 + ~~(v / 0x10000) + z[6] + (y[14] - x[14] - z[14] + x[6]) * 38) & 0xffff
  r[7] = (v = 0x7fff80 + ~~(v / 0x10000) + z[7] + (y[15] - x[15] - z[15] + x[7]) * 38) & 0xffff
  r[8] = (v = 0x7fff80 + ~~(v / 0x10000) + z[8] + y[0] - x[0] - z[0] + x[8] * 38) & 0xffff
  r[9] = (v = 0x7fff80 + ~~(v / 0x10000) + z[9] + y[1] - x[1] - z[1] + x[9] * 38) & 0xffff
  r[10] = (v = 0x7fff80 + ~~(v / 0x10000) + z[10] + y[2] - x[2] - z[2] + x[10] * 38) & 0xffff
  r[11] = (v = 0x7fff80 + ~~(v / 0x10000) + z[11] + y[3] - x[3] - z[3] + x[11] * 38) & 0xffff
  r[12] = (v = 0x7fff80 + ~~(v / 0x10000) + z[12] + y[4] - x[4] - z[4] + x[12] * 38) & 0xffff
  r[13] = (v = 0x7fff80 + ~~(v / 0x10000) + z[13] + y[5] - x[5] - z[5] + x[13] * 38) & 0xffff
  r[14] = (v = 0x7fff80 + ~~(v / 0x10000) + z[14] + y[6] - x[6] - z[6] + x[14] * 38) & 0xffff
  r[15] = 0x7fff80 + ~~(v / 0x10000) + z[15] + y[7] - x[7] - z[7] + x[15] * 38
  curve25519_reduce(r)
}

var curve25519_mulasmall = function(r: any, a: any, m: any) {
  var v = 0
  r[0] = (v = a[0] * m) & 0xffff
  r[1] = (v = ~~(v / 0x10000) + a[1] * m) & 0xffff
  r[2] = (v = ~~(v / 0x10000) + a[2] * m) & 0xffff
  r[3] = (v = ~~(v / 0x10000) + a[3] * m) & 0xffff
  r[4] = (v = ~~(v / 0x10000) + a[4] * m) & 0xffff
  r[5] = (v = ~~(v / 0x10000) + a[5] * m) & 0xffff
  r[6] = (v = ~~(v / 0x10000) + a[6] * m) & 0xffff
  r[7] = (v = ~~(v / 0x10000) + a[7] * m) & 0xffff
  r[8] = (v = ~~(v / 0x10000) + a[8] * m) & 0xffff
  r[9] = (v = ~~(v / 0x10000) + a[9] * m) & 0xffff
  r[10] = (v = ~~(v / 0x10000) + a[10] * m) & 0xffff
  r[11] = (v = ~~(v / 0x10000) + a[11] * m) & 0xffff
  r[12] = (v = ~~(v / 0x10000) + a[12] * m) & 0xffff
  r[13] = (v = ~~(v / 0x10000) + a[13] * m) & 0xffff
  r[14] = (v = ~~(v / 0x10000) + a[14] * m) & 0xffff
  r[15] = ~~(v / 0x10000) + a[15] * m
  curve25519_reduce(r)
}

var curve25519_addmodp = function(r: any, a: any, b: any) {
  var v = 0
  r[0] = (v = (~~(a[15] / 0x8000) + ~~(b[15] / 0x8000)) * 19 + a[0] + b[0]) & 0xffff
  r[1] = (v = ~~(v / 0x10000) + a[1] + b[1]) & 0xffff
  r[2] = (v = ~~(v / 0x10000) + a[2] + b[2]) & 0xffff
  r[3] = (v = ~~(v / 0x10000) + a[3] + b[3]) & 0xffff
  r[4] = (v = ~~(v / 0x10000) + a[4] + b[4]) & 0xffff
  r[5] = (v = ~~(v / 0x10000) + a[5] + b[5]) & 0xffff
  r[6] = (v = ~~(v / 0x10000) + a[6] + b[6]) & 0xffff
  r[7] = (v = ~~(v / 0x10000) + a[7] + b[7]) & 0xffff
  r[8] = (v = ~~(v / 0x10000) + a[8] + b[8]) & 0xffff
  r[9] = (v = ~~(v / 0x10000) + a[9] + b[9]) & 0xffff
  r[10] = (v = ~~(v / 0x10000) + a[10] + b[10]) & 0xffff
  r[11] = (v = ~~(v / 0x10000) + a[11] + b[11]) & 0xffff
  r[12] = (v = ~~(v / 0x10000) + a[12] + b[12]) & 0xffff
  r[13] = (v = ~~(v / 0x10000) + a[13] + b[13]) & 0xffff
  r[14] = (v = ~~(v / 0x10000) + a[14] + b[14]) & 0xffff
  r[15] = ~~(v / 0x10000) + a[15] % 0x8000 + b[15] % 0x8000
}

var curve25519_submodp = function(r: any, a: any, b: any) {
  var v = 0
  r[0] = (v = 0x80000 + (~~(a[15] / 0x8000) - ~~(b[15] / 0x8000) - 1) * 19 + a[0] - b[0]) & 0xffff
  r[1] = (v = ~~(v / 0x10000) + 0x7fff8 + a[1] - b[1]) & 0xffff
  r[2] = (v = ~~(v / 0x10000) + 0x7fff8 + a[2] - b[2]) & 0xffff
  r[3] = (v = ~~(v / 0x10000) + 0x7fff8 + a[3] - b[3]) & 0xffff
  r[4] = (v = ~~(v / 0x10000) + 0x7fff8 + a[4] - b[4]) & 0xffff
  r[5] = (v = ~~(v / 0x10000) + 0x7fff8 + a[5] - b[5]) & 0xffff
  r[6] = (v = ~~(v / 0x10000) + 0x7fff8 + a[6] - b[6]) & 0xffff
  r[7] = (v = ~~(v / 0x10000) + 0x7fff8 + a[7] - b[7]) & 0xffff
  r[8] = (v = ~~(v / 0x10000) + 0x7fff8 + a[8] - b[8]) & 0xffff
  r[9] = (v = ~~(v / 0x10000) + 0x7fff8 + a[9] - b[9]) & 0xffff
  r[10] = (v = ~~(v / 0x10000) + 0x7fff8 + a[10] - b[10]) & 0xffff
  r[11] = (v = ~~(v / 0x10000) + 0x7fff8 + a[11] - b[11]) & 0xffff
  r[12] = (v = ~~(v / 0x10000) + 0x7fff8 + a[12] - b[12]) & 0xffff
  r[13] = (v = ~~(v / 0x10000) + 0x7fff8 + a[13] - b[13]) & 0xffff
  r[14] = (v = ~~(v / 0x10000) + 0x7fff8 + a[14] - b[14]) & 0xffff
  r[15] = ~~(v / 0x10000) + 0x7ff8 + a[15] % 0x8000 - b[15] % 0x8000
}
/****
 * BloodyRookie: a^-1 is found via Fermats little theorem:
 * a^p congruent a mod p and therefore a^(p-2) congruent a^-1 mod p
 */
var curve25519_invmodp = function(r: any, a: any, sqrtassist: any) {
  var r1 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var r2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var r3 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var r4 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var r5 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var i = 0
  curve25519_sqrmodp(r2, a) //  2 == 2 * 1
  curve25519_sqrmodp(r3, r2) //  4 == 2 * 2
  curve25519_sqrmodp(r1, r3) //  8 == 2 * 4
  curve25519_mulmodp(r3, r1, a) //  9 == 8 + 1
  curve25519_mulmodp(r1, r3, r2) // 11 == 9 + 2
  curve25519_sqrmodp(r2, r1) // 22 == 2 * 11
  curve25519_mulmodp(r4, r2, r3) // 31 == 22 + 9
  //	== 2^5   - 2^0
  curve25519_sqrmodp(r2, r4) // 2^6   - 2^1
  curve25519_sqrmodp(r3, r2) // 2^7   - 2^2
  curve25519_sqrmodp(r2, r3) // 2^8   - 2^3
  curve25519_sqrmodp(r3, r2) // 2^9   - 2^4
  curve25519_sqrmodp(r2, r3) // 2^10  - 2^5
  curve25519_mulmodp(r3, r2, r4) // 2^10  - 2^0
  curve25519_sqrmodp(r2, r3) // 2^11  - 2^1
  curve25519_sqrmodp(r4, r2) // 2^12  - 2^2
  for (i = 1; i < 5; i++) {
    curve25519_sqrmodp(r2, r4)
    curve25519_sqrmodp(r4, r2)
  } // 2^20  - 2^10
  curve25519_mulmodp(r2, r4, r3) // 2^20  - 2^0
  curve25519_sqrmodp(r4, r2) // 2^21  - 2^1
  curve25519_sqrmodp(r5, r4) // 2^22  - 2^2
  for (i = 1; i < 10; i++) {
    curve25519_sqrmodp(r4, r5)
    curve25519_sqrmodp(r5, r4)
  } // 2^40  - 2^20
  curve25519_mulmodp(r4, r5, r2) // 2^40  - 2^0
  for (i = 0; i < 5; i++) {
    curve25519_sqrmodp(r2, r4)
    curve25519_sqrmodp(r4, r2)
  } // 2^50  - 2^10
  curve25519_mulmodp(r2, r4, r3) // 2^50  - 2^0
  curve25519_sqrmodp(r3, r2) // 2^51  - 2^1
  curve25519_sqrmodp(r4, r3) // 2^52  - 2^2
  for (i = 1; i < 25; i++) {
    curve25519_sqrmodp(r3, r4)
    curve25519_sqrmodp(r4, r3)
  } // 2^100 - 2^50
  curve25519_mulmodp(r3, r4, r2) // 2^100 - 2^0
  curve25519_sqrmodp(r4, r3) // 2^101 - 2^1
  curve25519_sqrmodp(r5, r4) // 2^102 - 2^2
  for (i = 1; i < 50; i++) {
    curve25519_sqrmodp(r4, r5)
    curve25519_sqrmodp(r5, r4)
  } // 2^200 - 2^100
  curve25519_mulmodp(r4, r5, r3) // 2^200 - 2^0
  for (i = 0; i < 25; i++) {
    curve25519_sqrmodp(r5, r4)
    curve25519_sqrmodp(r4, r5)
  } // 2^250 - 2^50
  curve25519_mulmodp(r3, r4, r2) // 2^250 - 2^0
  curve25519_sqrmodp(r2, r3) // 2^251 - 2^1
  curve25519_sqrmodp(r3, r2) // 2^252 - 2^2
  if (sqrtassist == 1) {
    curve25519_mulmodp(r, a, r3) // 2^252 - 3
  } else {
    curve25519_sqrmodp(r2, r3) // 2^253 - 2^3
    curve25519_sqrmodp(r3, r2) // 2^254 - 2^4
    curve25519_sqrmodp(r2, r3) // 2^255 - 2^5
    curve25519_mulmodp(r, r2, r1) // 2^255 - 21
  }
}

var curve25519_reduce = function(a: any) {
  curve25519_reduce2(a)

  /**
   * BloodyRookie: special case for p <= a < 2^255
   */
  if (
    a[15] != 0x7fff ||
    a[14] != 0xffff ||
    a[13] != 0xffff ||
    a[12] != 0xffff ||
    a[11] != 0xffff ||
    a[10] != 0xffff ||
    a[9] != 0xffff ||
    a[8] != 0xffff ||
    a[7] != 0xffff ||
    a[6] != 0xffff ||
    a[5] != 0xffff ||
    a[4] != 0xffff ||
    a[3] != 0xffff ||
    a[2] != 0xffff ||
    a[1] != 0xffff ||
    a[0] < 0xffed
  ) {
    return
  }

  var i
  for (i = 1; i < 16; i++) {
    a[i] = 0
  }
  a[0] = a[0] - 0xffed
}
var curve25519_reduce2 = function(a: any) {
  var v = a[15]
  if (v < 0x8000) return
  a[15] = v % 0x8000
  v = ~~(v / 0x8000) * 19
  a[0] = (v += a[0]) & 0xffff
  if ((v = ~~(v / 0x10000)) < 1) return
  a[1] = (v += a[1]) & 0xffff
  if ((v = ~~(v / 0x10000)) < 1) return
  a[2] = (v += a[2]) & 0xffff
  if ((v = ~~(v / 0x10000)) < 1) return
  a[3] = (v += a[3]) & 0xffff
  if ((v = ~~(v / 0x10000)) < 1) return
  a[4] = (v += a[4]) & 0xffff
  if ((v = ~~(v / 0x10000)) < 1) return
  a[5] = (v += a[5]) & 0xffff
  if ((v = ~~(v / 0x10000)) < 1) return
  a[6] = (v += a[6]) & 0xffff
  if ((v = ~~(v / 0x10000)) < 1) return
  a[7] = (v += a[7]) & 0xffff
  if ((v = ~~(v / 0x10000)) < 1) return
  a[8] = (v += a[8]) & 0xffff
  if ((v = ~~(v / 0x10000)) < 1) return
  a[9] = (v += a[9]) & 0xffff
  if ((v = ~~(v / 0x10000)) < 1) return
  a[10] = (v += a[10]) & 0xffff
  if ((v = ~~(v / 0x10000)) < 1) return
  a[11] = (v += a[11]) & 0xffff
  if ((v = ~~(v / 0x10000)) < 1) return
  a[12] = (v += a[12]) & 0xffff
  if ((v = ~~(v / 0x10000)) < 1) return
  a[13] = (v += a[13]) & 0xffff
  if ((v = ~~(v / 0x10000)) < 1) return
  a[14] = (v += a[14]) & 0xffff
  if ((v = ~~(v / 0x10000)) < 1) return
  a[15] += v
}

/**
 * Montgomery curve with A=486662 and B=1
 */
var curve25519_x_to_y2 = function(r: any, x: any) {
  var r1 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var r2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  curve25519_sqrmodp(r1, x) // r1 = x^2
  curve25519_mulasmall(r2, x, 486662) // r2 = Ax
  curve25519_addmodp(r, r1, r2) //  r = x^2 + Ax
  curve25519_addmodp(r1, r, curve25519_one()) // r1 = x^2 + Ax + 1
  curve25519_mulmodp(r, r1, x) //  r = x^3 + Ax^2 + x
}

var curve25519_prep = function(r: any, s: any, a: any, b: any) {
  curve25519_addmodp(r, a, b)
  curve25519_submodp(s, a, b)
}

/****
 * BloodyRookie: Doubling a point on a Montgomery curve:
 * Point is given in projective coordinates p=x/z
 * 2*P = r/s,
 * r = (x+z)^2 * (x-z)^2
 * s = ((((x+z)^2 - (x-z)^2) * 121665) + (x+z)^2) * ((x+z)^2 - (x-z)^2)
 *   = 4*x*z * (x^2 + 486662*x*z + z^2)
 *   = 4*x*z * ((x-z)^2 + ((486662+2)/4)(4*x*z))
 */
var curve25519_dbl = function(r: any, s: any, t1: any, t2: any) {
  var r1 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var r2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var r3 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var r4 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  curve25519_sqrmodp(r1, t1) // r1 = t1^2
  curve25519_sqrmodp(r2, t2) // r2 = t2^2
  curve25519_submodp(r3, r1, r2) // r3 = t1^2 - t2^2
  curve25519_mulmodp(r, r2, r1) //  r = t1^2 * t2^2
  curve25519_mulasmall(r2, r3, 121665) // r2 = (t1^2 - t2^2) * 121665
  curve25519_addmodp(r4, r2, r1) // r4 = (t1^2 - t2^2) * 121665 + t1^2
  curve25519_mulmodp(s, r4, r3) //  s = ((t1^2 - t2^2) * 121665 + t1^2) * (t1^2 - t2^2)
}

/****
 * BloodyRookie: Adding 2 points on a Montgomery curve:
 * R = Q + P = r/s when given
 * Q = x/z, P = x_p/z_p, P-Q = x_1/1
 * r = ((x-z)*(x_p+z_p) + (x+z)*(x_p-z_p))^2
 * s = x_1*((x-z)*(x_p+z_p) - (x+z)*(x_p-z_p))^2
 */
function curve25519_sum(r: any, s: any, t1: any, t2: any, t3: any, t4: any, x_1: any) {
  var r1 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var r2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var r3 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var r4 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  curve25519_mulmodp(r1, t2, t3) // r1 = t2 * t3
  curve25519_mulmodp(r2, t1, t4) // r2 = t1 * t4
  curve25519_addmodp(r3, r1, r2) // r3 = t2 * t3 + t1 * t4
  curve25519_submodp(r4, r1, r2) // r4 = t2 * t3 - t1 * t4
  curve25519_sqrmodp(r, r3) //  r = (t2 * t3 + t1 * t4)^2
  curve25519_sqrmodp(r1, r4) // r1 = (t2 * t3 - t1 * t4)^2
  curve25519_mulmodp(s, r1, x_1) //  s = (t2 * t3 - t1 * t4)^2 * x_1
}

export function curve25519_(f: any, c: any, s: any) {
  var j,
    a,
    x_1,
    q,
    fb,
    counter = 0
  var t = new Array(16) //, t1 = new Array(16), t2 = new Array(16), t3 = new Array(16), t4 = new Array(16);
  var sb = new Int8Array(32)
  var temp1 = new Int8Array(32)
  var temp2 = new Int8Array(64)
  var temp3 = new Int8Array(64)

  x_1 = c
  q = [curve25519_one(), curve25519_zero()]
  a = [x_1, curve25519_one()]

  var n = 255

  /**********************************************************************
   * BloodyRookie:                                                      *
   * Given f = f0*2^0 + f1*2^1 + ... + f255*2^255 and Basepoint a=9/1   *
   * calculate f*a by applying the Montgomery ladder (const time algo): *
   * r0 := 0 (point at infinity)                                        *
   * r1 := a                                                            *
   * for i from 255 to 0 do                                             *
   *   if fi = 0 then                                                   *
   *      r1 := r0 + r1                                                 *
   *      r0 := 2r0                                                     *
   *   else                                                             *
   *      r0 := r0 + r1                                                 *
   *      r1 := 2r1                                                     *
   *                                                                    *
   * Result: r0 = x-coordinate of f*a                                   *
   **********************************************************************/
  var r0 = new Array(new Array(16), new Array(16))
  var r1 = new Array(new Array(16), new Array(16))
  var t1 = new Array(16),
    t2 = new Array(16)
  var t3 = new Array(16),
    t4 = new Array(16)
  var fi
  while (n >= 0) {
    fi = curve25519_getbit(f, n)
    if (fi == 0) {
      curve25519_prep(t1, t2, a[0], a[1])
      curve25519_prep(t3, t4, q[0], q[1])
      curve25519_sum(r1[0], r1[1], t1, t2, t3, t4, x_1)
      curve25519_dbl(r0[0], r0[1], t3, t4)
    } else {
      curve25519_prep(t1, t2, q[0], q[1])
      curve25519_prep(t3, t4, a[0], a[1])
      curve25519_sum(r0[0], r0[1], t1, t2, t3, t4, x_1)
      curve25519_dbl(r1[0], r1[1], t3, t4)
    }
    q = r0
    a = r1
    n--
  }
  curve25519_invmodp(t, q[1], 0)
  curve25519_mulmodp(t1, q[0], t)
  q[0] = curve25519_cpy16(t1)

  // q[0]=x-coordinate of k*G=:Px
  // q[1]=z-coordinate of k*G=:Pz
  // a = q + G = P + G
  if (s != null) {
    /*************************************************************************
     * BloodyRookie: Recovery of the y-coordinate of point P:                *
     *                                                                       *
     * If P=(x,y), P1=(x1, y1), P2=(x2,y2) and P2 = P1 + P then              *
     *                                                                       *
     * y1 = ((x1 * x + 1)(x1 + x + 2A) - 2A - (x1 - x)^2 * x2)/2y            *
     *                                                                       *
     * Setting P2=Q, P1=P and P=G in the above formula we get                *
     *                                                                       *
     * Py =  ((Px * Gx + 1) * (Px + Gx + 2A) - 2A - (Px - Gx)^2 * Qx)/(2*Gy) *
     *    = -((Qx + Px + Gx + A) * (Px - Gx)^2 - Py^2 - Gy^2)/(2*Gy)         *
     *************************************************************************/
    t = curve25519_cpy16(q[0])
    curve25519_x_to_y2(t1, t) // t1 = Py^2
    curve25519_invmodp(t3, a[1], 0)
    curve25519_mulmodp(t2, a[0], t3) // t2 = (P+G)x = Qx
    curve25519_addmodp(t4, t2, t) // t4 =  Qx + Px
    curve25519_addmodp(t2, t4, curve25519_486671()) // t2 = Qx + Px + Gx + A
    curve25519_submodp(t4, t, curve25519_nine()) // t4 = Px - Gx
    curve25519_sqrmodp(t3, t4) // t3 = (Px - Gx)^2
    curve25519_mulmodp(t4, t2, t3) // t4 = (Qx + Px + Gx + A) * (Px - Gx)^2
    curve25519_submodp(t, t4, t1) //  t = (Qx + Px + Gx + A) * (Px - Gx)^2 - Py^2
    curve25519_submodp(t4, t, curve25519_39420360()) // t4 = (Qx + Px + Gx + A) * (Px - Gx)^2 - Py^2 - Gy^2
    curve25519_mulmodp(t1, t4, curve25519_r2y()) // t1 = ((Qx + Px + Gx + A) * (Px - Gx)^2 - Py^2 - Gy^2)/(2Gy) = -Py
    fb = curve25519_convertToByteArray(f)
    j = curve25519_isNegative(t1)
    if (j != 0) {
      /***
       * Py is positiv, so just copy
       */
      sb = curve25519_cpy32(fb)
    } else {
      /***
       * Py is negative:
       * We will take s = -f^-1 mod q instead of s=f^-1 mod q
       */
      curve25519_mula_small(sb, curve25519_order_times_8, 0, fb, 32, -1)
    }

    temp1 = curve25519_cpy32(curve25519_order)
    temp1 = curve25519_egcd32(temp2, temp3, sb, temp1)
    sb = curve25519_cpy32(temp1)
    if ((sb[31] & 0x80) != 0) {
      curve25519_mula_small(sb, sb, 0, curve25519_order, 32, 1)
    }
    var stmp = curve25519_convertToShortArray(sb)
    curve25519_fillShortArray(stmp, s)
  }

  return q[0]
}

// ==================================================================================================
// END INCLUDE FILE curve25519_.js
// ==================================================================================================

// ==================================================================================================
// START INCLUDE FILE curve25519.js
// ==================================================================================================

/* Ported to JavaScript from Java 07/01/14.
*
* Ported from C to Java by Dmitry Skiba [sahn0], 23/02/08.
* Original: http://cds.xs4all.nl:8081/ecdh/
*/
/* Generic 64-bit integer implementation of Curve25519 ECDH
* Written by Matthijs van Duin, 200608242056
* Public domain.
*
* Based on work by Daniel J Bernstein, http://cr.yp.to/ecdh.html
*/

export var curve25519 = (function() {
  //region Constants

  var KEY_SIZE = 32

  /* array length */
  var UNPACKED_SIZE = 16

  /* group order (a prime near 2^252+2^124) */
  var ORDER = [
    237,
    211,
    245,
    92,
    26,
    99,
    18,
    88,
    214,
    156,
    247,
    162,
    222,
    249,
    222,
    20,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    16
  ]

  /* smallest multiple of the order that's >= 2^255 */
  var ORDER_TIMES_8 = [
    104,
    159,
    174,
    231,
    210,
    24,
    147,
    192,
    178,
    230,
    188,
    23,
    245,
    206,
    247,
    166,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    128
  ]

  /* constants 2Gy and 1/(2Gy) */
  var BASE_2Y = [
    22587,
    610,
    29883,
    44076,
    15515,
    9479,
    25859,
    56197,
    23910,
    4462,
    17831,
    16322,
    62102,
    36542,
    52412,
    16035
  ]

  var BASE_R2Y = [
    5744,
    16384,
    61977,
    54121,
    8776,
    18501,
    26522,
    34893,
    23833,
    5823,
    55924,
    58749,
    24147,
    14085,
    13606,
    6080
  ]

  var C1 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var C9 = [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var C486671 = [0x6d0f, 0x0007, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var C39420360 = [0x81c8, 0x0259, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

  var P25 = 33554431 /* (1 << 25) - 1 */
  var P26 = 67108863 /* (1 << 26) - 1 */

  //#endregion

  //region Key Agreement

  /* Private key clamping
  *   k [out] your private key for key agreement
  *   k  [in]  32 random bytes
  */
  function clamp(k: any) {
    k[31] &= 0x7f
    k[31] |= 0x40
    k[0] &= 0xf8
  }

  //endregion

  //region radix 2^8 math

  function cpy32(d: any, s: any) {
    for (var i = 0; i < 32; i++) d[i] = s[i]
  }

  /* p[m..n+m-1] = q[m..n+m-1] + z * x */
  /* n is the size of x */
  /* n+m is the size of p and q */
  function mula_small(p: any, q: any, m: any, x: any, n: any, z: any) {
    m = m | 0
    n = n | 0
    z = z | 0

    var v = 0
    for (var i = 0; i < n; ++i) {
      v += (q[i + m] & 0xff) + z * (x[i] & 0xff)
      p[i + m] = v & 0xff
      v >>= 8
    }

    return v
  }

  /* p += x * y * z  where z is a small integer
  * x is size 32, y is size t, p is size 32+t
  * y is allowed to overlap with p+32 if you don't care about the upper half  */
  function mula32(p: any, x: any, y: any, t: any, z: any) {
    t = t | 0
    z = z | 0

    var n = 31
    var w = 0
    var i = 0
    for (; i < t; i++) {
      var zy = z * (y[i] & 0xff)
      w += mula_small(p, p, i, x, n, zy) + (p[i + n] & 0xff) + zy * (x[n] & 0xff)
      p[i + n] = w & 0xff
      w >>= 8
    }
    p[i + n] = (w + (p[i + n] & 0xff)) & 0xff
    return w >> 8
  }

  /* divide r (size n) by d (size t), returning quotient q and remainder r
  * quotient is size n-t+1, remainder is size t
  * requires t > 0 && d[t-1] !== 0
  * requires that r[-1] and d[-1] are valid memory locations
  * q may overlap with r+t */
  function divmod(q: any, r: any, n: any, d: any, t: any) {
    n = n | 0
    t = t | 0

    var rn = 0
    var dt = (d[t - 1] & 0xff) << 8
    if (t > 1) dt |= d[t - 2] & 0xff

    while (n-- >= t) {
      var z = (rn << 16) | ((r[n] & 0xff) << 8)
      if (n > 0) z |= r[n - 1] & 0xff

      var i = n - t + 1
      z /= dt
      rn += mula_small(r, r, i, d, t, -z)
      q[i] = (z + rn) & 0xff
      /* rn is 0 or -1 (underflow) */
      mula_small(r, r, i, d, t, -rn)
      rn = r[n] & 0xff
      r[n] = 0
    }

    r[t - 1] = rn & 0xff
  }

  function numsize(x: any, n: any) {
    while (n-- !== 0 && x[n] === 0) {}
    return n + 1
  }

  /* Returns x if a contains the gcd, y if b.
  * Also, the returned buffer contains the inverse of a mod b,
  * as 32-byte signed.
  * x and y must have 64 bytes space for temporary use.
  * requires that a[-1] and b[-1] are valid memory locations  */
  function egcd32(x: any, y: any, a: any, b: any) {
    var an,
      bn = 32,
      qn,
      i
    for (i = 0; i < 32; i++) x[i] = y[i] = 0
    x[0] = 1
    an = numsize(a, 32)
    if (an === 0) return y /* division by zero */
    var temp = new Array(32)
    while (true) {
      qn = bn - an + 1
      divmod(temp, b, bn, a, an)
      bn = numsize(b, bn)
      if (bn === 0) return x
      mula32(y, x, temp, qn, -1)

      qn = an - bn + 1
      divmod(temp, a, an, b, bn)
      an = numsize(a, an)
      if (an === 0) return y
      mula32(x, y, temp, qn, -1)
    }
  }

  //endregion

  //region radix 2^25.5 GF(2^255-19) math

  //region pack / unpack

  /* Convert to internal format from little-endian byte format */
  function unpack(x: any, m: any) {
    for (var i = 0; i < KEY_SIZE; i += 2) x[i / 2] = (m[i] & 0xff) | ((m[i + 1] & 0xff) << 8)
  }

  /* Check if reduced-form input >= 2^255-19 */
  function is_overflow(x: any) {
    return (
      (x[0] > P26 - 19 &&
        (x[1] & x[3] & x[5] & x[7] & x[9]) === P25 &&
        (x[2] & x[4] & x[6] & x[8]) === P26) ||
      x[9] > P25
    )
  }

  /* Convert from internal format to little-endian byte format.  The
  * number must be in a reduced form which is output by the following ops:
  *     unpack, mul, sqr
  *     set --  if input in range 0 .. P25
  * If you're unsure if the number is reduced, first multiply it by 1.  */
  function pack(x: any, m: any) {
    for (var i = 0; i < UNPACKED_SIZE; ++i) {
      m[2 * i] = x[i] & 0x00ff
      m[2 * i + 1] = (x[i] & 0xff00) >> 8
    }
  }

  //endregion

  function createUnpackedArray() {
    return new Uint16Array(UNPACKED_SIZE)
  }

  /* Copy a number */
  function cpy(d: any, s: any) {
    for (var i = 0; i < UNPACKED_SIZE; ++i) d[i] = s[i]
  }

  /* Set a number to value, which must be in range -185861411 .. 185861411 */
  function set(d: any, s: any) {
    d[0] = s
    for (var i = 1; i < UNPACKED_SIZE; ++i) d[i] = 0
  }

  /* Add/subtract two numbers.  The inputs must be in reduced form, and the
  * output isn't, so to do another addition or subtraction on the output,
  * first multiply it by one to reduce it. */
  var add = c255laddmodp
  var sub = c255lsubmodp

  /* Multiply a number by a small integer in range -185861411 .. 185861411.
  * The output is in reduced form, the input x need not be.  x and xy may point
  * to the same buffer. */
  var mul_small = c255lmulasmall

  /* Multiply two numbers.  The output is in reduced form, the inputs need not be. */
  var mul = c255lmulmodp

  /* Square a number.  Optimization of  mul25519(x2, x, x)  */
  var sqr = c255lsqrmodp

  /* Calculates a reciprocal.  The output is in reduced form, the inputs need not
  * be.  Simply calculates  y = x^(p-2)  so it's not too fast. */
  /* When sqrtassist is true, it instead calculates y = x^((p-5)/8) */
  function recip(y: any, x: any, sqrtassist: any) {
    var t0 = createUnpackedArray()
    var t1 = createUnpackedArray()
    var t2 = createUnpackedArray()
    var t3 = createUnpackedArray()
    var t4 = createUnpackedArray()

    /* the chain for x^(2^255-21) is straight from djb's implementation */
    var i
    sqr(t1, x) /*  2 === 2 * 1	*/
    sqr(t2, t1) /*  4 === 2 * 2	*/
    sqr(t0, t2) /*  8 === 2 * 4	*/
    mul(t2, t0, x) /*  9 === 8 + 1	*/
    mul(t0, t2, t1) /* 11 === 9 + 2	*/
    sqr(t1, t0) /* 22 === 2 * 11	*/
    mul(t3, t1, t2) /* 31 === 22 + 9 === 2^5   - 2^0	*/
    sqr(t1, t3) /* 2^6   - 2^1	*/
    sqr(t2, t1) /* 2^7   - 2^2	*/
    sqr(t1, t2) /* 2^8   - 2^3	*/
    sqr(t2, t1) /* 2^9   - 2^4	*/
    sqr(t1, t2) /* 2^10  - 2^5	*/
    mul(t2, t1, t3) /* 2^10  - 2^0	*/
    sqr(t1, t2) /* 2^11  - 2^1	*/
    sqr(t3, t1) /* 2^12  - 2^2	*/
    for (i = 1; i < 5; i++) {
      sqr(t1, t3)
      sqr(t3, t1)
    } /* 2^20  - 2^10	*/ /* t3 */
    mul(t1, t3, t2) /* 2^20  - 2^0	*/
    sqr(t3, t1) /* 2^21  - 2^1	*/
    sqr(t4, t3) /* 2^22  - 2^2	*/
    for (i = 1; i < 10; i++) {
      sqr(t3, t4)
      sqr(t4, t3)
    } /* 2^40  - 2^20	*/ /* t4 */
    mul(t3, t4, t1) /* 2^40  - 2^0	*/
    for (i = 0; i < 5; i++) {
      sqr(t1, t3)
      sqr(t3, t1)
    } /* 2^50  - 2^10	*/ /* t3 */
    mul(t1, t3, t2) /* 2^50  - 2^0	*/
    sqr(t2, t1) /* 2^51  - 2^1	*/
    sqr(t3, t2) /* 2^52  - 2^2	*/
    for (i = 1; i < 25; i++) {
      sqr(t2, t3)
      sqr(t3, t2)
    } /* 2^100 - 2^50 */ /* t3 */
    mul(t2, t3, t1) /* 2^100 - 2^0	*/
    sqr(t3, t2) /* 2^101 - 2^1	*/
    sqr(t4, t3) /* 2^102 - 2^2	*/
    for (i = 1; i < 50; i++) {
      sqr(t3, t4)
      sqr(t4, t3)
    } /* 2^200 - 2^100 */ /* t4 */
    mul(t3, t4, t2) /* 2^200 - 2^0	*/
    for (i = 0; i < 25; i++) {
      sqr(t4, t3)
      sqr(t3, t4)
    } /* 2^250 - 2^50	*/ /* t3 */
    mul(t2, t3, t1) /* 2^250 - 2^0	*/
    sqr(t1, t2) /* 2^251 - 2^1	*/
    sqr(t2, t1) /* 2^252 - 2^2	*/
    if (sqrtassist !== 0) {
      mul(y, x, t2) /* 2^252 - 3 */
    } else {
      sqr(t1, t2) /* 2^253 - 2^3	*/
      sqr(t2, t1) /* 2^254 - 2^4	*/
      sqr(t1, t2) /* 2^255 - 2^5	*/
      mul(y, t1, t0) /* 2^255 - 21	*/
    }
  }

  /* checks if x is "negative", requires reduced input */
  function is_negative(x: any) {
    var isOverflowOrNegative = is_overflow(x) || x[9] < 0
    var leastSignificantBit = x[0] & 1
    return ((isOverflowOrNegative ? 1 : 0) ^ leastSignificantBit) & 0xffffffff
  }

  /* a square root */
  function sqrt(x: any, u: any) {
    var v = createUnpackedArray()
    var t1 = createUnpackedArray()
    var t2 = createUnpackedArray()

    add(t1, u, u) /* t1 = 2u		*/
    recip(v, t1, 1) /* v = (2u)^((p-5)/8)	*/
    sqr(x, v) /* x = v^2		*/
    mul(t2, t1, x) /* t2 = 2uv^2		*/
    sub(t2, t2, C1) /* t2 = 2uv^2-1		*/
    mul(t1, v, t2) /* t1 = v(2uv^2-1)	*/
    mul(x, u, t1) /* x = uv(2uv^2-1)	*/
  }

  //endregion

  //region JavaScript Fast Math

  function c255lsqr8h(a7: any, a6: any, a5: any, a4: any, a3: any, a2: any, a1: any, a0: any) {
    var r = []
    var v
    r[0] = (v = a0 * a0) & 0xffff
    r[1] = (v = ((v / 0x10000) | 0) + 2 * a0 * a1) & 0xffff
    r[2] = (v = ((v / 0x10000) | 0) + 2 * a0 * a2 + a1 * a1) & 0xffff
    r[3] = (v = ((v / 0x10000) | 0) + 2 * a0 * a3 + 2 * a1 * a2) & 0xffff
    r[4] = (v = ((v / 0x10000) | 0) + 2 * a0 * a4 + 2 * a1 * a3 + a2 * a2) & 0xffff
    r[5] = (v = ((v / 0x10000) | 0) + 2 * a0 * a5 + 2 * a1 * a4 + 2 * a2 * a3) & 0xffff
    r[6] = (v = ((v / 0x10000) | 0) + 2 * a0 * a6 + 2 * a1 * a5 + 2 * a2 * a4 + a3 * a3) & 0xffff
    r[7] =
      (v = ((v / 0x10000) | 0) + 2 * a0 * a7 + 2 * a1 * a6 + 2 * a2 * a5 + 2 * a3 * a4) & 0xffff
    r[8] = (v = ((v / 0x10000) | 0) + 2 * a1 * a7 + 2 * a2 * a6 + 2 * a3 * a5 + a4 * a4) & 0xffff
    r[9] = (v = ((v / 0x10000) | 0) + 2 * a2 * a7 + 2 * a3 * a6 + 2 * a4 * a5) & 0xffff
    r[10] = (v = ((v / 0x10000) | 0) + 2 * a3 * a7 + 2 * a4 * a6 + a5 * a5) & 0xffff
    r[11] = (v = ((v / 0x10000) | 0) + 2 * a4 * a7 + 2 * a5 * a6) & 0xffff
    r[12] = (v = ((v / 0x10000) | 0) + 2 * a5 * a7 + a6 * a6) & 0xffff
    r[13] = (v = ((v / 0x10000) | 0) + 2 * a6 * a7) & 0xffff
    r[14] = (v = ((v / 0x10000) | 0) + a7 * a7) & 0xffff
    r[15] = (v / 0x10000) | 0
    return r
  }

  function c255lsqrmodp(r: any, a: any) {
    var x = c255lsqr8h(a[15], a[14], a[13], a[12], a[11], a[10], a[9], a[8])
    var z = c255lsqr8h(a[7], a[6], a[5], a[4], a[3], a[2], a[1], a[0])
    var y = c255lsqr8h(
      a[15] + a[7],
      a[14] + a[6],
      a[13] + a[5],
      a[12] + a[4],
      a[11] + a[3],
      a[10] + a[2],
      a[9] + a[1],
      a[8] + a[0]
    )

    var v
    r[0] = (v = 0x800000 + z[0] + (y[8] - x[8] - z[8] + x[0] - 0x80) * 38) & 0xffff
    r[1] = (v = 0x7fff80 + ((v / 0x10000) | 0) + z[1] + (y[9] - x[9] - z[9] + x[1]) * 38) & 0xffff
    r[2] =
      (v = 0x7fff80 + ((v / 0x10000) | 0) + z[2] + (y[10] - x[10] - z[10] + x[2]) * 38) & 0xffff
    r[3] =
      (v = 0x7fff80 + ((v / 0x10000) | 0) + z[3] + (y[11] - x[11] - z[11] + x[3]) * 38) & 0xffff
    r[4] =
      (v = 0x7fff80 + ((v / 0x10000) | 0) + z[4] + (y[12] - x[12] - z[12] + x[4]) * 38) & 0xffff
    r[5] =
      (v = 0x7fff80 + ((v / 0x10000) | 0) + z[5] + (y[13] - x[13] - z[13] + x[5]) * 38) & 0xffff
    r[6] =
      (v = 0x7fff80 + ((v / 0x10000) | 0) + z[6] + (y[14] - x[14] - z[14] + x[6]) * 38) & 0xffff
    r[7] =
      (v = 0x7fff80 + ((v / 0x10000) | 0) + z[7] + (y[15] - x[15] - z[15] + x[7]) * 38) & 0xffff
    r[8] = (v = 0x7fff80 + ((v / 0x10000) | 0) + z[8] + y[0] - x[0] - z[0] + x[8] * 38) & 0xffff
    r[9] = (v = 0x7fff80 + ((v / 0x10000) | 0) + z[9] + y[1] - x[1] - z[1] + x[9] * 38) & 0xffff
    r[10] = (v = 0x7fff80 + ((v / 0x10000) | 0) + z[10] + y[2] - x[2] - z[2] + x[10] * 38) & 0xffff
    r[11] = (v = 0x7fff80 + ((v / 0x10000) | 0) + z[11] + y[3] - x[3] - z[3] + x[11] * 38) & 0xffff
    r[12] = (v = 0x7fff80 + ((v / 0x10000) | 0) + z[12] + y[4] - x[4] - z[4] + x[12] * 38) & 0xffff
    r[13] = (v = 0x7fff80 + ((v / 0x10000) | 0) + z[13] + y[5] - x[5] - z[5] + x[13] * 38) & 0xffff
    r[14] = (v = 0x7fff80 + ((v / 0x10000) | 0) + z[14] + y[6] - x[6] - z[6] + x[14] * 38) & 0xffff
    var r15 = 0x7fff80 + ((v / 0x10000) | 0) + z[15] + y[7] - x[7] - z[7] + x[15] * 38
    c255lreduce(r, r15)
  }

  function c255lmul8h(
    a7: any,
    a6: any,
    a5: any,
    a4: any,
    a3: any,
    a2: any,
    a1: any,
    a0: any,
    b7: any,
    b6: any,
    b5: any,
    b4: any,
    b3: any,
    b2: any,
    b1: any,
    b0: any
  ) {
    var r = []
    var v
    r[0] = (v = a0 * b0) & 0xffff
    r[1] = (v = ((v / 0x10000) | 0) + a0 * b1 + a1 * b0) & 0xffff
    r[2] = (v = ((v / 0x10000) | 0) + a0 * b2 + a1 * b1 + a2 * b0) & 0xffff
    r[3] = (v = ((v / 0x10000) | 0) + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0) & 0xffff
    r[4] = (v = ((v / 0x10000) | 0) + a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0) & 0xffff
    r[5] =
      (v = ((v / 0x10000) | 0) + a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0) & 0xffff
    r[6] =
      (v =
        ((v / 0x10000) | 0) + a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0) &
      0xffff
    r[7] =
      (v =
        ((v / 0x10000) | 0) +
        a0 * b7 +
        a1 * b6 +
        a2 * b5 +
        a3 * b4 +
        a4 * b3 +
        a5 * b2 +
        a6 * b1 +
        a7 * b0) & 0xffff
    r[8] =
      (v =
        ((v / 0x10000) | 0) + a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2 + a7 * b1) &
      0xffff
    r[9] =
      (v = ((v / 0x10000) | 0) + a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 + a6 * b3 + a7 * b2) & 0xffff
    r[10] = (v = ((v / 0x10000) | 0) + a3 * b7 + a4 * b6 + a5 * b5 + a6 * b4 + a7 * b3) & 0xffff
    r[11] = (v = ((v / 0x10000) | 0) + a4 * b7 + a5 * b6 + a6 * b5 + a7 * b4) & 0xffff
    r[12] = (v = ((v / 0x10000) | 0) + a5 * b7 + a6 * b6 + a7 * b5) & 0xffff
    r[13] = (v = ((v / 0x10000) | 0) + a6 * b7 + a7 * b6) & 0xffff
    r[14] = (v = ((v / 0x10000) | 0) + a7 * b7) & 0xffff
    r[15] = (v / 0x10000) | 0
    return r
  }

  function c255lmulmodp(r: any, a: any, b: any) {
    // Karatsuba multiplication scheme: x*y = (b^2+b)*x1*y1 - b*(x1-x0)*(y1-y0) + (b+1)*x0*y0
    var x = c255lmul8h(
      a[15],
      a[14],
      a[13],
      a[12],
      a[11],
      a[10],
      a[9],
      a[8],
      b[15],
      b[14],
      b[13],
      b[12],
      b[11],
      b[10],
      b[9],
      b[8]
    )
    var z = c255lmul8h(
      a[7],
      a[6],
      a[5],
      a[4],
      a[3],
      a[2],
      a[1],
      a[0],
      b[7],
      b[6],
      b[5],
      b[4],
      b[3],
      b[2],
      b[1],
      b[0]
    )
    var y = c255lmul8h(
      a[15] + a[7],
      a[14] + a[6],
      a[13] + a[5],
      a[12] + a[4],
      a[11] + a[3],
      a[10] + a[2],
      a[9] + a[1],
      a[8] + a[0],
      b[15] + b[7],
      b[14] + b[6],
      b[13] + b[5],
      b[12] + b[4],
      b[11] + b[3],
      b[10] + b[2],
      b[9] + b[1],
      b[8] + b[0]
    )

    var v
    r[0] = (v = 0x800000 + z[0] + (y[8] - x[8] - z[8] + x[0] - 0x80) * 38) & 0xffff
    r[1] = (v = 0x7fff80 + ((v / 0x10000) | 0) + z[1] + (y[9] - x[9] - z[9] + x[1]) * 38) & 0xffff
    r[2] =
      (v = 0x7fff80 + ((v / 0x10000) | 0) + z[2] + (y[10] - x[10] - z[10] + x[2]) * 38) & 0xffff
    r[3] =
      (v = 0x7fff80 + ((v / 0x10000) | 0) + z[3] + (y[11] - x[11] - z[11] + x[3]) * 38) & 0xffff
    r[4] =
      (v = 0x7fff80 + ((v / 0x10000) | 0) + z[4] + (y[12] - x[12] - z[12] + x[4]) * 38) & 0xffff
    r[5] =
      (v = 0x7fff80 + ((v / 0x10000) | 0) + z[5] + (y[13] - x[13] - z[13] + x[5]) * 38) & 0xffff
    r[6] =
      (v = 0x7fff80 + ((v / 0x10000) | 0) + z[6] + (y[14] - x[14] - z[14] + x[6]) * 38) & 0xffff
    r[7] =
      (v = 0x7fff80 + ((v / 0x10000) | 0) + z[7] + (y[15] - x[15] - z[15] + x[7]) * 38) & 0xffff
    r[8] = (v = 0x7fff80 + ((v / 0x10000) | 0) + z[8] + y[0] - x[0] - z[0] + x[8] * 38) & 0xffff
    r[9] = (v = 0x7fff80 + ((v / 0x10000) | 0) + z[9] + y[1] - x[1] - z[1] + x[9] * 38) & 0xffff
    r[10] = (v = 0x7fff80 + ((v / 0x10000) | 0) + z[10] + y[2] - x[2] - z[2] + x[10] * 38) & 0xffff
    r[11] = (v = 0x7fff80 + ((v / 0x10000) | 0) + z[11] + y[3] - x[3] - z[3] + x[11] * 38) & 0xffff
    r[12] = (v = 0x7fff80 + ((v / 0x10000) | 0) + z[12] + y[4] - x[4] - z[4] + x[12] * 38) & 0xffff
    r[13] = (v = 0x7fff80 + ((v / 0x10000) | 0) + z[13] + y[5] - x[5] - z[5] + x[13] * 38) & 0xffff
    r[14] = (v = 0x7fff80 + ((v / 0x10000) | 0) + z[14] + y[6] - x[6] - z[6] + x[14] * 38) & 0xffff
    var r15 = 0x7fff80 + ((v / 0x10000) | 0) + z[15] + y[7] - x[7] - z[7] + x[15] * 38
    c255lreduce(r, r15)
  }

  function c255lreduce(a: any, a15: any) {
    var v = a15
    a[15] = v & 0x7fff
    v = ((v / 0x8000) | 0) * 19
    for (var i = 0; i <= 14; ++i) {
      a[i] = (v += a[i]) & 0xffff
      v = (v / 0x10000) | 0
    }

    a[15] += v
  }

  function c255laddmodp(r: any, a: any, b: any) {
    var v
    r[0] = (v = (((a[15] / 0x8000) | 0) + ((b[15] / 0x8000) | 0)) * 19 + a[0] + b[0]) & 0xffff
    for (var i = 1; i <= 14; ++i) r[i] = (v = ((v / 0x10000) | 0) + a[i] + b[i]) & 0xffff

    r[15] = ((v / 0x10000) | 0) + (a[15] & 0x7fff) + (b[15] & 0x7fff)
  }

  function c255lsubmodp(r: any, a: any, b: any) {
    var v
    r[0] =
      (v = 0x80000 + (((a[15] / 0x8000) | 0) - ((b[15] / 0x8000) | 0) - 1) * 19 + a[0] - b[0]) &
      0xffff
    for (var i = 1; i <= 14; ++i) r[i] = (v = ((v / 0x10000) | 0) + 0x7fff8 + a[i] - b[i]) & 0xffff

    r[15] = ((v / 0x10000) | 0) + 0x7ff8 + (a[15] & 0x7fff) - (b[15] & 0x7fff)
  }

  function c255lmulasmall(r: any, a: any, m: any) {
    var v
    r[0] = (v = a[0] * m) & 0xffff
    for (var i = 1; i <= 14; ++i) r[i] = (v = ((v / 0x10000) | 0) + a[i] * m) & 0xffff

    var r15 = ((v / 0x10000) | 0) + a[15] * m
    c255lreduce(r, r15)
  }

  //endregion

  /********************* Elliptic curve *********************/

  /* y^2 = x^3 + 486662 x^2 + x  over GF(2^255-19) */

  /* t1 = ax + az
  * t2 = ax - az  */
  function mont_prep(t1: any, t2: any, ax: any, az: any) {
    add(t1, ax, az)
    sub(t2, ax, az)
  }

  /* A = P + Q   where
  *  X(A) = ax/az
  *  X(P) = (t1+t2)/(t1-t2)
  *  X(Q) = (t3+t4)/(t3-t4)
  *  X(P-Q) = dx
  * clobbers t1 and t2, preserves t3 and t4  */
  function mont_add(t1: any, t2: any, t3: any, t4: any, ax: any, az: any, dx: any) {
    mul(ax, t2, t3)
    mul(az, t1, t4)
    add(t1, ax, az)
    sub(t2, ax, az)
    sqr(ax, t1)
    sqr(t1, t2)
    mul(az, t1, dx)
  }

  /* B = 2 * Q   where
  *  X(B) = bx/bz
  *  X(Q) = (t3+t4)/(t3-t4)
  * clobbers t1 and t2, preserves t3 and t4  */
  function mont_dbl(t1: any, t2: any, t3: any, t4: any, bx: any, bz: any) {
    sqr(t1, t3)
    sqr(t2, t4)
    mul(bx, t1, t2)
    sub(t2, t1, t2)
    mul_small(bz, t2, 121665)
    add(t1, t1, bz)
    mul(bz, t1, t2)
  }

  /* Y^2 = X^3 + 486662 X^2 + X
  * t is a temporary  */
  function x_to_y2(t: any, y2: any, x: any) {
    sqr(t, x)
    mul_small(y2, x, 486662)
    add(t, t, y2)
    add(t, t, C1)
    mul(y2, t, x)
  }

  /* P = kG   and  s = sign(P)/k  */
  function core(Px: any, s: any, k: any, Gx: any) {
    var dx = createUnpackedArray()
    var t1 = createUnpackedArray()
    var t2 = createUnpackedArray()
    var t3 = createUnpackedArray()
    var t4 = createUnpackedArray()
    var x = [createUnpackedArray(), createUnpackedArray()]
    var z = [createUnpackedArray(), createUnpackedArray()]
    var i, j

    /* unpack the base */
    if (Gx !== null) unpack(dx, Gx)
    else set(dx, 9)

    /* 0G = point-at-infinity */
    set(x[0], 1)
    set(z[0], 0)

    /* 1G = G */
    cpy(x[1], dx)
    set(z[1], 1)

    for (i = 32; i-- !== 0; ) {
      for (j = 8; j-- !== 0; ) {
        /* swap arguments depending on bit */
        var bit1 = ((k[i] & 0xff) >> j) & 1
        var bit0 = (~(k[i] & 0xff) >> j) & 1
        var ax = x[bit0]
        var az = z[bit0]
        var bx = x[bit1]
        var bz = z[bit1]

        /* a' = a + b	*/
        /* b' = 2 b	*/
        mont_prep(t1, t2, ax, az)
        mont_prep(t3, t4, bx, bz)
        mont_add(t1, t2, t3, t4, ax, az, dx)
        mont_dbl(t1, t2, t3, t4, bx, bz)
      }
    }

    recip(t1, z[0], 0)
    mul(dx, x[0], t1)

    pack(dx, Px)

    /* calculate s such that s abs(P) = G  .. assumes G is std base point */
    if (s !== null) {
      x_to_y2(t2, t1, dx) /* t1 = Py^2  */
      recip(t3, z[1], 0) /* where Q=P+G ... */
      mul(t2, x[1], t3) /* t2 = Qx  */
      add(t2, t2, dx) /* t2 = Qx + Px  */
      add(t2, t2, C486671) /* t2 = Qx + Px + Gx + 486662  */
      sub(dx, dx, C9) /* dx = Px - Gx  */
      sqr(t3, dx) /* t3 = (Px - Gx)^2  */
      mul(dx, t2, t3) /* dx = t2 (Px - Gx)^2  */
      sub(dx, dx, t1) /* dx = t2 (Px - Gx)^2 - Py^2  */
      sub(dx, dx, C39420360) /* dx = t2 (Px - Gx)^2 - Py^2 - Gy^2  */
      mul(t1, dx, BASE_R2Y) /* t1 = -Py  */

      if (is_negative(t1) !== 0)
        /* sign is 1, so just copy  */
        cpy32(s, k)
      /* sign is -1, so negate  */ else mula_small(s, ORDER_TIMES_8, 0, k, 32, -1)

      /* reduce s mod q
       * (is this needed?  do it just in case, it's fast anyway) */
      //divmod((dstptr) t1, s, 32, order25519, 32);

      /* take reciprocal of s mod q */
      var temp1 = new Array(32)
      var temp2 = new Array(64)
      var temp3 = new Array(64)
      cpy32(temp1, ORDER)
      cpy32(s, egcd32(temp2, temp3, s, temp1))
      if ((s[31] & 0x80) !== 0) mula_small(s, s, 0, ORDER, 32, 1)
    }
  }

  /********* DIGITAL SIGNATURES *********/

  /* deterministic EC-KCDSA
  *
  *    s is the private key for signing
  *    P is the corresponding public key
  *    Z is the context data (signer public key or certificate, etc)
  *
  * signing:
  *
  *    m = hash(Z, message)
  *    x = hash(m, s)
  *    keygen25519(Y, NULL, x);
  *    r = hash(Y);
  *    h = m XOR r
  *    sign25519(v, h, x, s);
  *
  *    output (v,r) as the signature
  *
  * verification:
  *
  *    m = hash(Z, message);
  *    h = m XOR r
  *    verify25519(Y, v, h, P)
  *
  *    confirm  r === hash(Y)
  *
  * It would seem to me that it would be simpler to have the signer directly do
  * h = hash(m, Y) and send that to the recipient instead of r, who can verify
  * the signature by checking h === hash(m, Y).  If there are any problems with
  * such a scheme, please let me know.
  *
  * Also, EC-KCDSA (like most DS algorithms) picks x random, which is a waste of
  * perfectly good entropy, but does allow Y to be calculated in advance of (or
  * parallel to) hashing the message.
  */

  /* Signature generation primitive, calculates (x-h)s mod q
  *   h  [in]  signature hash (of message, signature pub key, and context data)
  *   x  [in]  signature private key
  *   s  [in]  private key for signing
  * returns signature value on success, undefined on failure (use different x or h)
  */

  function sign(h: any, x: any, s: any) {
    // v = (x - h) s  mod q
    var w, i
    var h1 = new Array(32)
    var x1 = new Array(32)
    var tmp1 = new Array(64)
    var tmp2 = new Array(64)

    // Don't clobber the arguments, be nice!
    cpy32(h1, h)
    cpy32(x1, x)

    // Reduce modulo group order
    var tmp3 = new Array(32)
    divmod(tmp3, h1, 32, ORDER, 32)
    divmod(tmp3, x1, 32, ORDER, 32)

    // v = x1 - h1
    // If v is negative, add the group order to it to become positive.
    // If v was already positive we don't have to worry about overflow
    // when adding the order because v < ORDER and 2*ORDER < 2^256
    var v = new Array(32)
    mula_small(v, x1, 0, h1, 32, -1)
    mula_small(v, v, 0, ORDER, 32, 1)

    // tmp1 = (x-h)*s mod q
    mula32(tmp1, v, s, 32, 1)
    divmod(tmp2, tmp1, 64, ORDER, 32)

    for (w = 0, i = 0; i < 32; i++) w |= v[i] = tmp1[i]

    return w !== 0 ? v : undefined
  }

  /* Signature verification primitive, calculates Y = vP + hG
  *   v  [in]  signature value
  *   h  [in]  signature hash
  *   P  [in]  public key
  *   Returns signature public key
  */
  function verify(v: any, h: any, P: any) {
    /* Y = v abs(P) + h G  */
    var d = new Array(32)
    var p = [createUnpackedArray(), createUnpackedArray()]
    var s = [createUnpackedArray(), createUnpackedArray()]
    var yx = [createUnpackedArray(), createUnpackedArray(), createUnpackedArray()]
    var yz = [createUnpackedArray(), createUnpackedArray(), createUnpackedArray()]
    var t1 = [createUnpackedArray(), createUnpackedArray(), createUnpackedArray()]
    var t2 = [createUnpackedArray(), createUnpackedArray(), createUnpackedArray()]

    var vi = 0,
      hi = 0,
      di = 0,
      nvh = 0,
      i,
      j,
      k

    /* set p[0] to G and p[1] to P  */

    set(p[0], 9)
    unpack(p[1], P)

    /* set s[0] to P+G and s[1] to P-G  */

    /* s[0] = (Py^2 + Gy^2 - 2 Py Gy)/(Px - Gx)^2 - Px - Gx - 486662  */
    /* s[1] = (Py^2 + Gy^2 + 2 Py Gy)/(Px - Gx)^2 - Px - Gx - 486662  */

    x_to_y2(t1[0], t2[0], p[1]) /* t2[0] = Py^2  */
    sqrt(t1[0], t2[0]) /* t1[0] = Py or -Py  */
    j = is_negative(t1[0]) /*      ... check which  */
    add(t2[0], t2[0], C39420360) /* t2[0] = Py^2 + Gy^2  */
    mul(t2[1], BASE_2Y, t1[0]) /* t2[1] = 2 Py Gy or -2 Py Gy  */
    sub(t1[j], t2[0], t2[1]) /* t1[0] = Py^2 + Gy^2 - 2 Py Gy  */
    add(t1[1 - j], t2[0], t2[1]) /* t1[1] = Py^2 + Gy^2 + 2 Py Gy  */
    cpy(t2[0], p[1]) /* t2[0] = Px  */
    sub(t2[0], t2[0], C9) /* t2[0] = Px - Gx  */
    sqr(t2[1], t2[0]) /* t2[1] = (Px - Gx)^2  */
    recip(t2[0], t2[1], 0) /* t2[0] = 1/(Px - Gx)^2  */
    mul(s[0], t1[0], t2[0]) /* s[0] = t1[0]/(Px - Gx)^2  */
    sub(s[0], s[0], p[1]) /* s[0] = t1[0]/(Px - Gx)^2 - Px  */
    sub(s[0], s[0], C486671) /* s[0] = X(P+G)  */
    mul(s[1], t1[1], t2[0]) /* s[1] = t1[1]/(Px - Gx)^2  */
    sub(s[1], s[1], p[1]) /* s[1] = t1[1]/(Px - Gx)^2 - Px  */
    sub(s[1], s[1], C486671) /* s[1] = X(P-G)  */
    mul_small(s[0], s[0], 1) /* reduce s[0] */
    mul_small(s[1], s[1], 1) /* reduce s[1] */

    /* prepare the chain  */
    for (i = 0; i < 32; i++) {
      vi = (vi >> 8) ^ (v[i] & 0xff) ^ ((v[i] & 0xff) << 1)
      hi = (hi >> 8) ^ (h[i] & 0xff) ^ ((h[i] & 0xff) << 1)
      nvh = ~(vi ^ hi)
      di = (nvh & ((di & 0x80) >> 7)) ^ vi
      di ^= nvh & ((di & 0x01) << 1)
      di ^= nvh & ((di & 0x02) << 1)
      di ^= nvh & ((di & 0x04) << 1)
      di ^= nvh & ((di & 0x08) << 1)
      di ^= nvh & ((di & 0x10) << 1)
      di ^= nvh & ((di & 0x20) << 1)
      di ^= nvh & ((di & 0x40) << 1)
      d[i] = di & 0xff
    }

    di = ((nvh & ((di & 0x80) << 1)) ^ vi) >> 8

    /* initialize state */
    set(yx[0], 1)
    cpy(yx[1], p[di])
    cpy(yx[2], s[0])
    set(yz[0], 0)
    set(yz[1], 1)
    set(yz[2], 1)

    /* y[0] is (even)P + (even)G
     * y[1] is (even)P + (odd)G  if current d-bit is 0
     * y[1] is (odd)P + (even)G  if current d-bit is 1
     * y[2] is (odd)P + (odd)G
     */

    vi = 0
    hi = 0

    /* and go for it! */
    for (i = 32; i-- !== 0; ) {
      vi = (vi << 8) | (v[i] & 0xff)
      hi = (hi << 8) | (h[i] & 0xff)
      di = (di << 8) | (d[i] & 0xff)

      for (j = 8; j-- !== 0; ) {
        mont_prep(t1[0], t2[0], yx[0], yz[0])
        mont_prep(t1[1], t2[1], yx[1], yz[1])
        mont_prep(t1[2], t2[2], yx[2], yz[2])

        k = (((vi ^ (vi >> 1)) >> j) & 1) + (((hi ^ (hi >> 1)) >> j) & 1)
        mont_dbl(yx[2], yz[2], t1[k], t2[k], yx[0], yz[0])

        k = ((di >> j) & 2) ^ (((di >> j) & 1) << 1)
        mont_add(t1[1], t2[1], t1[k], t2[k], yx[1], yz[1], p[(di >> j) & 1])

        mont_add(t1[2], t2[2], t1[0], t2[0], yx[2], yz[2], s[(((vi ^ hi) >> j) & 2) >> 1])
      }
    }

    k = (vi & 1) + (hi & 1)
    recip(t1[0], yz[k], 0)
    mul(t1[1], yx[k], t1[0])

    var Y: any[] = []
    pack(t1[1], Y)
    return Y
  }

  /* Key-pair generation
  *   P  [out] your public key
  *   s  [out] your private key for signing
  *   k  [out] your private key for key agreement
  *   k  [in]  32 random bytes
  * s may be NULL if you don't care
  *
  * WARNING: if s is not NULL, this function has data-dependent timing */
  function keygen(k: any) {
    var P: any[] = []
    var s: any[] = []
    k = k || []
    clamp(k)
    core(P, s, k, null)

    return { p: P, s: s, k: k }
  }

  return {
    sign: sign,
    verify: verify,
    keygen: keygen
  }
})()

// ==================================================================================================
// END INCLUDE FILE curve25519.js
// ==================================================================================================
