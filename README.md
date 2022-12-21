# curve25519

Copyright (c) 2007 Michele Bini

Konstantin Welke, 2008:

  - moved into .js file, renamed all c255lname to curve25519_name
  - added curve25519_clamp()
  - functions to read from/to 8bit string
  - removed base32/hex functions (cleanup)
  - removed setbit function (cleanup, had a bug anyway)

BloodyRookie 2014:

  - ported part of the java implementation by Dmitry Skiba to js and merged into this file
  - profiled for higher speed

## Licence

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA. */

The original curve25519 library was released into the public domain
by Daniel J. Bernstein