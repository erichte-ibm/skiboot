.. _secvar/secboot_tpm:

secboot_tpm secvar storage driver for P9 platforms
==================================================

Overview
--------

This storage driver utilizes the SECBOOT PNOR partition and TPM NV space to
persist secure variables across reboots in a tamper-resistant manner. While
writes to PNOR cannot be completely prevented, writes CAN be prevented to TPM
NV. On the other hand, there is limited available space in TPM NV.

Therefore, this driver uses both in conjunction: large variable data is written
to SECBOOT, and a hash of all stored variable data is stored in PNOR. When the
variables are loaded from SECBOOT, this hash is recalculated and compared
against the value stored in the TPM. If they do not match, then the variables
must have been tampered with and are not loaded.

See the following sections for more information on the internals of the driver.

*[TODO: needs section on resetting/physical presence probably]*

TPM NV Indices
--------------

The driver utilizes two TPM NV indices:

.. code-block:: c

  #define SECBOOT_TPMNV_VARS_INDEX	0x01c10190
  #define SECBOOT_TPMNV_CONTROL_INDEX	0x01c10191

The ``VARS`` index stores priority variables, that for some reason cannot be
stored in the SECBOOT partition (see the Priority Variables section). This index
is defined to be 1024 bytes in size, which is the maximum NV index size
supported by the npct650 chip *[citation needed].* 

The ``CONTROL`` index stores the bank hashes, and the bit to determine which
bank is active. See the Active/Staging Bank Swapping section for more.

Both indices are defined on first boot with the same set of attributes. If the
indices are already defined, but the attributes do NOT match, then the driver
will halt the boot. Asserting physical presence will undefine the indices.

*[should we mention the attributes in here?]*
*[move this to the end maybe?]*

Storage Layouts
---------------

At a high-level, there are a few major logical components:

 - Variable storage (split in half, active/staging)
 - Update storage
 - Priority variable storage
 - Bank hashes & active bit

Variable storage consists of two smaller banks, variable bank 0 and variable
bank 1. Either of the banks may be designated "active" by setting the active
bank bit to either 0 or 1, indicating that the corresponding bank is now
"active". The other bank is then considered "staging". See the "Persisting
Variable Bank Updates" for more on the active/staging bank logic.

Priority variable storage is stored in ``VARS`` TPM NV index. Unlike the other
variable storage, there is only one bank due to limited storage space.


SECBOOT (PNOR)
^^^^^^^^^^^^^^
*TODO MAKE THESE FANCY TABLES OR SOMETHING*

Partition Format:
 - 8b secboot header
   - 4b: u32. magic number, always 0x5053424b
   - 1b: u8. version, always 1
   - 3b: unused padding
 - 32k variable bank 0
 - 32k variable bank 1
 - 32k update bank

Variable Format:
 - 8b: u64. key length
 - 8b: u64. data size
 - 1k: string. key
 - (data size). data

TPM VARS (NV)
^^^^^^^^^^^^^
*TODO MAKE THESE FANCY TABLES OR SOMETHING*

NV Index Format:
 - 8b secboot header
   - 4b: u32. magic number, always 0x5053424b
   - 1b: u8. version, always 1
   - 3b: unused padding
 - 1016b variable data

Variable Format:
 - 8b: u64. key length
 - 8b: u64. data size
 - (key length): string. key
 - (data size). data

*[i'm really considering just making this the default storage method, why are we
wasting a full 1k on three-letter variable names...]*
TPM CONTROL (NV)
^^^^^^^^^^^^^^^^
*TODO MAKE THESE FANCY TABLES OR SOMETHING*

 - 8b secboot header
   - 4b: u32. magic number, always 0x5053424b
   - 1b: u8. version, always 1
   - 3b: unused padding
 - 1b: u8. active bit, 0 or 1
 - 32b: sha256 hash of variable bank 0
 - 32b: sha256 hash of variable bank 1


Persisting Variable Bank Updates
--------------------------------

When writing a new variable bank to storage, this is (roughly) the procedure the
driver will follow:

0. load variables from the active bank, process using variables in the active
    bank
1. write variables to the staging bank
2. calculate hash of the staging bank
3. store the staging bank hash in the TPM NV
4. flip the active bank bit

This procedure is to ensure that the switch-over from the old variables to the
new variables is as atomic as possible. If, for example, power was cut when
writing the variables to PNOR, the machine on next boot will still be loading
the old variables (validated against the old bank hash), as the active bit was
not yet flipped.

The bank hashes are a SHA256 hash calculated over the whole region of
memory/storage space allocated to the bank, included unused memory. For
consistency, unused space is always written as zeroes. Like the variable banks,
there are also two bank hashes stored in the TPM, and the index (0 or 1) always
corresponds with the matching variable bank index (0 or 1). *[index is annoyingly
overloaded here, is it clear it's not talking about nv index?]*

Locking
-------

PNOR cannot be locked, however the TPM can be. This driver utilizes two locking
mechanisms for the TPM NV indices:

 - The TPM NV indices are defined with a set of attributes that prevent them
from being written to without the proper authentication. This is handled outside
of this driver, but in short: after secvar operations are completed, the indices
are locked with a random password that is thrown away. (TODO please rewrite,
this is not a good short summary)

 - The ``TSS_NV_WriteLock`` TPM command is sent in the driver ``.lock()`` hook.
While this isn't entirely necessary in combination with setting the platform
auth, there is also no reason not to lock it in this manner as well.

