.. _device-tree/ibm,secureboot/secvar:

secvar
======

The ``secvar`` node provides secure variable information for the secure
boot of the target OS.

Required properties
-------------------

.. code-block:: none

    compatible:         this property is set based on the current secure
                        variable scheme as set by the platform.

    status:             set to "fail" if the secure variables could not
                        be initialized, validated, or some other
                        catastrophic failure.

    update-status:      contains the return code of the update queue
                        process run during initialization. Signifies if
                        updates were processed or not, and if there was
                        an error. See table below

    secure-mode:        a u64 bitfield set by the backend to determine
                        what secure mode we should be in, and if host
                        secure boot should be enforced.

Example
-------

.. code-block:: dts

    secvar {
        compatible = "ibm,edk2-compat-v1";
        status = "okay";
        secure-mode = "1";
    };

Update Status
-------------

The update status property should be set by the backend driver to a value
that best fits its error condtion. The following table defines the
general intent of each error code, check backend specific documentation
for more detail.

+-----------------+-----------------------------------------------+
| update-status   | Generic Reason                                |
+-----------------|-----------------------------------------------+
| OPAL_SUCCESS    | Updates were found and processed successfully |
+-----------------|-----------------------------------------------+
| OPAL_EMPTY      | No updates were found, none processed         |
+-----------------|-----------------------------------------------+
| OPAL_PARAMETER  | Unable to parse data in the update section    |
+-----------------|-----------------------------------------------+
| OPAL_PERMISSION | Update failed to apply, possible auth failure |
+-----------------|-----------------------------------------------+
| OPAL_HARDWARE   | Misc. storage-related error                   |
+-----------------|-----------------------------------------------+
| OPAL_RESOURCE   | Out of space (somewhere)                      |
+-----------------|-----------------------------------------------+
| OPAL_NO_MEM     | Out of memory                                 |
+-----------------+-----------------------------------------------+

Secure Mode
-----------

+-----------------------+------------------------+
| backend specific-bits |      generic mode bits |
+-----------------------+------------------------+
64                     32                        0

The secure mode property should be set by the backend driver. The least
significant 32 bits are reserved for generic modes, shared across all
possible backends. The other 32 bits are open for backends to determine
their own modes. Any kernel must be made aware of any custom modes.

At the moment, only one general-purpose bit is defined:

``#define SECVAR_SECURE_MODE_ENFORCING  0x1``

which signals that a kernel should enforce host secure boot.
