.. _device-tree/ibm,opal/secvar:

secvar
======

The ``secvar`` node provides secure variable information for the secure
boot of the target OS.

Required properties
-------------------

.. code-block:: none

    status:             set to "fail" if the secure variables could not
                        be initialized, validated, or some other
                        hardware problem.

    update-status:      contains the return code of the update queue
                        process run during initialization. Signifies if
                        updates were processed or not, and if there was
                        an error. See table below.
                        TODO: This probably belongs in the backend node.

    os-secure-enforcing: If this property exists, the system is in
                        considered to be in "OS secure mode". Kexec
                        images should be signature checked, etc.

    backend:            This node contains any backend-specific
                        information, and is maintained by the backend driver.

    storage:            This node contains any storage-specific
                        information, and is mainted by the storage driver.

    max-var-size:       This property must be exposed as a child of the
                        storage driver, and determines how large a
                        variable can be.

Example
-------

.. code-block:: dts

    secvar {
        compatible = "ibm,secvar-v1";
        status = "okay";
        os-secure-enforcing = <0x0>;
        update-status = <0x0>;
        storage {
            compatible = "ibm,secboot-tpm-v1";
            status = "okay";
            max-var-size = <0x1000>;
        }
        backend {
            compatible = "ibm,edk2-compat-v1";
            status = "okay";
        }
    };

Update Status
-------------

The update status property should be set by the backend driver to a value
that best fits its error condition. The following table defines the
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

