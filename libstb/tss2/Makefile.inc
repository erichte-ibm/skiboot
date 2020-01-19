# -*-Makefile-*-

TSS2_DIR = libstb/tss2
IBMTSS_DIR = $(TSS2_DIR)/ibmtpm20tss/utils

SUBDIRS += $(TSS2_DIR) $(IBMTSS_DIR)

CPPFLAGS += -I$(SRC)/$(TSS2_DIR)
CPPFLAGS += -I$(SRC)/$(IBMTSS_DIR)

TSS2LIB_SRCS = tss.c tss20.c tssauth.c tssauth20.c tssccattributes.c
#TSS2LIB_SRCS += tsscryptoh.c
TSS2LIB_SRCS += tssmarshal.c tssprint.c tssprintcmd.c tssproperties.c
TSS2LIB_SRCS += tssresponsecode.c tsstransmit.c tssutils.c tssntc.c
TSS2LIB_SRCS += Commands.c CommandAttributeData.c Unmarshal.c
TSS2LIB_SRCS += tssdevskiboot.c

TSS2_SRCS = $(addprefix ibmtpm20tss/utils/,$(TSS2LIB_SRCS))
TSS2_SRCS += tpm2.c tssskiboot.c

#tsscryptombed.c tsscryptouv.c tssdevuv.c tssuv.c
#tssskiboot.c eventlog.c eventlib.c tpm_nv.c opalcreate.c

TSS2_OBJS = $(TSS2_SRCS:%.c=%.o)

CFLAGS_$(TSS2_DIR)/ = -DTPM_POSIX -DTPM_TPM20 -DTPM_SKIBOOT
CFLAGS_$(TSS2_DIR)/ += -DTPM_NOSOCKET
CFLAGS_$(TSS2_DIR)/ += -DTPM_TSS_NOECC -DTPM_TSS_NORSA -DTPM_TSS_NOCRYPTO
CFLAGS_$(TSS2_DIR)/ += -DTPM_TSS_NOFILE -DTPM_TSS_NOENV
CFLAGS_$(TSS2_DIR)/ += -Wstack-usage=4096

CFLAGS_$(IBMTSS_DIR)/ = $(CFLAGS_$(TSS2_DIR)/)

CFLAGS_SKIP_$(TSS2_DIR)/ = -Wsuggest-attribute=const
CFLAGS_SKIP_$(IBMTSS_DIR)/ = $(CFLAGS_SKIP_$(TSS2_DIR)/)

TSS2 = $(TSS2_DIR)/built-in.a

$(TSS2): $(TSS2_OBJS:%=$(TSS2_DIR)/%)
