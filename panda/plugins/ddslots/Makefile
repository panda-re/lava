# Don't forget to add your plugin to config.panda!

# Include the PANDA Makefile rules
#include $(SRC_PATH)/panda/plugins/extra_plugins_panda.mak
#include ../extra_plugins_panda.mak

# If you need custom CFLAGS or LIBS, set them up here
#CXXFLAGS+= -I$(SRC_PATH)/panda_tools/pirate_utils/linux
#CXXFLAGS += -I../../../include
QEMU_CXXFLAGS += -I$(EXTRA_PLUGINS_PATH)/include
# LIBS+=
#QEMU_CXXFLAGS+= -std=c++11

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
	$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o
