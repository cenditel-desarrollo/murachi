# EstEID Browser Plugin
CC = gcc
COMMON_HEADERS = common/esteid_certinfo.h common/pkcs11_errors.h common/esteid_log.h common/esteid_sign.h common/esteid_timer.h common/esteid_time.h common/l10n.h common/labels.h common/esteid_map.h common/esteid_dialog_common.h 
COMMON_SOURCES = common/esteid_certinfo.c common/pkcs11_errors.c common/esteid_log.c common/esteid_sign.c common/esteid_timer.c common/esteid_time.c common/l10n.c common/l10n-linux.c common/esteid_map.c common/esteid_dialog_common.c
C_FLAGS = -g -O2 -std=gnu99 -Wall $(CPPFLAGS)
I_FLAGS = -Iinclude -Icommon `pkg-config --cflags gtk+-2.0`
L_FLAGS = -ldl -lcrypto -lpthread `pkg-config --libs gtk+-2.0`
D_FLAGS = -DXP_UNIX -DMOZ_X11
PLUGIN_HEADERS = firefox/plugin.h firefox/plugin-class.h firefox/cert-class.h
PLUGIN_SOURCES = firefox/plugin.c firefox/plugin-class.c firefox/cert-class.c

clean:
	rm -f test
	rm -f npesteid-firefox-plugin.so

plugin: $(COMMON_HEADERS) $(COMMON_SOURCES) $(PLUGIN_HEADERS) $(PLUGIN_SOURCES) firefox/dialogs-gtk.c common/dialogs.h
	$(CC) $(C_FLAGS) -fPIC -shared -o npesteid-firefox-plugin.so $(PLUGIN_SOURCES) firefox/dialogs-gtk.c $(COMMON_SOURCES) $(I_FLAGS) $(L_FLAGS) $(D_FLAGS) $(MODE_FLAG)

plugin-development:
	MODE_FLAG=-DDEVELOPMENT_MODE make plugin 

install: plugin
#	install -d $(HOME)/.mozilla/plugins
#	install firefox-plugin.so $(HOME)/.mozilla/plugins

maptest: plugin common/esteid_map_test.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(C_FLAGS) common/esteid_map.c common/esteid_map_test.c -o maptest
	./maptest
	rm maptest
