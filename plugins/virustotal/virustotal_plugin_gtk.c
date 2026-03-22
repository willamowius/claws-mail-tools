/*
 * Claws Mail -- VirusTotal plugin
 * Copyright (C) 2026 Jan Willamowius <jan@willamowius>
 * Copyright (C) 1999-2026 the Claws Mail team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 * 
 */


#ifdef HAVE_CONFIG_H
#  include "config.h"
#  include "claws-features.h"
#endif

#include <glib.h>
#include <glib/gi18n.h>

#include "defs.h"

#include <gtk/gtk.h>
#include <gtk/gtkutils.h>

#include "common/claws.h"
#include "common/version.h"
#include "plugin.h"
#include "utils.h"
#include "prefs.h"
#include "folder.h"
#include "prefs_gtk.h"
#include "foldersel.h"
#include "statusbar.h"
#include "alertpanel.h"
#include "virustotal_plugin.h"

struct VirusTotalPage
{
	PrefsPage page;
	
	GtkWidget *enable_virustotal;
	GtkWidget *api_key;
	GtkWidget *recv_infected;
	GtkWidget *save_folder;
};

static void foldersel_cb(GtkWidget *widget, gpointer data)
{
	struct VirusTotalPage *page = (struct VirusTotalPage *) data;
	FolderItem *item;
	gchar *item_id;
	gint newpos = 0;
	
	item = foldersel_folder_sel(NULL, FOLDER_SEL_MOVE, NULL, FALSE,
			_("Select folder to store infected messages in"));
	if (item && (item_id = folder_item_get_identifier(item)) != NULL) {
		gtk_editable_delete_text(GTK_EDITABLE(page->save_folder), 0, -1);
		gtk_editable_insert_text(GTK_EDITABLE(page->save_folder), item_id, strlen(item_id), &newpos);
		g_free(item_id);
	}
}

static void virustotal_create_widget_func(PrefsPage * _page, GtkWindow *window, gpointer data)
{
	struct VirusTotalPage *page = (struct VirusTotalPage *) _page;
	VirusTotalConfig *config;
 	 
	GtkWidget *vbox1, *vbox2;
	GtkWidget *warning_label;
	GtkWidget *enable_virustotal;
	GtkWidget *hbox1;
	GtkWidget *api_key_label;
	GtkWidget *api_key;
	GtkWidget *hbox2;
  	GtkWidget *recv_infected;
  	GtkWidget *save_folder;
  	GtkWidget *save_folder_select;

	enable_virustotal = page->enable_virustotal;

	vbox1 = gtk_box_new(GTK_ORIENTATION_VERTICAL, VSPACING);
	gtk_widget_show (vbox1);
	gtk_container_set_border_width (GTK_CONTAINER (vbox1), VBOX_BORDER);

	vbox2 = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
	gtk_widget_show (vbox2);
	gtk_box_pack_start (GTK_BOX (vbox1), vbox2, FALSE, FALSE, 0);

	warning_label = gtk_label_new(_("CAUTION:\nVirusTotal is a service owned by Google and operated on servers in the USA.\n"
			"When you activate it, your IP, your API key and the checksum of your attachments "
			"are sent to VirusTotal for scanning. Please beware of these privacy implications.\n"));
	gtk_label_set_line_wrap(GTK_LABEL(warning_label), TRUE);
	gtk_widget_show (warning_label);
	gtk_box_pack_start (GTK_BOX (vbox2), warning_label, FALSE, FALSE, 0);

	PACK_CHECK_BUTTON (vbox2, enable_virustotal, _("Enable virus scanning"));

  	hbox1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
	gtk_widget_show (hbox1);
	gtk_box_pack_start (GTK_BOX (vbox2), hbox1, FALSE, FALSE, 0);

	api_key_label = gtk_label_new(_("VirusTotal API key"));
	gtk_widget_show (api_key_label);
	gtk_box_pack_start (GTK_BOX (hbox1), api_key_label, FALSE, FALSE, 0);

	api_key = gtk_entry_new ();
	gtk_widget_show (api_key);
	gtk_box_pack_start (GTK_BOX (hbox1), api_key, TRUE, TRUE, 0);
	gtk_widget_set_tooltip_text(api_key,
			     _("Your VirusTotal API key, sign up at https://www.virustotal.com"));
 	SET_TOGGLE_SENSITIVITY (enable_virustotal, api_key);

  	hbox2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
	gtk_widget_show (hbox2);
	gtk_box_pack_start (GTK_BOX (vbox2), hbox2, FALSE, FALSE, 0);

 	recv_infected = gtk_check_button_new_with_label(_("Save infected mail in"));
	gtk_widget_show (recv_infected);
	gtk_box_pack_start (GTK_BOX (hbox2), recv_infected, FALSE, FALSE, 0);
	gtk_widget_set_tooltip_text(recv_infected,
			     _("Save mail that contains viruses"));
 	SET_TOGGLE_SENSITIVITY (enable_virustotal, recv_infected);

  	save_folder = gtk_entry_new ();
	gtk_widget_show (save_folder);
	gtk_box_pack_start (GTK_BOX (hbox2), save_folder, TRUE, TRUE, 0);
	gtk_widget_set_tooltip_text(save_folder,
			     _("Folder for storing infected mail. Leave empty to use the default trash folder"));
 	SET_TOGGLE_SENSITIVITY (enable_virustotal, save_folder);

	save_folder_select = gtkut_get_browse_directory_btn(_("_Browse"));
	gtk_widget_show (save_folder_select);
  	gtk_box_pack_start (GTK_BOX (hbox2), save_folder_select, FALSE, FALSE, 0);
	gtk_widget_set_tooltip_text(save_folder_select,
			     _("Click this button to select a folder for storing infected mail"));
 	SET_TOGGLE_SENSITIVITY (enable_virustotal, save_folder_select);

	config = virustotal_get_config();

	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(enable_virustotal), config->virustotal_enable);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(recv_infected), config->virustotal_recv_infected);

    g_signal_connect(G_OBJECT(save_folder_select), "clicked",
		 G_CALLBACK(foldersel_cb), page);

	if (config->virustotal_api_key != NULL)
		gtk_entry_set_text(GTK_ENTRY(api_key), config->virustotal_api_key);
	if (config->virustotal_save_folder != NULL)
		gtk_entry_set_text(GTK_ENTRY(save_folder), config->virustotal_save_folder);

	page->enable_virustotal = enable_virustotal;
	page->api_key = api_key;
	page->recv_infected = recv_infected;
	page->save_folder = save_folder;
	page->page.widget = vbox1;
	
	virustotal_save_config();
}

static void virustotal_destroy_widget_func(PrefsPage *_page)
{
	debug_print("Destroying VirusTotal widget\n");
}

static void virustotal_save_func(PrefsPage *_page)
{
	struct VirusTotalPage *page = (struct VirusTotalPage *) _page;
	VirusTotalConfig *config;

	debug_print("Saving VirusTotal Page - virustotal_save_func\n");

	config = virustotal_get_config();

	config->virustotal_enable = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(page->enable_virustotal));
	g_free(config->virustotal_api_key);
	config->virustotal_api_key = gtk_editable_get_chars(GTK_EDITABLE(page->api_key), 0, -1);
	config->virustotal_recv_infected = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(page->recv_infected));
	g_free(config->virustotal_save_folder);
	config->virustotal_save_folder = gtk_editable_get_chars(GTK_EDITABLE(page->save_folder), 0, -1);

	virustotal_save_config();
}

static struct VirusTotalPage virustotal_page;

static void gtk_message_callback(gchar *message)
{
	statusbar_print_all("%s", message);
}

gint virustotal_gtk_init(void)
{
	static gchar *path[3];

	path[0] = _("Plugins");
	path[1] = _("VirusTotal");
	path[2] = NULL;

	virustotal_page.page.path = path;
	virustotal_page.page.create_widget = virustotal_create_widget_func;
	virustotal_page.page.destroy_widget = virustotal_destroy_widget_func;
	virustotal_page.page.save_page = virustotal_save_func;
	virustotal_page.page.weight = 35.0;
	
	prefs_gtk_register_page((PrefsPage *) &virustotal_page);
	virustotal_set_message_callback(gtk_message_callback);

	debug_print("VirusTotal GTK plugin loaded\n");
	return 0;	
}

void virustotal_gtk_done(void)
{
        prefs_gtk_unregister_page((PrefsPage *) &virustotal_page);
}
