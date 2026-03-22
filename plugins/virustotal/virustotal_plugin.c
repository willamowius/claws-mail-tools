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

#include "common/claws.h"
#include "common/version.h"
#include "plugin.h"
#include "utils.h"
#include "hooks.h"
#include "inc.h"
#include "mimeview.h"
#include "folder.h"
#include "prefs.h"
#include "prefs_gtk.h"
#include "alertpanel.h"
#include "prefs_common.h"
#include "statusbar.h"
#include <curl/curl.h>
#include <curl/curlver.h>

#include "virustotal_plugin.h"

#define PLUGIN_NAME (_("VirusTotal"))

static gulong hook_id = HOOK_NONE;
static MessageCallback message_callback;

static VirusTotalConfig config;

static PrefParam param[] = {
	{"virustotal_enable", "FALSE", &config.virustotal_enable, P_BOOL,
	 NULL, NULL, NULL},
	{"virustotal_api_key", NULL, &config.virustotal_api_key, P_STRING,
	 NULL, NULL, NULL},
	{"virustotal_recv_infected", "TRUE", &config.virustotal_recv_infected, P_BOOL,
	 NULL, NULL, NULL},
	{"virustotal_save_folder", NULL, &config.virustotal_save_folder, P_STRING,
	 NULL, NULL, NULL},

	{NULL, NULL, NULL, P_OTHER, NULL, NULL, NULL}
};

#define OK 			0
#define VIRUS		1
#define SCAN_ERROR	2

typedef struct _virustotal_result virustotal_result;

struct _virustotal_result {
	int status;
	gchar *name; // virus name if a virus is detected
	gchar *msg;	// eg scan error
};

// curl helper functions borrowed from spam_report.c
struct CurlReadWrite {
        char *data;
        size_t size;
};

static void *myrealloc(void *pointer, size_t size) {
        /*
         * There might be a realloc() out there that doesn't like reallocing
         * NULL pointers, so we take care of it here.
         */
        if (pointer) {
                return realloc(pointer, size);
        } else {
                return malloc(size);
        }
}

static size_t curl_writefunction_cb(void *pointer, size_t size, size_t nmemb, void *data) {
        size_t realsize = size * nmemb;
        struct CurlReadWrite *mem = (struct CurlReadWrite *)data;

        mem->data = myrealloc(mem->data, mem->size + realsize + 1);
        if (mem->data) {
                memcpy(&(mem->data[mem->size]), pointer, realsize);
                mem->size += realsize;
                mem->data[mem->size] = 0;
        }
        return realsize;
}


void virustotal_verify_email(gchar *outfile, virustotal_result * result) {
	debug_print("VirusTotal checking %s\n", outfile);

	result->status = SCAN_ERROR; // defensive init
	g_free(result->name);
	result->name = NULL;
	g_free(result->msg);
	result->msg = NULL;

	// calculate MD5 checksum TODO sha1/sha256 would be better, but for now stay with the md5 function we have already
	gchar* md5sum = malloc(33);
	if (md5_hex_digest_file(md5sum, outfile) == -1) {
		free(md5sum);
		result->status = SCAN_ERROR;
		result->msg = g_strdup(_("MD5 error"));
		debug_print(result->msg);
		return;
	}

	curl_global_init(CURL_GLOBAL_DEFAULT);
	CURL * curl = curl_easy_init();
	CURLcode res;
	struct CurlReadWrite vt_response = { .data = NULL, .size = 0 };
	long vt_response_code = 0;

	if (curl) {
		gchar *vt_url = g_strdup_printf("https://www.virustotal.com/api/v3/files/%s", md5sum);
		gchar *accept_header = g_strdup("Accept: application/json");
		gchar *apikey_header = g_strdup_printf("x-apikey: %s", config.virustotal_api_key);
		struct curl_slist *vt_headers = NULL;
		vt_headers = curl_slist_append(vt_headers, accept_header);
		vt_headers = curl_slist_append(vt_headers, apikey_header);
		g_free(accept_header);
		g_free(apikey_header);
		curl_easy_setopt(curl, CURLOPT_URL, vt_url);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, vt_headers);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_writefunction_cb);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&vt_response);
		if (debug_get_mode())
			curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
#ifdef G_OS_WIN32
		curl_easy_setopt(curl, CURLOPT_CAINFO, claws_ssl_get_cert_file());
#endif
		res = curl_easy_perform(curl);
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &vt_response_code);
		curl_easy_cleanup(curl);
		curl_global_cleanup(); // TODO move the global calls to plugin start/stop?
		g_free(vt_url);

		if (CURLE_OK != res) {
			result->status = SCAN_ERROR;
			result->msg = g_strdup_printf(_("VirusTotal API error: %s"), curl_easy_strerror(res));
			debug_print(result->msg);
			alertpanel_error(result->msg);
			return;
		}
		vt_response.data[vt_response.size] = '\0'; // make sure it's NUL terminated
	}

	if (vt_response_code == 404) {
		result->status = OK; // they have never seen this signature, so probably not a virus
	} else {
		if (debug_get_mode())
			debug_print("VirusTotal response= %s\n", vt_response.data);
		GMatchInfo *matchInfo;
		GRegex *regex;
		
		regex = g_regex_new("\"last_analysis_stats\".*?\"malicious\":\\s*([0-9]+),", G_REGEX_RAW, 0, NULL);
		g_regex_match(regex, vt_response.data, 0, &matchInfo);
		if (g_match_info_matches (matchInfo)) {
			int num_malicious = atoi(g_match_info_fetch(matchInfo, 1));
			debug_print("VirusTotal has %d malicious verdicts\n", num_malicious);
			if (num_malicious > 0) {
				result->status = VIRUS;
				g_free(matchInfo);
				g_free(regex);
				regex = g_regex_new("\"suggested_threat_label\".*?\"([^\"]+)\"", G_REGEX_RAW, 0, NULL);
				g_regex_match(regex, vt_response.data, 0, &matchInfo);
				if (g_match_info_matches (matchInfo)) {
					result->name = g_strdup(g_match_info_fetch(matchInfo, 1));
				}
			} else {
				result->status = OK;
			}
		} else {  
			g_match_info_free (matchInfo);
			result->status = SCAN_ERROR;
		}
		g_free(matchInfo);
		//g_free(regex); // TODO this crashes, why shouldn't we free the regex ?
	}
	free(md5sum);
	vt_response.size = 0;
	free(vt_response.data);
}

static gboolean scan_func(GNode *node, gpointer data)
{
	virustotal_result *result = (virustotal_result *) data;
	MimeInfo *mimeinfo = (MimeInfo *) node->data;
	gchar *outfile;
	gchar* msg;

	// skip text, images etc. parts, only scan the application/*
	if (mimeinfo->type != MIMETYPE_APPLICATION) {
		return FALSE; // means OK
	}

	outfile = procmime_get_tmp_file_name(mimeinfo);
	if (procmime_get_part(outfile, mimeinfo) < 0) {
		g_warning("can't get the part of multipart message");
	} else {
		virustotal_verify_email(outfile, result);
		switch (result->status) {
			case VIRUS:
				msg = g_strconcat(_("Detected "), result->name, _(" virus."), NULL);
				g_warning("%s", msg);
				debug_print("show_recv_err: %d\n", prefs_common_get_prefs()->show_recv_err_dialog);
				if (!prefs_common_get_prefs()->show_recv_err_dialog) {
					statusbar_print_all("%s", msg);
				}
				else {
					alertpanel_warning("%s\n", msg);
				}
				g_free(msg);
				config.alert_ack = TRUE;
				break;
			case SCAN_ERROR:
				debug_print("Error: %s\n", result->msg);
				if (config.alert_ack) {
					alertpanel_error(_("Scanning error:\n%s"), result->msg);
					config.alert_ack = FALSE;
				}
				break;
			case OK:
				debug_print("No virus detected.\n");
				config.alert_ack = TRUE;
				break;
		}
		if (g_unlink(outfile) < 0)
            FILE_OP_ERROR(outfile, "g_unlink");
	}
	
	return (result->status == OK) ? FALSE : TRUE;
}

static gboolean mail_filtering_hook(gpointer source, gpointer data)
{
	MailFilteringData *mail_filtering_data = (MailFilteringData *) source;
	MsgInfo *msginfo = mail_filtering_data->msginfo;
	MimeInfo *mimeinfo;

	virustotal_result result = { .status = SCAN_ERROR, .name = NULL, .msg = NULL };

	if (!config.virustotal_enable)
		return FALSE;

	mimeinfo = procmime_scan_message(msginfo);
	if (!mimeinfo) return FALSE;

	debug_print("Scanning message %d for viruses\n", msginfo->msgnum);
	if (message_callback != NULL)
		message_callback(_("VirusTotal: scanning message..."));

	g_node_traverse(mimeinfo->node, G_PRE_ORDER, G_TRAVERSE_ALL, -1, scan_func, &result);
	debug_print("status: %d\n", result.status);

	if (result.status == VIRUS) {
		if (config.virustotal_recv_infected) {
			FolderItem *virustotal_save_folder;

			if ((!config.virustotal_save_folder) ||
			    (config.virustotal_save_folder[0] == '\0') ||
			    ((virustotal_save_folder = folder_find_item_from_identifier(config.virustotal_save_folder)) == NULL))
				    virustotal_save_folder = folder_get_default_trash();

			procmsg_msginfo_unset_flags(msginfo, ~0, 0);
			msginfo->filter_op = IS_MOVE;
			msginfo->to_filter_folder = virustotal_save_folder;
		} else {
			folder_item_remove_msg(msginfo->folder, msginfo->msgnum);
		}
	}
	
	procmime_mimeinfo_free_all(&mimeinfo);

	return (result.status == OK) ? FALSE : TRUE;
}

VirusTotalConfig *virustotal_get_config(void)
{
	return &config;
}

void virustotal_save_config(void)
{
	PrefFile *pfile;
	gchar *rcpath;

	debug_print("Saving VirusTotal Page - virustotal_save_config\n");

	rcpath = g_strconcat(get_rc_dir(), G_DIR_SEPARATOR_S, COMMON_RC, NULL);
	pfile = prefs_write_open(rcpath);
	g_free(rcpath);
	if (!pfile || (prefs_set_block_label(pfile, "VirusTotal") < 0))
		return;

	if (prefs_write_param(param, pfile->fp) < 0) {
		g_warning("failed to write VirusTotal configuration to file");
		prefs_file_close_revert(pfile);
		return;
	}
    if (fprintf(pfile->fp, "\n") < 0) {
		FILE_OP_ERROR(rcpath, "fprintf");
		prefs_file_close_revert(pfile);
	} else
	    prefs_file_close(pfile);
}

void virustotal_set_message_callback(MessageCallback callback)
{
	message_callback = callback;
}

gint plugin_init(gchar **error)
{
	gchar *rcpath;

	if (!check_plugin_version(MAKE_NUMERIC_VERSION(2,9,2,72),
				VERSION_NUMERIC, PLUGIN_NAME, error))
		return -1;

	hook_id = hooks_register_hook(MAIL_FILTERING_HOOKLIST, mail_filtering_hook, NULL);
	if (hook_id == HOOK_NONE) {
		*error = g_strdup(_("Failed to register mail filtering hook"));
		return -1;
	}

	prefs_set_default(param);
	rcpath = g_strconcat(get_rc_dir(), G_DIR_SEPARATOR_S, COMMON_RC, NULL);
	prefs_read_config(param, "VirusTotal", rcpath, NULL);
	g_free(rcpath);

	virustotal_gtk_init();
	debug_print("Virustotal plugin loaded\n");

	return 0;
	
}

gboolean plugin_done(void)
{
	hooks_unregister_hook(MAIL_FILTERING_HOOKLIST, hook_id);
	g_free(config.virustotal_save_folder);
	virustotal_gtk_done();

	debug_print("VirusTotal plugin unloaded\n");
	return TRUE;
}

const gchar *plugin_name(void)
{
	return PLUGIN_NAME;
}

const gchar *plugin_desc(void)
{
	return _("This plugin uses VirusTotal to scan all message attachments that are "
	       "received from an IMAP, LOCAL or POP account.\n"
	       "\n"
	       "When a message attachment is found to contain a virus it can be "
	       "deleted or saved in a specially designated folder.\n"
	       "\n"
	       "You need to add your own (free) VirusTotal API key in the configuration.\n"
	       "https://www.virustotal.com/");
}

const gchar *plugin_type(void)
{
	return "GTK3";
}

const gchar *plugin_licence(void)
{
	return "GPL3+";
}

const gchar *plugin_version(void)
{
	return VERSION;
}

struct PluginFeature *plugin_provides(void)
{
	static struct PluginFeature features[] = 
		{ {PLUGIN_FILTERING, N_("Virus detection")},
		  {PLUGIN_NOTHING, NULL}};
	return features;
}
