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

#ifndef VIRUSTOTAL_PLUGIN_H
#define VIRUSTOTAL_PLUGIN_H 1

#include <glib.h>

typedef struct _VirusTotalConfig VirusTotalConfig;

typedef void (*MessageCallback) (gchar *);

struct _VirusTotalConfig
{
	gboolean	 virustotal_enable;
	gchar		*virustotal_api_key;
	gboolean 	 virustotal_recv_infected;
	gchar		*virustotal_save_folder;
	gboolean	 alert_ack;
};

VirusTotalConfig *virustotal_get_config(void);
void	      virustotal_save_config(void);
void 	      virustotal_set_message_callback (MessageCallback callback);
gint	      virustotal_gtk_init(void);
void 	      virustotal_gtk_done(void);

#endif
