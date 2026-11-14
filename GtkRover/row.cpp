/*
 *  Rover -- Filesystem browser for Windows
 *  Copyright (C) 2026  A1ive
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "row.h"

#include <glib/gi18n.h>

#include <rover.h>

struct _RoverRow
{
	GObject parent_instance;
	row_data *data;
	char *content_type;	/* guessed lazily for files */
};

G_DEFINE_FINAL_TYPE (RoverRow, rover_row, G_TYPE_OBJECT)

enum
{
	PROP_0,
	PROP_TITLE,
	PROP_SUBTITLE,
	PROP_SIZE_TEXT,
	PROP_MTIME_TEXT,
	PROP_TYPE_TEXT,
	PROP_ICON,
	PROP_INDENT,
	N_PROPS
};

static GParamSpec *props[N_PROPS];

static std::string
format_size (unsigned long long size)
{
	char *text = g_format_size_full (size, G_FORMAT_SIZE_IEC_UNITS);
	std::string out = text;

	g_free (text);
	return out;
}

static const char *
content_type (RoverRow *self)
{
	if (!self->content_type)
	{
		if (self->data->is_dir)
			self->content_type = g_strdup ("inode/directory");
		else
			self->content_type = g_content_type_guess (self->data->name.c_str (),
				nullptr, 0, nullptr);
	}
	return self->content_type;
}

static std::string
disk_subtitle (const row_data &d)
{
	std::string out;

	if (!d.fs.empty ())
		out = d.fs;
	else if (!d.crypto_type.empty ())
		out = d.crypto_type + (d.encrypted ? _(", locked") : _(", unlocked"));
	else
		out = _("no filesystem");
	if (!d.label.empty ())
		out += " · " + d.label;
	if (d.size != ROVER_SIZE_UNKNOWN)
		out += " · " + format_size (d.size);
	if (!d.mountpoint.empty ())
		out += " · " + std::string (_("mounted"));
	return out;
}

static GIcon *
disk_icon (const row_data &d)
{
	static const char *const locked[] =
		{ "drive-harddisk-encrypted", "dialog-password", nullptr };
	static const char *const image[] =
		{ "application-x-cd-image", "media-optical", "drive-removable-media", nullptr };
	static const char *const unlocked[] =
		{ "drive-harddisk-encrypted", "drive-harddisk", nullptr };
	static const char *const partition[] =
		{ "drive-partition", "drive-harddisk", nullptr };
	static const char *const optical[] = { "drive-optical", nullptr };
	static const char *const disk[] = { "drive-harddisk", nullptr };
	const char *const *names = disk;

	if (d.encrypted)
		names = locked;
	else if (d.is_partition)
		names = partition;
	else if (d.dev_id == ROVER_DEV_POSIXFILE || d.dev_id == ROVER_DEV_LOOPBACK)
		names = image;
	else if (d.dev_id == ROVER_DEV_CRYPTODISK)
		names = unlocked;
	else if (d.name.rfind ("cd", 0) == 0)
		names = optical;
	return g_themed_icon_new_from_names (const_cast<char **> (names), -1);
}

static void
rover_row_get_property (GObject *object, guint id, GValue *value, GParamSpec *pspec)
{
	RoverRow *self = ROVER_ROW (object);
	const row_data &d = *self->data;

	switch (id)
	{
	case PROP_TITLE:
		g_value_set_string (value, d.name.c_str ());
		break;
	case PROP_SUBTITLE:
		g_value_set_string (value, d.kind == row_kind::disk
			? disk_subtitle (d).c_str () : "");
		break;
	case PROP_SIZE_TEXT:
		g_value_set_string (value, d.kind == row_kind::entry && !d.is_dir
			&& d.size_set ? format_size (d.size).c_str () : "");
		break;
	case PROP_MTIME_TEXT:
		if (d.mtime_set)
		{
			GDateTime *dt = g_date_time_new_from_unix_local (d.mtime);
			if (dt)
			{
				g_value_take_string (value, g_date_time_format (dt, "%Y-%m-%d %H:%M"));
				g_date_time_unref (dt);
				break;
			}
		}
		g_value_set_string (value, "");
		break;
	case PROP_TYPE_TEXT:
		if (d.kind == row_kind::entry && d.is_symlink)
			g_value_take_string (value, g_content_type_get_description ("inode/symlink"));
		else if (d.kind == row_kind::entry)
			g_value_take_string (value, g_content_type_get_description (content_type (self)));
		else
			g_value_set_string (value, "");
		break;
	case PROP_ICON:
		if (d.kind == row_kind::disk)
			g_value_take_object (value, disk_icon (d));
		else
			g_value_take_object (value, g_content_type_get_icon (content_type (self)));
		break;
	case PROP_INDENT:
		g_value_set_int (value, d.kind == row_kind::disk ? d.depth * 18 : 0);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, id, pspec);
	}
}

static void
rover_row_finalize (GObject *object)
{
	RoverRow *self = ROVER_ROW (object);

	delete self->data;
	g_free (self->content_type);
	G_OBJECT_CLASS (rover_row_parent_class)->finalize (object);
}

static void
rover_row_class_init (RoverRowClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	GParamFlags flags = (GParamFlags) (G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	object_class->get_property = rover_row_get_property;
	object_class->finalize = rover_row_finalize;
	props[PROP_TITLE] = g_param_spec_string ("title", nullptr, nullptr, nullptr, flags);
	props[PROP_SUBTITLE] = g_param_spec_string ("subtitle", nullptr, nullptr, nullptr, flags);
	props[PROP_SIZE_TEXT] = g_param_spec_string ("size-text", nullptr, nullptr, nullptr, flags);
	props[PROP_MTIME_TEXT] = g_param_spec_string ("mtime-text", nullptr, nullptr, nullptr, flags);
	props[PROP_TYPE_TEXT] = g_param_spec_string ("type-text", nullptr, nullptr, nullptr, flags);
	props[PROP_ICON] = g_param_spec_object ("icon", nullptr, nullptr, G_TYPE_ICON, flags);
	props[PROP_INDENT] = g_param_spec_int ("indent", nullptr, nullptr, 0, G_MAXINT, 0, flags);
	g_object_class_install_properties (object_class, N_PROPS, props);
}

static void
rover_row_init (RoverRow *self)
{
	self->data = new row_data;
}

RoverRow *
rover_row_new (row_data data)
{
	RoverRow *self = ROVER_ROW (g_object_new (ROVER_TYPE_ROW, nullptr));

	*self->data = std::move (data);
	return self;
}

const row_data &
rover_row_get (RoverRow *row)
{
	return *row->data;
}

void
rover_row_set_size (RoverRow *row, unsigned long long size)
{
	row->data->size = size;
	row->data->size_set = true;
	g_object_notify_by_pspec (G_OBJECT (row), props[PROP_SIZE_TEXT]);
}
