/*
 * Copyright (c) 2015-2017, Parallels International GmbH
 * Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 * This file is part of OpenVZ libraries. OpenVZ is free software; you can
 * redistribute it and/or modify it under the terms of the GNU Lesser General
 * Public License as published by the Free Software Foundation; either version
 * 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/> or write to Free Software Foundation,
 * 51 Franklin Street, Fifth Floor Boston, MA 02110, USA.
 *
 * Our contact details: Virtuozzo International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlwriter.h>
#include <errno.h>
#include <unistd.h>

#include "libvzctl.h"
#include "snapshot.h"
#include "vzerror.h"
#include "list.h"
#include "logger.h"

struct xml_node_param {
	list_elem_t list;
	void *p;
};

static void free_node_list(list_head_t *head)
{
	struct xml_node_param *tmp, *it;

	list_for_each_safe(it, tmp, head, list) {
		list_del(&it->list);
		free(it);
	}
}

static struct xml_node_param *add_xml_node(list_head_t *head, void *node, int tail)
{
	struct xml_node_param *p;

	p = malloc(sizeof(struct xml_node_param));
	if (p == NULL) {
		logger(-1, ENOMEM, "malloc");
		return NULL;
	}
	p->p = node;

	if (tail)
		list_add_tail(&p->list, head);
	else
		list_add(&p->list, head);
	return p;
}

static xmlNodePtr find_child_node(xmlNode *cur_node, const char *elem)
{
	xmlNodePtr child;

	for (child = cur_node->xmlChildrenNode; child != NULL; child = child->next) {
		if (!xmlStrcmp(child->name, (const xmlChar *) elem) &&
				child->type == XML_ELEMENT_NODE)
		{
			return child;
		}
	}
	return NULL;
}

static xmlNodePtr seek(xmlNodePtr root, const char *elem)
{
	xmlNodePtr childNode = root;
	const char *path, *p;
	char nodename[128];
	int last = 0;

	path = elem;
	if (path[0] == '/')
		path++;
	if (path[0] == 0)
		return NULL;
	while (!last) {
		if ((p = strchr(path, '/')) == NULL) {
			p = path + strlen(path);
			last = 1;
		}
		snprintf(nodename, p - path + 1, "%s", path);
		childNode = find_child_node(childNode, nodename);
		if (childNode == NULL)
			return NULL;
		path = ++p;
	}
	return childNode;
}

static const char *get_element_txt(xmlNode *node)
{
	xmlNode *child;

	for (child = node->xmlChildrenNode; child; child = child->next) {
		if (child->type == XML_TEXT_NODE ||
				child->type == XML_CDATA_SECTION_NODE)
			return (const char*)child->content;
	}
	return NULL;
}

static int add_child_nodes(struct vzctl_snapshot_tree *tree, list_head_t *pool,
		xmlNode *cur_node, const char *parent_guid)
{
	xmlNode *node;
	xmlChar *guid = NULL;
	xmlChar *val = NULL;
	const char *name = NULL;
	const char *date = NULL;
	const char *desc = NULL;
	int ret;
	int current;

	cur_node = seek(cur_node, "SavedStateItem");
	if (cur_node == NULL)
		return 0;

	ret = VZCTL_E_NOMEM;
	for (; cur_node; cur_node = cur_node->next) {
		if (cur_node->type != XML_ELEMENT_NODE)
			continue;
		guid = xmlGetProp(cur_node, BAD_CAST "guid");
		if (guid == NULL) {
			logger(-1, 0, "Invalid snapshot file format: no guid attribute");
			goto err;
		}
		current = 0;
		val = xmlGetProp(cur_node, BAD_CAST "current");
		if (val != NULL) {
			current = (strcasecmp((const char *)val, "yes") == 0) ? 1 : 0;
			free(val);
		}
		name = NULL;
		node = seek(cur_node, "Name");
		if (node != NULL)
			name = get_element_txt(node);
		date = NULL;
		node = seek(cur_node, "DateTime");
		if (node != NULL)
			date = get_element_txt(node);
		desc = NULL;
		node = seek(cur_node, "Description");
		if (node != NULL)
			desc = get_element_txt(node);

		if (vzctl_add_snapshot_tree_entry(tree, current, (const char *) guid, parent_guid,
					name, date, desc))
			goto err;
		if (add_xml_node(pool, cur_node, 1) == NULL)
			goto err;
		free(guid);
		guid = NULL;
	}
	ret = 0;
err:
	free(guid);
	return ret;
}

static int parse_xml(const char *basedir, xmlNode *root_node, struct vzctl_snapshot_tree *tree)
{
	xmlNode *cur_node ;
	xmlChar *guid;
	list_head_t pool;
	struct xml_node_param *tmp, *it;
	int ret = 0;

	list_head_init(&pool);
	cur_node = seek(root_node, "/SavedStateItem");
	if (cur_node == NULL)
		return 0;
	if (add_xml_node(&pool, cur_node, 1) == NULL)
		return VZCTL_E_NOMEM;
	while (!list_empty(&pool)) {
		list_for_each_safe(it, tmp, &pool, list) {
			xmlNode *cur_node = (xmlNode*) it->p;

			guid = xmlGetProp(cur_node, BAD_CAST "guid");
			if (guid == NULL) {
				logger(-1, 0, "Invalid snapshot file format: no guid attribute");
				ret = -1;
				break;
			}
			ret = add_child_nodes(tree, &pool, cur_node, (const char *)guid);
			free(guid);
			if (ret)
				break;
			list_del(&it->list);
			free(it);
		}
	}
	free_node_list(&pool);
	return ret;
}

static int update_child_by_guid(struct vzctl_snapshot_tree *tree, list_head_t *head, const char *guid)
{
	int i, cnt = 0;
	struct xml_node_param *it;
	list_head_t childs;

	list_head_init(&childs);
	for (i = 0; i < tree->nsnapshots; i++) {
		if (strcmp(tree->snapshots[i]->parent_guid, guid) != 0)
			continue;
		if (add_xml_node(&childs, tree->snapshots[i]->guid, 1) == NULL)
			return -1;
		cnt++;
	}
	// add on top
	list_for_each_prev(it, &childs, list) {
		if (add_xml_node(head, it->p, 0) == NULL)
			return -1;
	}
	free_node_list(&childs);
	return cnt;
}

#define WRITE_ELEMENT(name, data)						\
	if ((rc = xmlTextWriterWriteElement(writer, BAD_CAST name,		\
					BAD_CAST (data ? data : ""))) < 0) {	\
		return vzctl_err(-1, 0, "WriteElement %s rc=%d\n", name, rc);	\
	}

static int write_SavedStateItem(xmlTextWriterPtr writer, struct vzctl_snapshot_data *snapshot)
{
	int rc;

	rc = xmlTextWriterStartElement(writer, BAD_CAST "SavedStateItem");
	if (rc < 0)
		return vzctl_err(-1, 0, "Error at WriterStartElemen");
	rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "guid", BAD_CAST snapshot->guid);
	if (rc < 0)
		return vzctl_err(-1, 0, "Error at WriteAttribute");
	if (snapshot->current) {
		rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "current", BAD_CAST "yes");
		if (rc < 0)
			return vzctl_err(-1, 0, "Error at WriteAttribute");
	}
	WRITE_ELEMENT("Name", snapshot->name)
	WRITE_ELEMENT("DateTime", snapshot->date)
	WRITE_ELEMENT("Creator", NULL)
	WRITE_ELEMENT("ScreenShot", NULL)
	xmlTextWriterStartElement(writer, BAD_CAST "Description");
	xmlTextWriterWriteCDATA(writer, BAD_CAST (snapshot->desc ? snapshot->desc : ""));
	xmlTextWriterEndElement(writer);

	return 0;
}

static int is_last_in_subtree(struct vzctl_snapshot_tree *tree, int snap_idx)
{
	int i, max = -1;

	for (i = 0; i < tree->nsnapshots; i++) {
		if (strcmp(tree->snapshots[i]->parent_guid,
				tree->snapshots[snap_idx]->parent_guid) == 0)
			max = i;
	}
	return (max == snap_idx);
}

static void write_close_tag(xmlTextWriterPtr writer,
		struct vzctl_snapshot_tree *tree, const char *guid)
{
	int i;

	do {
		if (xmlTextWriterEndElement(writer) < 0)
			vzctl_err(-1, 0, "Error at xmlTextWriterEndElement");
		if (strcmp(guid, "") == 0)
			break;
		i = vzctl2_find_snapshot_by_guid(tree, guid);
		if (i == -1)
			break;
		guid = tree->snapshots[i]->parent_guid;
	} while (is_last_in_subtree(tree, i));
}

int vzctl_store_snapshot_tree(const char *fname, struct vzctl_snapshot_tree *tree)
{
	int i, rc = -1;
	xmlTextWriterPtr writer = NULL;
	xmlDocPtr doc = NULL;
	char tmpfname[MAXPATHLEN];
	struct xml_node_param *it;
	list_head_t pool;
	char *guid;

	logger(0, 0, "Storing %s", fname);
	list_head_init(&pool);
	doc = xmlNewDoc(BAD_CAST XML_DEFAULT_VERSION);
	if (doc == NULL)
		return vzctl_err(-1, 0, "Error creating the xml document tree");
	/* Create a new XmlWriter for DOM tree, with no compression. */
	writer = xmlNewTextWriterTree(doc, NULL, 0);
	if (writer == NULL) {
		vzctl_err(-1, 0, "Error creating the xml writer");
		goto err;
	}

	/* Start the document with the xml default for the version,
	 * encoding ISO 8859-1 and the default for the standalone
	 * declaration. */
	rc = xmlTextWriterStartDocument(writer, NULL, NULL, NULL);
	if (rc < 0) {
		vzctl_err(-1, 0, "Error at xmlTextWriterStartDocument");
		goto err;
	}
	rc = xmlTextWriterStartElement(writer, BAD_CAST "ParallelsSavedStates");
	if (rc < 0) {
		vzctl_err(-1, 0, "Error at ParallelsSavedStates");
		goto err;
	}
	if (tree->nsnapshots == 0) {
		// ParallelsSavedStates
		xmlTextWriterEndElement(writer);
		goto out;
	}
	// add initial entry
	if (update_child_by_guid(tree, &pool, "") == -1) {
		rc = VZCTL_E_NOMEM;
		goto err;
	}
	rc = xmlTextWriterStartElement(writer, BAD_CAST "SavedStateItem");
	if (rc < 0) {
		vzctl_err(-1, 0, "Error at ParallelsSavedStates");
		goto err;
	}
	rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "guid", BAD_CAST "");
	if (rc < 0) {
		vzctl_err(-1, 0, "Error at WriteAttribute");
		goto err;
	}
	WRITE_ELEMENT("Name", NULL)
	WRITE_ELEMENT("DateTime", NULL)
	WRITE_ELEMENT("Creator", NULL)
	WRITE_ELEMENT("ScreenShot", NULL)
	WRITE_ELEMENT("Description", NULL)

	while (!list_empty(&pool)) {
		list_for_each(it, &pool, list) {
			struct vzctl_snapshot_data *snapshot;

			guid = it->p;
			i = vzctl2_find_snapshot_by_guid(tree, guid);
			if (i == -1) {
				vzctl_err(-1, 0, "Inconsistent snapshot: no %s found",
						guid);
				goto err;
			}
			snapshot = tree->snapshots[i];
			rc = write_SavedStateItem(writer, snapshot);
			if (rc)
				goto err;
			rc = update_child_by_guid(tree, &pool, guid);
			if (rc == -1)
				goto err;
			else if (rc == 0)// no more child
				write_close_tag(writer, tree, guid);

			list_del(&it->list);
			free(it);
			break;
		}
	}
out:
	// <SavedStateItem guid ="">
	xmlTextWriterEndElement(writer);
	// ParallelsSavedStates
	xmlTextWriterEndElement(writer);

	xmlFreeTextWriter(writer);
	writer = NULL;
	snprintf(tmpfname, sizeof(tmpfname), "%s.tmp", fname);
	rc = xmlSaveFormatFile(tmpfname, doc, 1);
	if (rc < 0) {
		vzctl_err(-1, 0, "Error at xmlSaveFormatFile %s", tmpfname);
		goto err;
	}
	rc = rename(tmpfname, fname);
	if (rc) {
		vzctl_err(-1, errno, "Can't rename %s -> %s",
				tmpfname, fname);
		unlink(tmpfname);
		goto err;
	}
	rc = 0;
err:
	free_node_list(&pool);

	if (writer)
		xmlFreeTextWriter(writer);
	if (doc)
		xmlFreeDoc(doc);

	return rc;
}

int vzctl_read_snapshot_tree(const char *fname, struct vzctl_snapshot_tree *tree)
{
	int ret;
	xmlDoc *doc = NULL;
	xmlNode *root_element = NULL;

	LIBXML_TEST_VERSION

	doc = xmlReadFile(fname, NULL, 0);
	if (doc == NULL)
		return vzctl_err(VZCTL_E_SYSTEM, 0, "Error: could not parse file %s", fname);

	root_element = xmlDocGetRootElement(doc);

	ret = parse_xml(fname, root_element, tree);

	xmlFreeDoc(doc);

	return ret;
}
