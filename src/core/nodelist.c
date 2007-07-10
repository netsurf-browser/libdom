/*
 * This file is part of libdom.
 * Licensed under the MIT License,
 *                http://www.opensource.org/licenses/mit-license.php
 * Copyright 2007 John-Mark Bell <jmb@netsurf-browser.org>
 */

#include <dom/core/node.h>
#include <dom/core/nodelist.h>
#include <dom/core/string.h>

#include "core/document.h"
#include "core/nodelist.h"

#include "utils/utils.h"

struct dom_node;

/**
 * DOM node list
 */
struct dom_nodelist {
	struct dom_document *owner;	/**< Owning document */

	struct dom_node *root;		/**< Root of applicable subtree */

	enum { DOM_NODELIST_CHILDREN,
	       DOM_NODELIST_BY_NAME,
	       DOM_NODELIST_BY_NAMESPACE
	} type;				/**< List type */

	union {
		struct dom_string *name;	/**< Tag name to match */
		struct {
			struct dom_string *namespace;	/**< Namespace */
			struct dom_string *localname;	/**< Localname */
		} ns;			/**< Data for namespace matching */
	} data;

	uint32_t refcnt;		/**< Reference count */
};

/**
 * Create a nodelist
 *
 * \param doc        Owning document
 * \param root       Root node of subtree that list applies to
 * \param tagname    Name of nodes in list (or NULL)
 * \param namespace  Namespace part of nodes in list (or NULL)
 * \param localname  Local part of nodes in list (or NULL)
 * \param list       Pointer to location to receive list
 * \return DOM_NO_ERR on success, DOM_NO_MEM_ERR on memory exhaustion
 *
 * ::root must be a node owned by ::doc
 *
 * If ::tagname is non-NULL, ::namespace and ::localname must be NULL and
 * the created list will match nodes by name
 * If ::namespace is non-NULL, ::localname must be non-NULL and
 * ::tagname must be NULL and the created list will match nodes by namespace
 * and localname
 * If ::tagname, ::namespace and ::localname are NULL, the created list
 * will match the children of ::root.
 *
 * The returned list will already be referenced, so the client need not
 * do so explicitly. The client should unref the list once finished with it.
 */
dom_exception dom_nodelist_create(struct dom_document *doc,
		struct dom_node *root, struct dom_string *tagname,
		struct dom_string *namespace, struct dom_string *localname,
		struct dom_nodelist **list)
{
	struct dom_nodelist *l;

	l = dom_document_alloc(doc, NULL, sizeof(struct dom_nodelist));
	if (l == NULL)
		return DOM_NO_MEM_ERR;

	dom_node_ref((struct dom_node *) doc);
	l->owner = doc;

	dom_node_ref(root);
	l->root = root;

	if (tagname != NULL && namespace == NULL && localname == NULL) {
		dom_string_ref(tagname);
		l->type = DOM_NODELIST_BY_NAME;
		l->data.name = tagname;
	} else if (namespace != NULL && localname != NULL &&
			tagname == NULL) {
		dom_string_ref(namespace);
		dom_string_ref(localname);
		l->type = DOM_NODELIST_BY_NAMESPACE;
		l->data.ns.namespace = namespace;
		l->data.ns.localname = localname;
	} else {
		l->type = DOM_NODELIST_CHILDREN;
	}

	l->refcnt = 1;

	*list = l;

	return DOM_NO_ERR;
}

/**
 * Claim a reference on a DOM node list
 *
 * \param list  The list to claim a reference on
 */
void dom_nodelist_ref(struct dom_nodelist *list)
{
	list->refcnt++;
}

/**
 * Release a reference on a DOM node list
 *
 * \param list  The list to release the reference from
 *
 * If the reference count reaches zero, any memory claimed by the
 * list will be released
 */
void dom_nodelist_unref(struct dom_nodelist *list)
{
	if (--list->refcnt == 0) {
		switch (list->type) {
		case DOM_NODELIST_CHILDREN:
			/* Nothing to do */
			break;
		case DOM_NODELIST_BY_NAMESPACE:
			dom_string_unref(list->data.ns.namespace);
			dom_string_unref(list->data.ns.localname);
			break;
		case DOM_NODELIST_BY_NAME:
			dom_string_unref(list->data.name);
			break;
		}

		dom_node_unref(list->root);

		dom_node_unref((struct dom_node *) list->owner);

		/* Remove list from document */
		dom_document_remove_nodelist(list->owner, list);

		/* And destroy the list object */
		dom_document_alloc(list->owner, list, 0);
	}
}

/**
 * Retrieve the length of a node list
 *
 * \param list    List to retrieve length of
 * \param length  Pointer to location to receive length
 * \return DOM_NO_ERR.
 */
dom_exception dom_nodelist_get_length(struct dom_nodelist *list,
		unsigned long *length)
{
	UNUSED(list);
	UNUSED(length);

	return DOM_NOT_SUPPORTED_ERR;
}

/**
 * Retrieve an item from a node list
 *
 * \param list   The list to retrieve the item from
 * \param index  The list index to retrieve
 * \param node   Pointer to location to receive item
 * \return DOM_NO_ERR.
 *
 * ::index is a zero-based index into ::list.
 * ::index lies in the range [0, length-1]
 *
 * The returned node will have had its reference count increased. The client
 * should unref the node once it has finished with it.
 */
dom_exception dom_nodelist_item(struct dom_nodelist *list,
		unsigned long index, struct dom_node **node)
{
	UNUSED(list);
	UNUSED(index);
	UNUSED(node);

	return DOM_NOT_SUPPORTED_ERR;
}

/**
 * Match a nodelist instance against a set of nodelist creation parameters
 *
 * \param list       List to match
 * \param root       Root node of subtree that list applies to
 * \param tagname    Name of nodes in list (or NULL)
 * \param namespace  Namespace part of nodes in list (or NULL)
 * \param localname  Local part of nodes in list (or NULL)
 * \return true if list matches, false otherwise
 */
bool dom_nodelist_match(struct dom_nodelist *list, struct dom_node *root,
		struct dom_string *tagname, struct dom_string *namespace,
		struct dom_string *localname)
{
	if (list->root != root)
		return false;

	if (list->type == DOM_NODELIST_CHILDREN && tagname == NULL &&
			namespace == NULL && localname == NULL) {
		return true;
	}

	if (list->type == DOM_NODELIST_BY_NAME && tagname != NULL &&
			namespace == NULL && localname == NULL) {
		return (dom_string_cmp(list->data.name, tagname) == 0);
	}

	if (list->type == DOM_NODELIST_BY_NAMESPACE && tagname == NULL &&
			namespace != NULL && localname != NULL) {
		return (dom_string_cmp(list->data.ns.namespace,
				namespace) == 0) &&
			(dom_string_cmp(list->data.ns.localname,
				localname) == 0);
	}

	return false;
}
