/*
 * This file is part of libdom.
 * Licensed under the MIT License,
 *                http://www.opensource.org/licenses/mit-license.php
 * Copyright 2012 Daniel Silverstone <dsilvers@netsurf-browser.org>
 */

/* Note, this file deliberately lacks guards since it's included many times
 * in many places in order to correctly handle the loading of the strings.
 */

#ifndef HTML_DOCUMENT_STRINGS_ACTION
#define HTML_DOCUMENT_STRINGS_INTERNAL_ACTION 1
#define HTML_DOCUMENT_STRINGS_PREFIX      \
	typedef enum {
#define HTML_DOCUMENT_STRINGS_SUFFIX		\
	hds_COUNT				\
	} html_document_memo_string_e;
#define HTML_DOCUMENT_STRINGS_ACTION(tag,str)	\
	hds_##tag,
#endif

#define HTML_DOCUMENT_STRINGS_ACTION1(x) HTML_DOCUMENT_STRINGS_ACTION(x,x)

#ifdef HTML_DOCUMENT_STRINGS_PREFIX
HTML_DOCUMENT_STRINGS_PREFIX
#endif

/* Useful attributes for HTMLElement */
HTML_DOCUMENT_STRINGS_ACTION1(id)
HTML_DOCUMENT_STRINGS_ACTION1(title)
HTML_DOCUMENT_STRINGS_ACTION1(lang)
HTML_DOCUMENT_STRINGS_ACTION1(dir)
HTML_DOCUMENT_STRINGS_ACTION1(class)
/* Useful attributes used by HTMLHtmlElement */
HTML_DOCUMENT_STRINGS_ACTION1(version)
/* Useful attributes used by HTMLHeadElement */
HTML_DOCUMENT_STRINGS_ACTION1(profile)
/* Useful attributes used by HTMLLinkElement */
HTML_DOCUMENT_STRINGS_ACTION1(charset)
HTML_DOCUMENT_STRINGS_ACTION1(href)
HTML_DOCUMENT_STRINGS_ACTION1(hreflang)
HTML_DOCUMENT_STRINGS_ACTION1(media)
HTML_DOCUMENT_STRINGS_ACTION1(rel)
HTML_DOCUMENT_STRINGS_ACTION1(rev)
HTML_DOCUMENT_STRINGS_ACTION1(target)
HTML_DOCUMENT_STRINGS_ACTION1(type)
/* Useful attributes used by HTMLMetaElement */
HTML_DOCUMENT_STRINGS_ACTION1(content)
HTML_DOCUMENT_STRINGS_ACTION(http_equiv,http-equiv)
HTML_DOCUMENT_STRINGS_ACTION1(name)
HTML_DOCUMENT_STRINGS_ACTION1(scheme)
/* Useful attributes used by HTMLFormElement */
HTML_DOCUMENT_STRINGS_ACTION(accept_charset,accept-charset)
HTML_DOCUMENT_STRINGS_ACTION1(action)
HTML_DOCUMENT_STRINGS_ACTION1(enctype)
HTML_DOCUMENT_STRINGS_ACTION1(method)
/* HTML_DOCUMENT_STRINGS_ACTION1(target) */
/* Names for elements which get specialised. */
HTML_DOCUMENT_STRINGS_ACTION1(HTML)
HTML_DOCUMENT_STRINGS_ACTION1(HEAD)
HTML_DOCUMENT_STRINGS_ACTION1(LINK)
HTML_DOCUMENT_STRINGS_ACTION1(TITLE)
HTML_DOCUMENT_STRINGS_ACTION1(META)
HTML_DOCUMENT_STRINGS_ACTION1(BASE)
HTML_DOCUMENT_STRINGS_ACTION1(ISINDEX)
HTML_DOCUMENT_STRINGS_ACTION1(STYLE)
HTML_DOCUMENT_STRINGS_ACTION1(BODY)
HTML_DOCUMENT_STRINGS_ACTION1(FORM)
HTML_DOCUMENT_STRINGS_ACTION1(SELECT)
HTML_DOCUMENT_STRINGS_ACTION1(OPTGROUP)
HTML_DOCUMENT_STRINGS_ACTION1(OPTION)
HTML_DOCUMENT_STRINGS_ACTION1(INPUT)
HTML_DOCUMENT_STRINGS_ACTION1(TEXTAREA)
HTML_DOCUMENT_STRINGS_ACTION1(BUTTON)
HTML_DOCUMENT_STRINGS_ACTION1(LABEL)
HTML_DOCUMENT_STRINGS_ACTION1(FIELDSET)
HTML_DOCUMENT_STRINGS_ACTION1(LEGEND)
HTML_DOCUMENT_STRINGS_ACTION1(UL)
HTML_DOCUMENT_STRINGS_ACTION1(OL)
HTML_DOCUMENT_STRINGS_ACTION1(DL)
HTML_DOCUMENT_STRINGS_ACTION1(DIR)
HTML_DOCUMENT_STRINGS_ACTION1(MENU)
HTML_DOCUMENT_STRINGS_ACTION1(LI)
HTML_DOCUMENT_STRINGS_ACTION1(BLOCKQUOTE)
HTML_DOCUMENT_STRINGS_ACTION1(DIV)
HTML_DOCUMENT_STRINGS_ACTION1(P)
HTML_DOCUMENT_STRINGS_ACTION1(H1)
HTML_DOCUMENT_STRINGS_ACTION1(H2)
HTML_DOCUMENT_STRINGS_ACTION1(H3)
HTML_DOCUMENT_STRINGS_ACTION1(H4)
HTML_DOCUMENT_STRINGS_ACTION1(H5)
HTML_DOCUMENT_STRINGS_ACTION1(H6)
HTML_DOCUMENT_STRINGS_ACTION1(Q)
HTML_DOCUMENT_STRINGS_ACTION1(PRE)
HTML_DOCUMENT_STRINGS_ACTION1(BR)
HTML_DOCUMENT_STRINGS_ACTION1(BASEFONT)
HTML_DOCUMENT_STRINGS_ACTION1(FONT)
HTML_DOCUMENT_STRINGS_ACTION1(HR)
HTML_DOCUMENT_STRINGS_ACTION1(INS)
HTML_DOCUMENT_STRINGS_ACTION1(DEL)
HTML_DOCUMENT_STRINGS_ACTION1(A)
HTML_DOCUMENT_STRINGS_ACTION1(IMG)
HTML_DOCUMENT_STRINGS_ACTION1(OBJECT)
HTML_DOCUMENT_STRINGS_ACTION1(PARAM)
HTML_DOCUMENT_STRINGS_ACTION1(APPLET)
HTML_DOCUMENT_STRINGS_ACTION1(MAP)
HTML_DOCUMENT_STRINGS_ACTION1(AREA)
HTML_DOCUMENT_STRINGS_ACTION1(SCRIPT)
HTML_DOCUMENT_STRINGS_ACTION1(TABLE)
HTML_DOCUMENT_STRINGS_ACTION1(CAPTION)
HTML_DOCUMENT_STRINGS_ACTION1(COL)
HTML_DOCUMENT_STRINGS_ACTION1(COLGROUP)
HTML_DOCUMENT_STRINGS_ACTION1(THEAD)
HTML_DOCUMENT_STRINGS_ACTION1(TFOOT)
HTML_DOCUMENT_STRINGS_ACTION1(TBODY)
HTML_DOCUMENT_STRINGS_ACTION1(TR)
HTML_DOCUMENT_STRINGS_ACTION1(TH)
HTML_DOCUMENT_STRINGS_ACTION1(TD)
HTML_DOCUMENT_STRINGS_ACTION1(FRAMESET)
HTML_DOCUMENT_STRINGS_ACTION1(FRAME)
HTML_DOCUMENT_STRINGS_ACTION1(IFRAME)

#ifdef HTML_DOCUMENT_STRINGS_SUFFIX
HTML_DOCUMENT_STRINGS_SUFFIX
#endif
  
#undef HTML_DOCUMENT_STRINGS_ACTION1

#ifdef HTML_DOCUMENT_STRINGS_INTERNAL_ACTION
#undef HTML_DOCUMENT_STRINGS_INTERNAL_ACTION
#undef HTML_DOCUMENT_STRINGS_PREFIX
#undef HTML_DOCUMENT_STRINGS_SUFFIX
#undef HTML_DOCUMENT_STRINGS_ACTION
#endif
