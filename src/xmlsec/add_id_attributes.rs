use super::{XmlSecError, XmlSecResult};
use crate::bindings::*;
use std::ptr::{null, null_mut};
// static int
// xmlSecAppAddIDAttr(xmlNodePtr node, const xmlChar* attrName, const xmlChar* nodeName, const xmlChar* nsHref) {
//     xmlAttrPtr attr, tmpAttr;
//     xmlNodePtr cur;
//     xmlChar* id;

//     if((node == NULL) || (attrName == NULL) || (nodeName == NULL)) {
//         return(-1);
//     }

//     /* process children first because it does not matter much but does simplify code */
//     cur = xmlSecGetNextElementNode(node->children);
//     while(cur != NULL) {
//         if(xmlSecAppAddIDAttr(cur, attrName, nodeName, nsHref) < 0) {
//             return(-1);
//         }
//         cur = xmlSecGetNextElementNode(cur->next);
//     }

//     /* node name must match */
//     if(!xmlStrEqual(node->name, nodeName)) {
//         return(0);
//     }

//     /* if nsHref is set then it also should match */
//     if((nsHref != NULL) && (node->ns != NULL) && (!xmlStrEqual(nsHref, node->ns->href))) {
//         return(0);
//     }

//     /* the attribute with name equal to attrName should exist */
//     for(attr = node->properties; attr != NULL; attr = attr->next) {
//         if(xmlStrEqual(attr->name, attrName)) {
//             break;
//         }
//     }
//     if(attr == NULL) {
//         return(0);
//     }

//     /* and this attr should have a value */
//     id = xmlNodeListGetString(node->doc, attr->children, 1);
//     if(id == NULL) {
//         return(0);
//     }

//     /* check that we don't have same ID already */
//     tmpAttr = xmlGetID(node->doc, id);
//     if(tmpAttr == NULL) {
//         xmlAddID(NULL, node->doc, id, attr);
//     } else if(tmpAttr != attr) {
//         fprintf(stderr, "Error: duplicate ID attribute \"%s\"\n", id);
//         xmlFree(id);
//         return(-1);
//     }
//     xmlFree(id);
//     return(0);
// }

/// Update the document with any/all ID attributes so that XPointer evaluation
/// works.
pub unsafe fn xml_sec_app_add_id_attr(
    node: xmlNodePtr,
    attribute_name: &std::ffi::CString,
    node_name: &std::ffi::CString,
    ns_href: *const u8,
) -> XmlSecResult<()> {
    if node.is_null() {
        return Err(XmlSecError::SecInvalidIdCollectionNode);
    }

    let mut cur: xmlNodePtr = xmlSecGetNextElementNode((*node).children);
    while cur != null_mut() {
        xml_sec_app_add_id_attr(cur, attribute_name, node_name, ns_href)?;
        cur = xmlSecGetNextElementNode((*cur).next);
    }

    // node name must match.
    if xmlStrEqual((*node).name, node_name.as_ptr() as *const u8) == 0 {
        return Ok(());
    }

    // if nsHref is set then it also should match
    if ns_href != null()
        && (*node).ns != null_mut()
        && xmlStrEqual(ns_href, (*(*node).ns).href) == 0
    {
        return Ok(());
    }

    // The attribute with name equal to attrName should exist.
    let mut attr: xmlAttrPtr = (*node).properties;
    while attr != null_mut() {
        if xmlStrEqual((*attr).name, attribute_name.as_ptr() as *const u8) == 1 {
            break;
        }
        attr = (*attr).next;
    }

    // We didn't find what we were looking for.
    if attr == null_mut() {
        return Ok(());
    }

    // and this attr should have a value
    let id: *const xmlChar = xmlNodeListGetString((*node).doc, (*attr).children, 1);
    if id == null() {
        return Ok(());
    }

    // check that we don't have same ID already
    let tmp_attr = xmlGetID((*node).doc, id);
    if tmp_attr == null_mut() {
        xmlAddID(null_mut(), (*node).doc, id, attr);
    }

    // This is always must work because we initialized the libxml2 library
    // already and if this isn't set we have much bigger issue.
    (xmlFree.unwrap())(id as *mut std::ffi::c_void);

    Ok(())
}
