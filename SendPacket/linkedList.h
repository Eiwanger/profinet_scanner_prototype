
#include "stdafx.h"

#ifndef LINKEDLIST_H
#define LINKEDLIST_H




extern int add_to_list(linked_list_t *ll, datasheet* d, epm_handle* eh);

// will count the number of elements in the list
// return value: amount
extern int linkedlist_status(linked_list_t *ll);
// remove all items from the list and will free allocated memory
// return value items deleted from list
extern int empty_list(linked_list_t *ll);
extern void createSeqNum(rpc_sequenceNum* sequenceNum);
extern void initHandle(epm_handle* handle);

extern linkedList_slot* createSlotList();
extern linkedList_subslot* createSubslotList();

extern int empty_SlotList(linkedList_slot *ll);
extern int empty_SubSlotList(linkedList_subslot *ll);



#endif