#include "stdafx.h"

unsigned int seqNumberCounter = 0;

// creates a datasheet and adds it to a existing list
int add_to_list(linked_list_t *ll, datasheet* d, epm_handle* eh)
{
	linked_list_t *new_box;
	if ((new_box = (linked_list_t*)malloc(sizeof(linked_list_t))) == NULL)
	{
		// not enough memory space
		printf("Error allocating space for new node linkedlist\n");
		return -1;
	}
	// check if the datasheet is null
	if (d == NULL)
	{
		return -1;
	}


	// ll wasn't null so set the data and count till tmp->next is null
	new_box->next = NULL; // set next and data
	new_box->device = d;




	while (ll->next != NULL){
		ll = ll->next;
	}
	// now we are at the last position
	new_box->index = ll->index + 1;


	createSeqNum(&(new_box->sequenceNum));

	// set server boot time to zero
	new_box->sBootTime.byte1 = 0x00;
	new_box->sBootTime.byte2 = 0x00;
	new_box->sBootTime.byte3 = 0x00;
	new_box->sBootTime.byte4 = 0x00;

	if (eh)
	{
		new_box->rpc_handle = *eh;
	}
	else{
		initHandle(&(new_box->rpc_handle));

	}
	new_box->finished = false;

	ll->next = new_box;

	return new_box->index;
}

// will count the number of elements in the list
// return value: amount
int linkedlist_status(linked_list_t *ll)
{
	// list does not exits return -1
	if (ll == NULL)
	{
		return -1;
	}
	if (ll->next == NULL)
	{
		// if ll->next is null return the index +1 because of the value at index 0
		return ll->index + 1;
	}
	else{
		// if ll->next is not null call the function recursive with ll->next as ll
		return linkedlist_status(ll->next);
	}
}

// initialise the handle with 0x00
void initHandle(epm_handle* handle)
{
	handle->byte1 = 0x00;
	handle->byte2 = 0x00;
	handle->byte3 = 0x00;
	handle->byte4 = 0x00;
	handle->byte5 = 0x00;
	handle->byte6 = 0x00;
	handle->byte7 = 0x00;
	handle->byte8 = 0x00;
	handle->byte9 = 0x00;
	handle->byte10 = 0x00;
	handle->byte11 = 0x00;
	handle->byte12 = 0x00;
	handle->byte13 = 0x00;
	handle->byte14 = 0x00;
	handle->byte15 = 0x00;
	handle->byte16 = 0x00;
	handle->byte17 = 0x00;
	handle->byte18 = 0x00;
	handle->byte19 = 0x00;
	handle->byte20 = 0x00;
}


// remove all items from the list and will free allocated memory
// return value items deleted from list
int empty_list(linked_list_t *ll){
	linked_list_t *tmp;
	linked_list_t *next;
	// list does not exist
	if (ll == NULL)
	{
		return -1;
	}



	// there are more items
	tmp = ll;

	while (tmp->next != NULL)
	{
		next = tmp -> next; 

	
			
		if (tmp->device->slotList)
		{
			empty_SlotList(tmp->device->slotList);
		}
	

		free(tmp);
		tmp = next;
	}
	// if tmp next is NULL we are at the last box
	// check if there is only one item and free it
	if (!ll->next)
	{
		if (ll->device->nameOfStation)
			free(ll->device->nameOfStation);
		if (ll->device->hardwareRevison)
			free(ll->device->hardwareRevison);
		if (tmp->device->slotList)
		{
			empty_SlotList(tmp->device->slotList);
		}
		free(ll);

		return 0;
	}


	return 0;
}

// create a sequence number from the global variable and increment it
void createSeqNum(rpc_sequenceNum* sequenceNum){

	sequenceNum->byte1 = seqNumberCounter & 0xFF;
	sequenceNum->byte2 = (seqNumberCounter >> 8) & 0xFF;
	sequenceNum->byte3 = (seqNumberCounter >> 16) & 0xFF;
	sequenceNum->byte4 = (seqNumberCounter >> 24) & 0xFF;

	seqNumberCounter++;
}


// create a subslotlist and set its pointer to NULL
linkedList_subslot* createSubslotList(){
	linkedList_subslot *new_subslot;

	if ((new_subslot = malloc(sizeof(linkedList_subslot))) == NULL)
	{
		// not enough memory space
		return NULL;
	}
	
	new_subslot->next = NULL; // set next and data
	new_subslot->peerChassisID = NULL;
	new_subslot->peerMacAddress = NULL;
	new_subslot->peerPortID = NULL;
	new_subslot->ownPortID = NULL;
	new_subslot->MAUType = 0xFFFF;
	new_subslot->portState = 0x0000;

	return new_subslot;
}

// create a slotlist and set its pointer to NULL
linkedList_slot* createSlotList()
{
	linkedList_slot *new_slot;

	if ((new_slot = malloc(sizeof(linkedList_slot))) == NULL)
	{
		// not enough memory space
		return NULL;
	}

	new_slot->moduledata.hardwareRevison = NULL;
	new_slot->moduledata.version = NULL;
	new_slot->moduledata.IMversion = NULL;

	new_slot->next = NULL; 
	new_slot->subslotList = NULL;
	return new_slot;
}

// free a sublslotlist
int empty_SubSlotList(linkedList_subslot *ll){
	linkedList_subslot *tmp;
	linkedList_subslot *last;
	// list does not exist
	if (ll == NULL)
	{
		return -1;
	}


	// check if the first element is null, if not delete it
	if (!ll->next)
	{
		free(ll);
		return 0;
	}

	while (ll->next != NULL)
	{
		tmp = ll;
		last = ll; // in case we only have 1 element

		// start at the end and delete every item
		while (tmp->next != NULL)
		{
			last = tmp;
			tmp = tmp->next;

		}

		if (!tmp->peerChassisID)
			free(tmp->peerChassisID);
		if (!tmp->peerMacAddress)
			free(tmp->peerMacAddress);

		free(tmp);
		last->next = NULL;
	}
	return 0;
}

// free a slotlist
int empty_SlotList(linkedList_slot *ll){
	linkedList_slot *tmp;
	linkedList_slot *last;
	// list does not exist
	if (ll == NULL)
	{
		return -1;
	}

	if (!ll->next)
	{
		free(ll);
		return 0;
	}

	// check if the first element is null, if not delete it
	while (ll->next != NULL)
	{
		tmp = ll;
		last = ll; // in case we only have 1 element

		// start at the end and delete every item
		while (tmp->next != NULL)
		{
			last = tmp;
			tmp = tmp->next;

		}
		if (tmp->subslotList)
		{
			empty_SubSlotList(tmp->subslotList);
		}
		free(tmp);
		last->next = NULL;
	}
	return 0;
}