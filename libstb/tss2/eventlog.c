#include<skiboot.h>
#include<eventlog.h>

#include<eventlib.h>
#include<ibmtss/tssmarshal.h>

/*
 * NOTE(maurosr): I wonder if any lock is necessary to manage eventlog. By what
 * I've seen so far, this is just sequential setup code. A lock would be
 * necessary if this code was dynamically - and concurrently - called through
 * opal call by the OS.
 */
int load_eventlog(TpmLogMgr *logmgr, uint8_t *eventlog_ptr,
		  uint32_t eventlog_size)
{
	int rc = 0;
	uint8_t *log_ptr, *ptr;
	uint32_t size;
	TCG_PCR_EVENT *event = NULL;
	TCG_PCR_EVENT2 *event2 = NULL;

	event = calloc(1, sizeof(TCG_PCR_EVENT));
	if(!event)
		return 1;

	event2 = calloc(1, sizeof(TCG_PCR_EVENT2));
	if(!event2){
		rc = 1;
		goto fail;
	}

	logmgr->logMaxSize = eventlog_size;
	logmgr->eventLogInMem = eventlog_ptr;
	logmgr->logSize = 0;

	log_ptr = logmgr->eventLogInMem;
	size = sizeof(TCG_PCR_EVENT);

	//first event in the log is a header
	rc = TSS_EVENT_Line_LE_Unmarshal(event, &log_ptr, &size);
	if(rc)
	{
		prlog(PR_INFO, "Couldn't read event log header event, rc=%d",
		      rc);
		rc = 1;
		goto cleanup;
	}

	//now iterate through all events
	ptr = log_ptr;
	do {
		size = sizeof(TCG_PCR_EVENT2);
		rc = TSS_EVENT2_Line_LE_Unmarshal(event2, &ptr, &size);
		/* something went wrong in parsing (invalid values) or
		 * digest.count is 0 - which doesn't make sense - we stop.
		 */
		if (rc || event2->digests.count == 0 )
			break;
		log_ptr = ptr;

	} while(1);
	logmgr->logSize = log_ptr - logmgr->eventLogInMem;
	logmgr->newEventPtr = log_ptr;


cleanup:
	free(event);
fail:
	free(event2);
	return rc;
}

int add_to_eventlog(TpmLogMgr *logmgr, TCG_PCR_EVENT2 *event)
{
	uint16_t written = 0, ev_size = 0;
	uint32_t  size = sizeof(TCG_PCR_EVENT2);
	int rc = 0;

	/* Calling Marshal function with a NULL buffer to obtain the event size.
	 * It's a well known and safe pattern used in TSS code.
	 * Then check if an event that larger will fit in evenlog buffer, and
	 * only after success here marshal it to eventlog buffer pointed by
	 * logmgr->newEventPtr.
	 */
	TSS_EVENT2_Line_LE_Marshal(event, &ev_size, NULL, &size);
	if(logmgr->logSize + ev_size > logmgr->logMaxSize){
		return 1;
	}

	rc = TSS_EVENT2_Line_LE_Marshal(event, &written,
				     &(logmgr->newEventPtr), &size);

	if(rc)
		return rc;

	logmgr->logSize += ev_size;

	return rc;
}

int build_event(TCG_PCR_EVENT2 *event, TPMI_DH_PCR pcrHandle,
		TPMI_ALG_HASH *hashes, uint8_t hashes_len, const char *digest,
		uint32_t event_type, const char* logmsg)
{

	uint16_t alg_digest_size;
	uint32_t size;

	memset(event, 0, sizeof(TCG_PCR_EVENT2));
	event->pcrIndex = pcrHandle;
	event->eventType = event_type;
	event->digests.count = hashes_len;

	size = sizeof(TPMI_ALG_HASH);
	for (int i=0; i < event->digests.count; i++){
		event->digests.digests[i].hashAlg = hashes[i];
		 TSS_TPMI_ALG_HASH_Marshalu(hashes+i, &alg_digest_size, NULL, &size);

		if (alg_digest_size == 0)
			return 1;
		memcpy(&(event->digests.digests[i].digest), digest,
		       strlen(digest) > alg_digest_size ?
				strlen(digest) : alg_digest_size);

	}

	event->eventSize = strlen(logmsg);
	memset(&(event->event), 0, sizeof(event->event));
	memcpy(&(event->event), logmsg,
	       event->eventSize > TCG_EVENT_LEN_MAX ?
			TCG_EVENT_LEN_MAX - 1: event->eventSize);

	return 0;
}
