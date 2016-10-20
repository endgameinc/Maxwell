#include <stdio.h>
#include "hook.h"
#include "ntapi.h"
#include "log.h"
#include "whitelist.h"


NTSTATUS(WINAPI * OldNtDelayExecution)
(
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval
    );
NTSTATUS WINAPI MyNtDelayExecution
(
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval
    )
{
	unsigned long long milli = -DelayInterval->QuadPart / 10000;
	if (milli >= 1000)
	{
		LARGE_INTEGER newDelay;
		newDelay.QuadPart = -10000000;
		return OldNtDelayExecution(Alertable, &newDelay);
	}

	return OldNtDelayExecution(Alertable, DelayInterval);


}


