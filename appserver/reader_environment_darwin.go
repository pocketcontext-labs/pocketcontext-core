//go:build darwin && cgo

package appserver

/*
#cgo LDFLAGS: -framework ApplicationServices -framework CoreFoundation
#include <ApplicationServices/ApplicationServices.h>
#include <CoreFoundation/CoreFoundation.h>
#include <unistd.h>

// 1: this graphical login session; 0: no usable graphical session; -1: unknown.
static int context_graphical_session(void) {
 CFDictionaryRef session = CGSessionCopyCurrentDictionary();
 if (!session) return 0;
 CFNumberRef uid = (CFNumberRef)CFDictionaryGetValue(session, kCGSessionUserIDKey);
 CFBooleanRef console = (CFBooleanRef)CFDictionaryGetValue(session, kCGSessionOnConsoleKey);
 int user = -1;
 int result = -1;
 if (uid && CFGetTypeID(uid) == CFNumberGetTypeID() && CFNumberGetValue(uid, kCFNumberIntType, &user) &&
     console && CFGetTypeID(console) == CFBooleanGetTypeID()) {
  result = user == (int)getuid() && CFBooleanGetValue(console) ? 1 : 0;
 }
 CFRelease(session);
 return result;
}

static int context_http_handler(void) {
 CFStringRef handler = LSCopyDefaultHandlerForURLScheme(CFSTR("http"));
 if (!handler) return 0;
 // Verify the association resolves to an installed application, without launching it.
 CFURLRef app = NULL;
 OSStatus status = LSFindApplicationForInfo(kLSUnknownCreator, handler, NULL, NULL, &app);
 CFRelease(handler);
 if (app) CFRelease(app);
 return status == noErr ? 1 : 0;
}
*/
import "C"

import "os/exec"

func nativeReaderEnvironment() ReaderEnvironmentInfo {
	switch int(C.context_graphical_session()) {
	case 0:
		return ReaderEnvironmentInfo{"headless", "unknown", "No accessible graphical login session was detected for this process"}
	case -1:
		return ReaderEnvironmentInfo{"unknown", "unknown", "The graphical login session could not be determined"}
	}
	if _, err := exec.LookPath("open"); err != nil {
		return ReaderEnvironmentInfo{"desktop", "unavailable", "The desktop browser launcher is unavailable"}
	}
	if C.context_http_handler() == 0 {
		return ReaderEnvironmentInfo{"desktop", "unavailable", "No installed default HTTP browser handler was detected"}
	}
	return ReaderEnvironmentInfo{"desktop", "available", "Graphical login session and HTTP browser handler detected; opening is not yet verified"}
}
