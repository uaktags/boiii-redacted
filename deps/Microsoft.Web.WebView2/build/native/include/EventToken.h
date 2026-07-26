// Case-compatibility shim: WebView2.h includes "EventToken.h" (mixed case);
// sysroot/mingw provide it lowercase. Resolve on case-sensitive hosts.
#include <eventtoken.h>
