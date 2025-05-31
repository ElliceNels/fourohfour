#ifndef CUSTOM_DELETER_H
#define CUSTOM_DELETER_H

#include <curl/curl.h>

namespace custom_deleters {
    // Custom deleter for CURL handles
    struct CurlDeleter {
        void operator()(CURL* curl) const {
            if (curl) {
                curl_easy_cleanup(curl);
            }
        }
    };

    // Custom deleter for curl_slist structures
    struct CurlSListDeleter {
        void operator()(struct curl_slist* list) const {
            if (list) {
                curl_slist_free_all(list);
            }
        }
    };
}

#endif // CUSTOM_DELETER_H
