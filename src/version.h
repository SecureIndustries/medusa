
#define MEDUSA_VERSION_MAJOR                            1
#define MEDUSA_VERSION_MINOR                            0
#define MEDUSA_VERSION_PATCH                            5
#define MEDUSA_VERSION_STRING                           "1.0.5"
#define MEDUSA_VERSION                                  MEDUSA_VERSION_CHECK(MEDUSA_VERSION_MAJOR, MEDUSA_VERSION_MINOR, MEDUSA_VERSION_PATCH)
#define MEDUSA_VERSION_CHECK(major, minor, patch)       ((major << 16) | (minor << 8) | (patch))
