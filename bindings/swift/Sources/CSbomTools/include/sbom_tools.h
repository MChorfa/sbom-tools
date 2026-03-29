#ifndef SBOM_TOOLS_H
#define SBOM_TOOLS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum SbomToolsErrorCode {
    SBOM_TOOLS_ERROR_OK = 0,
    SBOM_TOOLS_ERROR_PARSE = 1,
    SBOM_TOOLS_ERROR_DIFF = 2,
    SBOM_TOOLS_ERROR_VALIDATION = 3,
    SBOM_TOOLS_ERROR_IO = 4,
    SBOM_TOOLS_ERROR_UNSUPPORTED = 5,
    SBOM_TOOLS_ERROR_INTERNAL = 6
} SbomToolsErrorCode;

typedef enum SbomToolsScoringProfile {
    SBOM_TOOLS_PROFILE_MINIMAL = 0,
    SBOM_TOOLS_PROFILE_STANDARD = 1,
    SBOM_TOOLS_PROFILE_SECURITY = 2,
    SBOM_TOOLS_PROFILE_LICENSE_COMPLIANCE = 3,
    SBOM_TOOLS_PROFILE_CRA = 4,
    SBOM_TOOLS_PROFILE_COMPREHENSIVE = 5
} SbomToolsScoringProfile;

typedef struct SbomToolsStringResult {
    char *data;
    SbomToolsErrorCode error_code;
    char *error_message;
} SbomToolsStringResult;

SbomToolsStringResult sbom_tools_abi_version_json(void);
SbomToolsStringResult sbom_tools_detect_format_json(const char *content);
SbomToolsStringResult sbom_tools_parse_sbom_path_json(const char *path);
SbomToolsStringResult sbom_tools_parse_sbom_str_json(const char *content);
SbomToolsStringResult sbom_tools_diff_sboms_json(
    const char *old_sbom_json,
    const char *new_sbom_json
);
SbomToolsStringResult sbom_tools_score_sbom_json(
    const char *sbom_json,
    SbomToolsScoringProfile profile
);
void sbom_tools_string_result_free(SbomToolsStringResult result);

#ifdef __cplusplus
}
#endif

#endif