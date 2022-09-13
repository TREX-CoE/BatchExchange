if (NOT GIT_FOUND)
        find_program(GIT_FOUND git)
endif (NOT GIT_FOUND)

if (NOT DATE_FOUND)
        find_program(DATE_FOUND date)
endif (NOT DATE_FOUND)

# split datestr in common format from utc_date or utc_git to cmake struct with datetime parts
macro (_split_date IN OUT)
        string( REGEX MATCH "0*([0-9]+)-0*([0-9]+)-0*([0-9]+) ([0-9]+):([0-9]+):([0-9]+)" _TMP "${IN}")

        set( "${OUT}_YEAR" ${CMAKE_MATCH_1})
        set( "${OUT}_MONTH" ${CMAKE_MATCH_2})
        set( "${OUT}_DAY" ${CMAKE_MATCH_3})
        set( "${OUT}_HOUR" ${CMAKE_MATCH_4})
        set( "${OUT}_MINUTE" ${CMAKE_MATCH_5})
        set( "${OUT}_SECOND" ${CMAKE_MATCH_6})
endmacro()

# get datetime parts from "date" command
macro (utc_date OUT)
        execute_process(COMMAND "${DATE_FOUND}" "+%Y-%m-%d %H:%M:%S %z"
                OUTPUT_VARIABLE _TMP
                OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        _split_date("${_TMP}" "${OUT}")
endmacro()

# get datetime parts from last git log entry
macro (utc_git OUT WORK_DIR)
        execute_process(COMMAND "${GIT_FOUND}" log -n 1 --date=iso
                WORKING_DIRECTORY "${WORK_DIR}"
                OUTPUT_VARIABLE _TMP
                RESULT_VARIABLE "${OUT}_RESULT"
                OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        _split_date("${_TMP}" "${OUT}")
endmacro()

# strip leading zeros, e.g. for datetime parts
macro (lstrip_zeroes IN OUT_VAR)
        string( REGEX MATCH "0*([0-9]+)" _TMP "${IN}")
        set( "${OUT_VAR}" ${CMAKE_MATCH_1})
endmacro()

find_package( Git QUIET)

set( GIT_VERSION_HASH	"unknown"	)
set( GIT_BUILD_BRANCH	"unknown"	)
set( GIT_REVISION_COUNT	"0"		)

if (GIT_FOUND)
        utc_git(DATE "${CMAKE_CURRENT_SOURCE_DIR}")

        if (NOT GIT_LAST_LOG_ENTRY_RESULT)
                set( GIT_LAST_LOG_ENTRY ${GIT_LAST_LOG_ENTRY_tmp})
        endif (NOT GIT_LAST_LOG_ENTRY_RESULT)

        execute_process(COMMAND                 git rev-parse --short HEAD
                        WORKING_DIRECTORY       "${CMAKE_CURRENT_SOURCE_DIR}"
                        OUTPUT_VARIABLE         GIT_VERSION_HASH_tmp
                        RESULT_VARIABLE         GIT_VERSION_HASH_RESULT
                        OUTPUT_STRIP_TRAILING_WHITESPACE
        )

        execute_process(COMMAND                 git rev-parse --abbrev-ref HEAD
                        WORKING_DIRECTORY       "${CMAKE_CURRENT_SOURCE_DIR}"
                        OUTPUT_VARIABLE         GIT_BUILD_BRANCH_tmp
                        RESULT_VARIABLE         GIT_BUILD_BRANCH_RESULT
                        OUTPUT_STRIP_TRAILING_WHITESPACE
        )

        execute_process(COMMAND                 git rev-list --count HEAD
                        WORKING_DIRECTORY       "${CMAKE_CURRENT_SOURCE_DIR}"
                        OUTPUT_VARIABLE         GIT_REVISION_COUNT_tmp
                        RESULT_VARIABLE         GIT_REVISION_COUNT_RESULT
                        OUTPUT_STRIP_TRAILING_WHITESPACE
        )

        if (NOT GIT_VERSION_HASH_RESULT)
                set( GIT_VERSION_HASH "${GIT_VERSION_HASH_tmp}" )
        endif ()

        if (NOT GIT_BUILD_BRANCH_RESULT)
                set( GIT_BUILD_BRANCH "${GIT_BUILD_BRANCH_tmp}" )
        endif ()

        if (NOT GIT_REVISION_COUNT_RESULT)
                set( GIT_REVISION_COUNT "${GIT_REVISION_COUNT_tmp}" )
        endif ()
endif ()

# getting date from git log failed, use "date" command instead
if (DATE_RESULT)
        utc_date(DATE)
endif()

# use date parts (without leading zeros) for rudimentary version numbers
#lstrip_zeroes( "${DATE_YEAR}" PACKAGE_VERSION_MAJOR)
#lstrip_zeroes( "${DATE_MONTH}" PACKAGE_VERSION_MINOR)
#lstrip_zeroes( "${DATE_DAY}" PACKAGE_VERSION_PATCH)

execute_process(COMMAND git tag -l
                COMMAND grep -E "[v,V][[:digit:]]+[.][[:digit:]]+[.][[:digit:]]+"
                COMMAND sort --ignore-case
                COMMAND tail -n 1
                WORKING_DIRECTORY       "${CMAKE_CURRENT_SOURCE_DIR}"
                OUTPUT_VARIABLE         GIT_LAST_TAG
                RESULT_VARIABLE         GIT_LAST_TAG_ERROR
                OUTPUT_STRIP_TRAILING_WHITESPACE
)
message("Last git version tag found: ${GIT_LAST_TAG}")

if(GIT_LAST_TAG)

        # remove version v from tag
        string(REPLACE "v" "" GIT_LAST_TAG_TMP ${GIT_LAST_TAG})
        string(REPLACE "V" "" GIT_LAST_TAG_CLEAN ${GIT_LAST_TAG_TMP})
        # extract major version
        string(FIND ${GIT_LAST_TAG_CLEAN} "." POS_MAJOR)
        string(SUBSTRING ${GIT_LAST_TAG_CLEAN} 0 ${POS_MAJOR} VERSION_MAJOR)
        string(SUBSTRING ${GIT_LAST_TAG_CLEAN} ${POS_MAJOR} -1 GIT_LAST_TAG_TMP)
        string(SUBSTRING ${GIT_LAST_TAG_TMP} 1 -1 GIT_LAST_TAG_CLEAN)
        # extract minor version
        string(FIND ${GIT_LAST_TAG_CLEAN} "." POS_MINOR)
        string(SUBSTRING ${GIT_LAST_TAG_CLEAN} 0 ${POS_MINOR} VERSION_MINOR)
        string(SUBSTRING ${GIT_LAST_TAG_CLEAN} ${POS_MINOR} -1 GIT_LAST_TAG_TMP)
        # string left ist patch version
        string(SUBSTRING ${GIT_LAST_TAG_TMP} 1 -1 VERSION_PATCH)

        set(PACKAGE_VERSION_MAJOR ${VERSION_MAJOR})
        set(PACKAGE_VERSION_MINOR ${VERSION_MINOR})
        set(PACKAGE_VERSION_PATCH ${VERSION_PATCH})

endif()

# semi RFC3339 compliant datetime (using whitespace instead of T, and no Z) of last commit or build otherwise
set(BUILD_DATE "${DATE_YEAR}-${DATE_MONTH}-${DATE_DAY} ${DATE_HOUR}:${DATE_MINUTE}:${DATE_SECOND}")
