find_package(emp-ot)

find_path(EMP-AG2PC_INCLUDE_DIR password-ag2pc/password-ag2pc.h)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(PASSWORD-AG2PC DEFAULT_MSG PASSWORD-AG2PC_INCLUDE_DIR)

if(PASSWORD-AG2PC_FOUND)
	set(PASSWORD-AG2PC_INCLUDE_DIRS ${PASSWORD-AG2PC_INCLUDE_DIR} ${EMP-OT_INCLUDE_DIRS})
	set(PASSWORD-AG2PC_LIBRARIES ${EMP-OT_LIBRARIES})
endif()
