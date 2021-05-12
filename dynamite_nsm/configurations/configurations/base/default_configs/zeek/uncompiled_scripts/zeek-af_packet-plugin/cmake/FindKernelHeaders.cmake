# - Try to find kernel includes.
#
# Based on FindKernelHeaders.cmake by David Sansome (me@davidsansome.com)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  KERNELHEADERS_ROOT_DIR    Set this variable to the root directory of the
#                            kernel sources if the module has problems finding
#                            the proper path.
#
#  KERNELHEADERS_LATEST      Set this option ON to use the latest kernel
#                            headers available on the system.
#
# Variables defined by this module:
#
#  KERNELHEADERS_FOUND         System has kernel headers.

# Define latest-headers-switch as cache variable
set(KERNELHEADERS_LATEST OFF CACHE BOOL "use latest kernel headers")

# Search paths:
set(KERNEL_PATHS
  /usr/src/linux-headers-
  /usr/src/kernels/
)

if ( NOT KERNELHEADERS_LATEST )
	# Find the kernel release
	execute_process(
	  COMMAND uname -r
	  OUTPUT_VARIABLE KERNEL_RELEASE
	  OUTPUT_STRIP_TRAILING_WHITESPACE
	)

	foreach ( KERNEL_PATH ${KERNEL_PATHS} )
		list(APPEND KERNEL_RELEASE_PATHS "${KERNEL_PATH}${KERNEL_RELEASE}")
	endforeach (KERNEL_PATH)

	find_path(KERNELHEADERS_ROOT_DIR
	  NAMES include/linux/user.h
	  PATHS ${KERNEL_RELEASE_PATHS}
	)
else ()
	# Use latest header version
	foreach ( KERNEL_PATH ${KERNEL_PATHS} )
		# Search for any installed headers
		file(GLOB KERNELS_AVAILABLE "${KERNEL_PATH}*")

		if ( KERNELS_AVAILABLE )
			# Get the newest kernel
			list(SORT KERNELS_AVAILABLE)
			list(REVERSE KERNELS_AVAILABLE)
			list(GET KERNELS_AVAILABLE 0 KERNEL_LATEST_PATH)

			find_path(KERNELHEADERS_ROOT_DIR
			  NAMES include/linux/user.h
			  PATHS ${KERNEL_LATEST_PATH}
			)

			if ( KERNELHEADERS_ROOT_DIR )
				break ()
			endif ()
		endif ()
	endforeach ( KERNEL_PATH )
endif ()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(KernelHeaders DEFAULT_MSG
    KERNELHEADERS_ROOT_DIR
)

mark_as_advanced(
    KERNELHEADERS_ROOT_DIR
)