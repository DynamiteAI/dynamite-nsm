
cmake_minimum_required(VERSION 2.8)

project(BroPluginCommunityID)

include(BroPlugin)

bro_plugin_begin(Corelight CommunityID)
bro_plugin_cc(src/Plugin.cc)
bro_plugin_bif(src/communityid.bif)
bro_plugin_dist_files(README CHANGES COPYING VERSION)
bro_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${BRO_HAS_OLD_DIGEST_CODE}")
   add_definitions(-DBRO_HAS_OLD_DIGEST_CODE)
endif ()

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
