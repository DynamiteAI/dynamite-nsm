
#include "Plugin.h"

namespace plugin { namespace Corelight_CommunityID { Plugin plugin; } }

using namespace plugin::Corelight_CommunityID;

plugin::Configuration Plugin::Configure()
	{
	plugin::Configuration config;
	config.name = "Corelight::CommunityID";
	config.description = "\"Community ID\" flow hash support in the connection log";
	config.version.major = 1;
	config.version.minor = 1;
	return config;
	}
