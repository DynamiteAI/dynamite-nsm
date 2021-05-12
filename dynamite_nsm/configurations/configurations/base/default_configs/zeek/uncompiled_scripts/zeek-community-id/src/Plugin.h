
#ifndef BRO_PLUGIN_CORELIGHT_COMMUNITYID
#define BRO_PLUGIN_CORELIGHT_COMMUNITYID

#include <plugin/Plugin.h>

namespace plugin {
namespace Corelight_CommunityID {

class Plugin : public ::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}

#endif
