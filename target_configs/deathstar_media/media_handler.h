#pragma once
#include "socialNetwork/gen-cpp/MediaService.h"

// A future live RPC entry point can link the SAME instrumented handler object
// used by the file driver, rather than recompiling a pristine upstream header.
apache::thrift::stdcxx::shared_ptr<social_network::MediaServiceIf> make_lava_media_handler();
