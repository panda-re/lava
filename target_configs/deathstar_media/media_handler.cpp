/**
 * Compile the unchanged upstream business handler in one reusable translation
 * unit. The local guards adapt telemetry startup only. See prepare.py and the
 * source manifest for the exact upstream TextMapReader/Writer provenance.
 */
#include "media_handler.h"
#include <opentracing/tracer.h>
#include "media_tracing_types.h"
#define SOCIAL_NETWORK_MICROSERVICES_LOGGER_H
#define SOCIAL_NETWORK_MICROSERVICES_TRACING_H
#include "socialNetwork/src/MediaService/MediaHandler.h"

apache::thrift::stdcxx::shared_ptr<social_network::MediaServiceIf> make_lava_media_handler() {
    return apache::thrift::stdcxx::shared_ptr<social_network::MediaServiceIf>(
        new social_network::MediaHandler());
}
