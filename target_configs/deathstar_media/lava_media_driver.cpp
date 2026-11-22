/**
 * File-backed entry into the pinned upstream MediaService RPC processor.
 *
 * A seed is one framed Thrift BinaryProtocol request, not an IP/TCP packet.
 * MediaServiceProcessor performs upstream deserialization and dispatch into the
 * unchanged MediaHandler::ComposeMedia, then upstream response serialization.
 * media_handler.cpp contains the upstream handler and adapts telemetry startup.
 * Its separate object can also be linked by a future live RPC entry point.
 * This adapter does not run a network server or a distributed application.
 */
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>
#include <opentracing/noop.h>
#include <thrift/TApplicationException.h>
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/transport/TBufferTransports.h>
#include "media_handler.h"

static std::string hex(const std::string& input) {
    static const char digits[] = "0123456789abcdef";
    std::string output;
    for (unsigned char byte : input) {
        output += digits[byte >> 4];
        output += digits[byte & 15];
    }
    return output;
}

int main(int argc, char** argv) try {
    if (argc != 2) throw std::runtime_error("usage: lava_media_driver REQUEST.bin");
    std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
    if (!file) throw std::runtime_error("cannot open request");
    const auto length = file.tellg();
    if (length < 4 || length > 1024 * 1024) throw std::runtime_error("invalid frame size");
    file.seekg(0);
    std::vector<uint8_t> bytes(static_cast<size_t>(length));
    if (!file.read(reinterpret_cast<char*>(bytes.data()), bytes.size()))
        throw std::runtime_error("cannot read request");
    const uint32_t size = (uint32_t(bytes[0]) << 24) | (uint32_t(bytes[1]) << 16)
                        | (uint32_t(bytes[2]) << 8) | uint32_t(bytes[3]);
    if (size != bytes.size() - 4) throw std::runtime_error("frame length mismatch");

    using apache::thrift::protocol::TBinaryProtocol;
    using apache::thrift::transport::TMemoryBuffer;
    using apache::thrift::stdcxx::shared_ptr;
    shared_ptr<TMemoryBuffer> input(new TMemoryBuffer(bytes.data() + 4, size, TMemoryBuffer::OBSERVE));
    shared_ptr<TMemoryBuffer> output(new TMemoryBuffer());
    shared_ptr<TBinaryProtocol> iprot(new TBinaryProtocol(input, 1024 * 1024, 65536, true, true));
    shared_ptr<TBinaryProtocol> oprot(new TBinaryProtocol(output));
    opentracing::Tracer::InitGlobal(opentracing::MakeNoopTracer());
    auto handler = make_lava_media_handler();
    social_network::MediaServiceProcessor processor(handler);
    if (!processor.process(iprot, oprot, nullptr)) throw std::runtime_error("RPC processing failed");
    if (input->available_read() != 0) throw std::runtime_error("trailing request bytes");

    TBinaryProtocol reply(output);
    std::string method;
    apache::thrift::protocol::TMessageType type;
    int32_t sequence;
    reply.readMessageBegin(method, type, sequence);
    if (type == apache::thrift::protocol::T_EXCEPTION) {
        apache::thrift::TApplicationException exception;
        exception.read(&reply);
        std::cout << "{\"status\":\"rpc_exception\",\"message_hex\":\""
                  << hex(exception.what()) << "\"}\n";
        return 0;
    }
    social_network::MediaService_ComposeMedia_result result;
    result.read(&reply);
    reply.readMessageEnd();
    if (result.__isset.se) {
        std::cout << "{\"status\":\"service_exception\",\"error_code\":"
                  << static_cast<int>(result.se.errorCode) << ",\"message_hex\":\"" << hex(result.se.message) << "\"}\n";
    } else if (result.__isset.success) {
        std::cout << "{\"status\":\"ok\",\"media\":[";
        bool first = true;
        for (const auto& media : result.success) {
            if (!first) std::cout << ',';
            first = false;
            std::cout << "{\"id\":" << media.media_id << ",\"type_hex\":\""
                      << hex(media.media_type) << "\"}";
        }
        std::cout << "]}\n";
    } else throw std::runtime_error("missing RPC result");
    return 0;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 2;
}
