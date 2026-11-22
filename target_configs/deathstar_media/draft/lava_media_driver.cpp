/**
 * @file lava_media_driver.cpp
 * @brief Draft file-backed entry into DeathStarBench's generated Thrift decoder.
 *
 * Reads one framed BinaryProtocol ComposeMedia request and invokes the actual
 * generated argument reader. Does not execute MediaHandler, start a server, or
 * claim distributed-service coverage. Requires the pinned Thrift 0.12 toolchain;
 * this source has not been compiled in the current environment.
 */
#include <cstdint>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/transport/TBufferTransports.h>
#include "gen-cpp/MediaService.h"

int main(int argc, const char **argv) try {
    if (argc != 2) {
        throw std::runtime_error("usage: lava_media_driver REQUEST.bin");
    }
    std::ifstream input(argv[1], std::ios::binary);
    if (!input) {
        throw std::runtime_error("cannot open request");
    }
    input.seekg(0, std::ios::end);
    const std::streamoff file_size = input.tellg();
    if (file_size < 4 || file_size > 1024 * 1024) {
        throw std::runtime_error("request exceeds the draft fixture bounds");
    }
    input.seekg(0, std::ios::beg);
    std::vector<uint8_t> bytes(static_cast<size_t>(file_size));
    if (!input.read(reinterpret_cast<char *>(bytes.data()), file_size)) {
        throw std::runtime_error("cannot read complete request");
    }
    const uint32_t size = (uint32_t(bytes[0]) << 24) | (uint32_t(bytes[1]) << 16)
                        | (uint32_t(bytes[2]) << 8) | uint32_t(bytes[3]);
    if (size != bytes.size() - 4) {
        throw std::runtime_error("frame length does not match file length");
    }

    using apache::thrift::protocol::TBinaryProtocol;
    using apache::thrift::protocol::TMessageType;
    using apache::thrift::transport::TMemoryBuffer;
    apache::thrift::stdcxx::shared_ptr<TMemoryBuffer> buffer(
        new TMemoryBuffer(bytes.data() + 4, size, TMemoryBuffer::OBSERVE));
    TBinaryProtocol protocol(buffer, 1024 * 1024, 65536, true, true);
    std::string method;
    TMessageType message_type;
    int32_t sequence;
    protocol.readMessageBegin(method, message_type, sequence);
    if (method != "ComposeMedia" || message_type != apache::thrift::protocol::T_CALL) {
        throw std::runtime_error("expected a ComposeMedia CALL");
    }
    social_network::MediaService_ComposeMedia_args request;
    request.read(&protocol);
    protocol.readMessageEnd();
    if (buffer->available_read() != 0) {
        throw std::runtime_error("unexpected trailing request bytes");
    }
    std::cout << "request=" << request.req_id << " types=" << request.media_types.size()
              << " ids=" << request.media_ids.size() << "\n";
    return 0;
} catch (const std::exception &error) {
    std::cerr << error.what() << "\n";
    return 1;
}
