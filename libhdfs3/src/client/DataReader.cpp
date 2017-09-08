#include "DateTime.h"
#include "Pipeline.h"
#include "Logger.h"
#include "Exception.h"
#include "ExceptionInternal.h"
#include "datatransfer.pb.h"
#include "DataReader.h"


#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>

using namespace ::google::protobuf;
using namespace google::protobuf::io;

namespace Hdfs {
namespace Internal {


int fillData(BufferedSocketReader *reader, std::string &raw, bool &error) {
    int offset=0;
    int numRetries=0;
    raw.resize(65536);
    error = false;
    while (numRetries < 5 && offset < 65536) {
        if (reader->poll(100)) {
            int nread = 0;

            try {
                nread = reader->read(&raw[offset], 65536-offset);
            }
            catch (HdfsEndOfStream ex) {
                if (offset == 0)
                    raise;
                break;
            }
            catch (HdfsNetworkException ex) {
                if (offset == 0)
                    raise;
                error = true;
                break;
            }
            if (nread) {
                offset += nread;
                numRetries = 0;
            } else {
                numRetries += 1;
            }
        } else {
            numRetries += 1;
        }
    }
    if (offset == 0) {
        THROW(HdfsIOException, "Couldn't fill buffer")
    }
    raw.resize(offset);
    return offset;

}
DataReader::DataReader(DataTransferProtocol * sender,
        shared_ptr<BufferedSocketReader> reader, int readTimeout) : sender(sender), reader(reader),
            readTimeout(readTimeout), buf(128)
        {
            // max size of packet
            raw.resize(65536);
            decrypted.resize(65536);
        }

std::vector<char>& DataReader::readPacketHeader(const char* text, int size, int &outsize) {
    int nread = size;
    if (rest.size()) {
        decrypted = rest;
        rest = "";
        if (decrypted.size() < size) {
            bool error = false;
            fillData(reader.get(), raw, error);
            decrypted += sender->unwrap(raw);
        }
    } else {
        bool error = false;
        fillData(reader.get(), raw, error);
        if (!error)
            decrypted = sender->unwrap(raw);
        else
            decrypted = raw;
    }
    CodedInputStream stream(reinterpret_cast<const uint8_t *>(decrypted.c_str()), decrypted.length());
    buf.resize(nread);
    bool ret = stream.ReadRaw(&buf[0], nread);
    if (!ret) {
        THROW(HdfsIOException, "cannot parse wrapped datanode data response: %s",
          text);
    }
    rest.assign(&decrypted[nread], decrypted.size()-nread);
    outsize = nread;
    return buf;
}

void DataReader::setRest(const char* data, int size) {
    rest.assign(data, size);
}

void DataReader::getMissing(int size) {
    bool error = false;
    if (sender->isWrapped()) {
        if (!sender->needsLength()) {
            while (size > rest.size()) {
                fillData(reader.get(), raw, error);
                decrypted = sender->unwrap(raw);
                rest = rest + decrypted;
            }
        }
     }
}

void DataReader::reduceRest(int size) {
    std::string temp;
    temp.assign(rest.c_str() + size, rest.size()-size);
    rest = temp;
}

std::vector<char>& DataReader::readResponse(const char* text, int &outsize) {
    int size;
    bool error = false;
    if (sender->isWrapped()) {
        if (!sender->needsLength()) {
            if (rest.size()) {
                decrypted = rest;
                rest = "";
            } else {
                fillData(reader.get(), raw, error);
                if (!error)
                    decrypted = sender->unwrap(raw);
                else
                    decrypted = raw;
            }
            CodedInputStream stream(reinterpret_cast<const uint8_t *>(decrypted.c_str()), decrypted.length());
            bool ret = stream.ReadVarint32((uint32*)&size);

            if (!ret) {
                THROW(HdfsIOException, "cannot parse wrapped datanode size response: %s",
                  text);
            }
            if (decrypted.size() < size) {
                fillData(reader.get(), raw, error);
                decrypted += sender->unwrap(raw);
            }
            buf.resize(size);
            ret = stream.ReadRaw(&buf[0], size);
            if (!ret) {
                THROW(HdfsIOException, "cannot parse wrapped datanode data response: %s",
                  text);
            }
            int offset;
            int pos = decrypted.find(&buf[0], 0, size);
            if (pos == string::npos) {
                THROW(HdfsIOException, "cannot parse wrapped datanode data response: %s",
                  text);
            }

            rest.assign(&decrypted[size+pos], decrypted.size()-(size+pos));
        } else {
            size = reader->readBigEndianInt32(readTimeout);
            buf.resize(size);
            reader->readFully(&buf[0], size, readTimeout);

            std::string data = sender->unwrap(std::string(buf.begin(), buf.end()));

            bool ret;
            CodedInputStream stream(reinterpret_cast<const uint8_t *>(data.c_str()), data.length());
            ret = stream.ReadVarint32((uint32*)&size);
            if (!ret) {
                THROW(HdfsIOException, "cannot parse wrapped datanode size response: %s",
                  text);
            }
            buf.resize(size);
            ret = stream.ReadRaw(&buf[0], size);
            if (!ret) {
                THROW(HdfsIOException, "cannot parse wrapped datanode data response: %s",
                  text);
            }
       }
    }
    else {
        size = reader->readVarint32(readTimeout);
        buf.resize(size);
        reader->readFully(&buf[0], size, readTimeout);
    }
    outsize = size;
    return buf;
}


}
}