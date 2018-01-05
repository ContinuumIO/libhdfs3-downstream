#ifndef _HDFS_LIBHDFS3_SERVER_DATAREADER_H_
#define _HDFS_LIBHDFS3_SERVER_DATAREADER_H_

#include <string>
#include <vector>
namespace Hdfs {
namespace Internal {

/**
 * Helps read data responses from the server
 */
class DataReader {
public:
    DataReader(DataTransferProtocol *sender,
            shared_ptr<BufferedSocketReader> reader, int readTimeout);
    std::vector<char>& readResponse(const char* text, int &outsize);
    std::vector<char>& readPacketHeader(const char* text, int size, int &outsize);
    std::string& getRest() {
        return rest;
    }

    void setRest(const char* data, int size);
    void reduceRest(int size);
    void getMissing(int size);

private:
    std::string raw;
    std::string decrypted;
    std::string rest;
    std::vector<char> buf;
    DataTransferProtocol *sender;
    shared_ptr<BufferedSocketReader> reader;
    int readTimeout;
};

}
}

#endif /* _HDFS_LIBHDFS3_SERVER_DATAREADER_H_ */