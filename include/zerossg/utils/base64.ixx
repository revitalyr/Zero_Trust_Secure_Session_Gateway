module;

#include <string>
#include <vector>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

export module zerossg.utils.base64;

export namespace zerossg {

inline std::string base64_encode(const std::vector<unsigned char>& data) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    
    BIO_write(bio, data.data(), static_cast<int>(data.size()));
    BIO_flush(bio);
    
    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);
    
    std::string result(buffer_ptr->data, buffer_ptr->length - 1); // Remove newline
    BIO_free_all(bio);
    
    return result;
}

inline std::string base64_encode(const std::string& data) {
    return base64_encode(std::vector<unsigned char>(data.begin(), data.end()));
}

inline std::vector<unsigned char> base64_decode(const std::string& encoded) {
    BIO* bio = BIO_new_mem_buf(encoded.data(), encoded.length());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    
    std::vector<unsigned char> result(encoded.length());
    int decoded_length = BIO_read(bio, result.data(), encoded.length());
    
    BIO_free_all(bio);
    result.resize(decoded_length);
    
    return result;
}

inline std::string base64_decode_string(const std::string& encoded) {
    auto decoded = base64_decode(encoded);
    return std::string(decoded.begin(), decoded.end());
}

} // namespace zerossg
