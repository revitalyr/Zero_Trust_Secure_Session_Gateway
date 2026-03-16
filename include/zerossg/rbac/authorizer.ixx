module;

#include <memory>
#include <string>
#include <vector>

export module zerossg.rbac.authorizer;

export import zerossg.common;
export import zerossg.types;

export namespace zerossg {

// Forward declarations
export class Authorizer;

// Authorizer interface class
export class Authorizer {
public:
    virtual ~Authorizer() = default;
    virtual Result<bool> can_access_service(const User& user, const ServiceName& service_name) = 0;
    virtual Result<bool> has_permission(const User& user, const String& permission) = 0;
    virtual Result<Strings> get_allowed_services(const User& user) = 0;
};

} // namespace zerossg
