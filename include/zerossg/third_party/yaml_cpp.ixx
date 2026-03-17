module;
#include <yaml-cpp/yaml.h>

export module zerossg.third_party.yaml_cpp;

export namespace zerossg {
    using YAML::Node;
    using YAML::LoadFile;
    using YAML::Dump;
    using YAML::Emitter;
}