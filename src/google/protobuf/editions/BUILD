load("@rules_cc//cc:defs.bzl", "cc_proto_library")
load("//tools/build_defs/testing:bzl_library.bzl", "bzl_library")

proto_library(
    name = "test_messages_proto2_proto",
    srcs = ["golden/test_messages_proto2.proto"],
    deps = ["//src/google/protobuf:cpp_features_proto"],
)

proto_library(
    name = "test_messages_proto3_proto",
    srcs = ["golden/test_messages_proto3.proto"],
    deps = [
        "//:any",
        "//:duration",
        "//:field_mask",
        "//:struct",
        "//:timestamp",
        "//:wrappers",
        "//src/google/protobuf:cpp_features_proto",
    ],
)

cc_proto_library(
    name = "test_messages_proto2_cc_proto",
    deps = [":test_messages_proto2_proto"],
)

cc_proto_library(
    name = "test_messages_proto3_cc_proto",
    deps = [":test_messages_proto3_proto"],
)

cc_test(
    name = "generated_files_test",
    srcs = ["generated_files_test.cc"],
    deps = [
        ":test_messages_proto2_cc_proto",
        ":test_messages_proto3_cc_proto",
        "//testing/base/public:gunit_main",
        "//src/google/protobuf",
        "//src/google/protobuf:test_textproto",
    ],
)

cc_test(
    name = "generated_reflection_test",
    srcs = ["generated_reflection_test.cc"],
    deps = [
        ":test_messages_proto2_cc_proto",
        "//testing/base/public:gunit_main",
    ],
)
