// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
  name: "mew-wallet-ios-tweetnacl",
  products: [
    .library(
      name: "mew-wallet-ios-tweetnacl",
      targets: ["mew-wallet-ios-tweetnacl"]),
  ],
  dependencies: [
  ],
  targets: [
    .target(
      name: "tweetnacl-lib",
      dependencies: [],
      path: "tweetnacl",
      exclude: [
        "tweetnacl/binding.gyp",
        "tweetnacl/nodetweetnacl.cc",
        "tweetnacl/package.json",
        "tweetnacl/test.js",
        "tweetnacl/LICENSE",
        "tweetnacl/README.md",
        "tweetnacl/index.js"
      ],
      publicHeadersPath: "include"
    ),
    .target(
      name: "mew-wallet-ios-tweetnacl",
      dependencies: ["tweetnacl-lib"]),
    .testTarget(
      name: "mew-wallet-ios-tweetnacl-tests",
      dependencies: ["mew-wallet-ios-tweetnacl"]),
  ]
)
