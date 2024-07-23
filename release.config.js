module.exports = {
  branches: ["main"],
  repositoryUrl: "https://github.com/codevault-llc/certshield",
  plugins: [
    "@semantic-release/commit-analyzer",
    "@semantic-release/release-notes-generator",
    "@semantic-release/changelog",
    "@semantic-release/github",
    [
      "@semantic-release/github",
      {
        assets: [
          {
            path: "certshield-ubuntu-latest-amd64.tar.gz",
            label: "certshield-ubuntu-latest-amd64",
          },
          {
            path: "certshield-windows-latest-amd64.zip",
            label: "certshield-windows-latest-amd64",
          },
          {
            path: "certshield-macos-latest-amd64.tar.gz",
            label: "certshield-macos-latest-amd64",
          },
          {
            path: "certshield-ubuntu-latest-386.tar.gz",
            label: "certshield-ubuntu-latest-386",
          },
          {
            path: "certshield-windows-latest-386.zip",
            label: "certshield-windows-latest-386",
          },
          {
            path: "certshield-macos-latest-386.tar.gz",
            label: "certshield-macos-latest-386",
          },
          {
            path: "certshield-ubuntu-latest-arm.tar.gz",
            label: "certshield-ubuntu-latest-arm",
          },
          {
            path: "certshield-windows-latest-arm.zip",
            label: "certshield-windows-latest-arm",
          },
          {
            path: "certshield-macos-latest-arm.tar.gz",
            label: "certshield-macos-latest-arm",
          },
          {
            path: "certshield-ubuntu-latest-arm64.tar.gz",
            label: "certshield-ubuntu-latest-arm64",
          },
          {
            path: "certshield-windows-latest-arm64.zip",
            label: "certshield-windows-latest-arm64",
          },
          {
            path: "certshield-macos-latest-arm64.tar.gz",
            label: "certshield-macos-latest-arm64",
          },
        ],
      },
    ],
  ],
};
