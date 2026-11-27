function buildTerraformDownloadUrl(version, platform, arch) {
  return `https://releases.hashicorp.com/terraform/${version}/terraform_${version}_${platform}_${arch}.zip`;
}

function buildTerraformChecksumUrl(version) {
  return `https://releases.hashicorp.com/terraform/${version}/terraform_${version}_SHA256SUMS`;
}

function buildOpenTofuDownloadUrl(version, platform, arch) {
  return `https://github.com/opentofu/opentofu/releases/download/v${version}/tofu_${version}_${platform}_${arch}.zip`;
}

function buildOpenTofuChecksumUrl(version) {
  return `https://github.com/opentofu/opentofu/releases/download/v${version}/tofu_${version}_SHA256SUMS`;
}

function buildScalrCliDownloadUrl(version, platform, arch) {
  return `https://github.com/Scalr/scalr-cli/releases/download/v${version}/scalr-cli_${version}_${platform}_${arch}.zip`;
}

function buildScalrCliChecksumUrl(version) {
  return `https://github.com/Scalr/scalr-cli/releases/download/v${version}/scalr-cli_${version}_checksums.txt`;
}

module.exports = {
  buildOpenTofuChecksumUrl,
  buildOpenTofuDownloadUrl,
  buildScalrCliChecksumUrl,
  buildScalrCliDownloadUrl,
  buildTerraformChecksumUrl,
  buildTerraformDownloadUrl,
};
