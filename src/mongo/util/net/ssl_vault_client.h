/**
 *    Copyright (C) 2026-present Percona and/or its affiliates.
 */

#pragma once

#include <string>

namespace mongo {

struct SSLVaultConfig {
    std::string host;
    int port = 8200;
    bool tlsEnabled = true;
    std::string tlsConnectCAFile;
    std::string nameSpace;
    std::string roleId;
    std::string secretId;
    std::string mountPath;
    std::string roleName;
    std::string certificateCN;
};

struct SSLVaultIssueResult {
    std::string certificatePem;
    std::string privateKeyPem;
    std::string caChainPem;
};

/**
 * Minimal Vault PKI client adapted from abedra/libvault workflow:
 * - AppRole login
 * - PKI certificate issue
 */
class SSLVaultClient {
public:
    explicit SSLVaultClient(SSLVaultConfig config);

    SSLVaultIssueResult issueTLSCertificate() const;

private:
    std::string _appRoleLogin() const;

    SSLVaultConfig _config;
};

}  // namespace mongo
