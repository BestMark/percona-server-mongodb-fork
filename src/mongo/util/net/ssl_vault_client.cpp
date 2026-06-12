/**
 *    Copyright (C) 2026-present Percona and/or its affiliates.
 */

#define MONGO_LOGV2_DEFAULT_COMPONENT ::mongo::logv2::LogComponent::kControl

#include "mongo/platform/basic.h"

#include "mongo/util/net/ssl_vault_client.h"

#include <cstddef>
#include <type_traits>
#include <utility>
#include <vector>

#include "mongo/base/data_range.h"
#include "mongo/base/error_codes.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/bson/json.h"
#include "mongo/logv2/log.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/net/http_client.h"
#include "mongo/util/str.h"
#include "mongo/util/text.h"

namespace mongo {
namespace {

template <typename T>
T bsonGetNestedField(const BSONObj& object, const StringData& dottedPath) {
    const auto components = StringSplitter::split(dottedPath.toString(), ".");
    BSONObj currentObj = object;
    BSONElement elem;
    for (size_t i = 0; i < components.size(); ++i) {
        elem = currentObj[components[i]];
        if (i + 1 < components.size()) {
            uassert(ErrorCodes::BadValue,
                    str::stream() << "Field '" << dottedPath << "' is missing or not an object",
                    elem.type() == mongo::Object);
            currentObj = elem.Obj();
        }
    }

    if constexpr (std::is_same_v<T, std::string>) {
        uassert(ErrorCodes::BadValue,
                str::stream() << "Field '" << dottedPath << "' is missing or not a string",
                elem.type() == mongo::String);
        return elem.valueStringDataSafe().toString();
    } else if constexpr (std::is_same_v<T, BSONArray>) {
        uassert(ErrorCodes::BadValue,
                str::stream() << "Field '" << dottedPath << "' is missing or not an array",
                elem.type() == mongo::Array);
        return elem.Array();
    } else {
        static_assert(!std::is_same_v<T, T>, "unsupported bsonGetNestedField type");
    }
}

std::string bodyFromDataBuilder(const DataBuilder& data) {
    ConstDataRangeCursor cursor = data.getCursor();
    return StringData(cursor.data(), cursor.length()).toString();
}

std::string normalizeMountPath(std::string value) {
    while (!value.empty() && value.front() == '/') {
        value.erase(value.begin());
    }
    while (!value.empty() && value.back() == '/') {
        value.pop_back();
    }
    return value;
}

std::string joinPemArray(const BSONArray& pemArray) {
    std::string result;
    for (const auto& chainPart : pemArray) {
        uassert(ErrorCodes::BadValue,
                "Vault returned non-string certificate chain entry",
                chainPart.type() == mongo::String);
        result += chainPart.valueStringDataSafe();
        result += "\n";
    }
    return result;
}

std::unique_ptr<HttpClient> makeHttpClient(const SSLVaultConfig& config,
                                           const std::vector<std::string>& headers) {
    auto httpClient = HttpClient::createWithoutConnectionPool();
    httpClient->allowInsecureHTTP(!config.tlsEnabled);
    if (!config.tlsConnectCAFile.empty()) {
        httpClient->setCAFile(config.tlsConnectCAFile);
    }
    httpClient->setHeaders(headers);
    return httpClient;
}

std::string makeUrlBase(const SSLVaultConfig& config) {
    return str::stream() << (config.tlsEnabled ? "https://" : "http://") << config.host << ":"
                         << config.port << "/v1/";
}

}  // namespace

SSLVaultClient::SSLVaultClient(SSLVaultConfig config) : _config(std::move(config)) {
    uassert(ErrorCodes::BadValue,
            "net.tls.vault.host must be provided when net.tls.vault.enabled is true",
            !_config.host.empty());
    uassert(ErrorCodes::BadValue,
            "net.tls.vault.roleId must be provided when net.tls.vault.enabled is true",
            !_config.roleId.empty());
    uassert(ErrorCodes::BadValue,
            "net.tls.vault.secretId must be provided when net.tls.vault.enabled is true",
            !_config.secretId.empty());
    uassert(ErrorCodes::BadValue,
            "net.tls.vault.mountPath must be provided when net.tls.vault.enabled is true",
            !_config.mountPath.empty());
    uassert(ErrorCodes::BadValue,
            "net.tls.vault.roleName must be provided when net.tls.vault.enabled is true",
            !_config.roleName.empty());
    uassert(ErrorCodes::BadValue,
            "net.tls.vault.certificateCN must be provided when net.tls.vault.enabled is true",
            !_config.certificateCN.empty());
}

std::string SSLVaultClient::_appRoleLogin() const {
    BSONObjBuilder authRequestBob;
    authRequestBob.append("role_id", _config.roleId);
    authRequestBob.append("secret_id", _config.secretId);
    const auto authRequest = authRequestBob.obj().jsonString();

    std::vector<std::string> headers = {"Content-Type: application/json"};
    if (!_config.nameSpace.empty()) {
        headers.push_back("X-Vault-Namespace: " + _config.nameSpace);
    }

    auto httpClient = makeHttpClient(_config, headers);
    const auto response =
        httpClient->request(HttpClient::HttpMethod::kPOST,
                            str::stream() << makeUrlBase(_config) << "auth/approle/login",
                            ConstDataRange(authRequest.data(),
                                           authRequest.data() + authRequest.size()));

    uassert(ErrorCodes::OperationFailed,
            str::stream() << "Vault AppRole login failed with HTTP code " << response.code,
            response.code == 200);

    const auto authBson = fromjson(bodyFromDataBuilder(response.body));
    return bsonGetNestedField<std::string>(authBson, "auth.client_token");
}

SSLVaultIssueResult SSLVaultClient::issueTLSCertificate() const {
    const auto token = _appRoleLogin();

    BSONObjBuilder issueRequestBob;
    issueRequestBob.append("common_name", _config.certificateCN);
    issueRequestBob.append("format", "pem");
    const auto issueRequest = issueRequestBob.obj().jsonString();

    std::vector<std::string> headers = {"Content-Type: application/json", "X-Vault-Token: " + token};
    if (!_config.nameSpace.empty()) {
        headers.push_back("X-Vault-Namespace: " + _config.nameSpace);
    }

    auto httpClient = makeHttpClient(_config, headers);
    const auto response =
        httpClient->request(HttpClient::HttpMethod::kPOST,
                            str::stream() << makeUrlBase(_config)
                                          << normalizeMountPath(_config.mountPath) << "/issue/"
                                          << _config.roleName,
                            ConstDataRange(issueRequest.data(),
                                           issueRequest.data() + issueRequest.size()));

    uassert(ErrorCodes::OperationFailed,
            str::stream() << "Vault PKI issue request failed with HTTP code " << response.code,
            response.code == 200);

    const auto issueBson = fromjson(bodyFromDataBuilder(response.body));
    const auto certificate = bsonGetNestedField<std::string>(issueBson, "data.certificate");
    const auto privateKey = bsonGetNestedField<std::string>(issueBson, "data.private_key");

    std::string caChain;
    const auto caChainElem = issueBson["data"]["ca_chain"];
    if (caChainElem.type() == mongo::Array) {
        caChain = joinPemArray(caChainElem.Array());
    } else {
        caChain = bsonGetNestedField<std::string>(issueBson, "data.issuing_ca");
        caChain += "\n";
    }

    return SSLVaultIssueResult{certificate, privateKey, caChain};
}

}  // namespace mongo
