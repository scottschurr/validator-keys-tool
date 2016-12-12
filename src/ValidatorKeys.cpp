//------------------------------------------------------------------------------
/*
    This file is part of validator-keys-tool:
        https://github.com/ripple/validator-keys-tool
    Copyright (c) 2016 Ripple Labs Inc.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose  with  or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE  SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH  REGARD  TO  THIS  SOFTWARE  INCLUDING  ALL  IMPLIED  WARRANTIES  OF
    MERCHANTABILITY  AND  FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY  SPECIAL ,  DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER  RESULTING  FROM  LOSS  OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION  OF  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
//==============================================================================

#include <ValidatorKeys.h>
#include <json_reader.h>
#include <ripple/protocol/HashPrefix.h>
#include <ripple/protocol/Sign.h>
#include <beast/core/detail/base64.hpp>
#include <fstream>

namespace ripple {

ValidatorKeys::ValidatorKeys (KeyType const& keyType)
    : keyType_ (keyType)
    , sequence_ (0)
{
    auto seed = randomSeed ();
    auto const kp = generateKeyPair (keyType, seed);

    masterSecret_ = kp.second;
    validationPublicKey_ = kp.first;
}

ValidatorKeys::ValidatorKeys (
    KeyType const& keyType,
    SecretKey const& masterSecret,
    PublicKey const& validationPublicKey,
    std::uint32_t sequence)
    : keyType_ (keyType)
    , masterSecret_ (masterSecret)
    , validationPublicKey_ (validationPublicKey)
    , sequence_ (sequence)
{
}

ValidatorKeys
ValidatorKeys::make_ValidatorKeys (
    boost::filesystem::path const& keyFile)
{
    std::ifstream ifsKeys (keyFile.c_str (), std::ios::in);

    if (! ifsKeys)
        throw std::runtime_error (
            "Failed to open key file: " + keyFile.string());

    Json::Reader reader;
    Json::Value jKeys;
    if (! reader.parse (ifsKeys, jKeys))
    {
        throw std::runtime_error (
            "Unable to parse json key file: " + keyFile.string());
    }

    static std::array<std::string, 3> const requiredFields {{
        "key_type",
        "master_secret",
        "sequence"
    }};

    for (auto field : requiredFields)
    {
        if (! jKeys.isMember(field))
        {
            throw std::runtime_error (
                "Key file '" + keyFile.string() +
                "' is missing \"" + field + "\" field");
        }
    }

    auto const keyType = keyTypeFromString (jKeys["key_type"].asString());
    if (keyType == KeyType::invalid)
    {
        throw std::runtime_error (
            "Key file '" + keyFile.string() +
            "' contains invalid key type: " +
            jKeys["key_type"].toStyledString());
    }

    auto const masterSecret = parseBase58<SecretKey> (
        TokenType::TOKEN_NODE_PRIVATE, jKeys["master_secret"].asString());

    if (! masterSecret)
    {
        throw std::runtime_error (
            "Key file '" + keyFile.string() +
            "' contains invalid master secret: " +
            jKeys["master_secret"].toStyledString());
    }

    auto const validationPublicKey = derivePublicKey(keyType, *masterSecret);

    if (! jKeys["sequence"].isIntegral())
    {
        throw std::runtime_error (
            "Key file '" + keyFile.string() +
            "' contains invalid sequence: " +
            jKeys["sequence"].toStyledString());
    }

    return ValidatorKeys (
        keyType, *masterSecret,
        validationPublicKey, jKeys["sequence"].asUInt());
}

void
ValidatorKeys::writeToFile (
    boost::filesystem::path const& keyFile) const
{
    using namespace boost::filesystem;

    Json::Value jv;
    jv["master_secret"] = toBase58(TOKEN_NODE_PRIVATE, masterSecret());
    jv["validation_public_key"] = toBase58(
        TOKEN_NODE_PUBLIC, validationPublicKey());
    jv["key_type"] = to_string(keyType());
    jv["sequence"] = Json::UInt (sequence());

    if (! keyFile.parent_path().empty())
    {
        boost::system::error_code ec;
        if (! exists (keyFile.parent_path()))
            boost::filesystem::create_directories(keyFile.parent_path(), ec);

        if (ec || ! is_directory (keyFile.parent_path()))
            throw std::runtime_error ("Cannot create directory: " +
                    keyFile.parent_path().string());
    }

    std::ofstream o (keyFile.string (), std::ios_base::trunc);
    if (o.fail())
        throw std::runtime_error ("Cannot open key file: " +
            keyFile.string());

    o << jv.toStyledString();
}

EphemeralKeys
ValidatorKeys::createEphemeralKeys (
    KeyType const& ephKeyType) const
{
    auto const seed = randomSeed ();
    auto const ssk = generateSecretKey (ephKeyType, seed);
    auto const spk = derivePublicKey(ephKeyType, ssk);

    STObject st(sfGeneric);
    st[sfSequence] = sequence();
    st[sfPublicKey] = validationPublicKey();
    st[sfSigningPubKey] = spk;

    sign(st, HashPrefix::manifest, ephKeyType, ssk);

    sign(st, HashPrefix::manifest, keyType(), masterSecret(),
        sfMasterSignature);

    Serializer s;
    st.add(s);

    std::string m (static_cast<char const*> (s.data()), s.size());
    return EphemeralKeys {
        seed, beast::detail::base64_encode(m), spk };
}

} // ripple
