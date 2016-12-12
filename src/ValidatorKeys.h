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

#include <ripple/crypto/KeyType.h>
#include <ripple/protocol/SecretKey.h>
#include <boost/filesystem.hpp>

namespace ripple {

struct EphemeralKeys
{
    Seed const seed;
    std::string const manifest;
    PublicKey const validationPublicKey;
};

class ValidatorKeys
{
private:
    KeyType keyType_;
    SecretKey masterSecret_;
    PublicKey validationPublicKey_;
    std::uint32_t sequence_;

public:
    explicit ValidatorKeys (
        KeyType const& keyType);

    ValidatorKeys (
        KeyType const& keyType,
        SecretKey const& masterSecret,
        PublicKey const& validationPublicKey,
        std::uint32_t sequence);

    /** Returns ValidatorKeys constructed from JSON file

        @param keyFile Path to JSON key file

        @throws std::runtime_error if file content is invalid
    */
    static ValidatorKeys make_ValidatorKeys(
        boost::filesystem::path const& keyFile);

    ~ValidatorKeys () = default;

    inline bool
    operator==(ValidatorKeys const& rhs) const
    {
        return sequence_ == rhs.sequence_ && keyType_ == rhs.keyType_ &&
               validationPublicKey_ == rhs.validationPublicKey_;
    }

    /** Return the KeyType. */
    KeyType const& keyType() const
    {
        return keyType_;
    }

    /** Return the master SecretKey. */
    SecretKey const& masterSecret() const
    {
        return masterSecret_;
    }

    /** Return the master PublicKey. */
    PublicKey const& validationPublicKey() const
    {
        return validationPublicKey_;
    }

    /** Return the sequence. */
    std::uint32_t sequence() const
    {
        return sequence_;
    }

    /** Set the sequence. */
    void setSequence (std::uint32_t sequence)
    {
        sequence_ = sequence;
    }

    /** Write keys to JSON file

        @param keyFile Path to file to write

        @note Overwrites existing key file

        @throws std::runtime_error if unable to create parent directory
    */
    void
    writeToFile (boost::filesystem::path const& keyFile) const;

    /** Returns ephemeral keys for current sequence

        @param ephKeyType Key type for ephemeral signing keys
    */
    EphemeralKeys
    createEphemeralKeys (KeyType const& ephKeyType) const;
};

} // ripple
