//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright 2015 Ripple Labs Inc.

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

#include <beast/core/detail/base64.hpp>
#include <ripple/basics/TestSuite.h>
#include <ripple/protocol/HashPrefix.h>
#include <ripple/protocol/Sign.h>
#include <ValidatorKeys.h>

#include <fstream>

namespace ripple {

namespace detail {

/**
   Write a key file dir and remove when done.
 */
class KeyFileGuard
{
protected:
    using path = boost::filesystem::path;
    path subDir_;
    beast::unit_test::suite& test_;

    auto rmDir (path const& toRm)
    {
        if (is_directory (toRm))
            remove_all (toRm);
        else
            test_.log << "Expected " << toRm.string ()
                      << " to be an existing directory." << std::endl;
    };

public:
    KeyFileGuard (beast::unit_test::suite& test,
        std::string const& subDir)
        : subDir_ (subDir)
        , test_ (test)
    {
        using namespace boost::filesystem;

        if (!exists (subDir_))
            create_directory (subDir_);
        else
            // Cannot run the test. Someone created a file or directory
            // where we want to put our directory
            Throw<std::runtime_error> (
                "Cannot create directory: " + subDir_.string ());
    }
    ~KeyFileGuard ()
    {
        try
        {
            using namespace boost::filesystem;

            rmDir (subDir_);
        }
        catch (std::exception& e)
        {
            // if we throw here, just let it die.
            test_.log << "Error in ~KeyFileGuard: " << e.what () << std::endl;
        };
    }
};

}  // detail
namespace tests {

class ValidatorKeys_test : public beast::unit_test::suite
{
private:

    void
    testBadKeyFile (boost::filesystem::path const& keyFile,
        Json::Value const& jv, std::string  const& expectedError)
    {
        std::ofstream o (keyFile.string (), std::ios_base::trunc);
        o << jv.toStyledString();
        o.close();
     
        std::string error;
        try {
            ValidatorKeys::make_ValidatorKeys (keyFile);
        } catch (std::runtime_error& e) {
            error = e.what();
        }
        BEAST_EXPECT(error == expectedError);
    }

    std::array<KeyType, 2> const keyTypes {{
        KeyType::ed25519,
        KeyType::secp256k1 }};

    void
    testMakeValidatorKeys ()
    {
        testcase ("Make Validator Keys");

        using namespace boost::filesystem;

        for (auto const keyType : keyTypes)
        {
            ValidatorKeys const keys (keyType);
            BEAST_EXPECT (keys.keyType == keyType);
            BEAST_EXPECT (keys.sequence == 0);
            auto const validationPublicKey =
                derivePublicKey(keyType, keys.masterSecret);
            BEAST_EXPECT (validationPublicKey == keys.validationPublicKey);

            std::string const subdir = "test_key_file";
            path const keyFile = subdir / "validator_keys.json";
            detail::KeyFileGuard g (*this, subdir);

            keys.writeToFile (keyFile);
            BEAST_EXPECT (exists (keyFile));

            auto const keys2 = ValidatorKeys::make_ValidatorKeys (keyFile);
            BEAST_EXPECT (keys == keys2);
        }
        {
            // Require expected fields
            std::string const subdir = "test_key_file";
            path const keyFile = subdir / "validator_keys.json";
            detail::KeyFileGuard g (*this, subdir);

            auto expectedError =
                "Failed to open key file: " + keyFile.string();
            std::string error;
            try {
                ValidatorKeys::make_ValidatorKeys (keyFile);
            } catch (std::runtime_error& e) {
                error = e.what();
            }
            BEAST_EXPECT(error == expectedError);

            expectedError =
                "Unable to parse json key file: " + keyFile.string();
            std::ofstream o (keyFile.string (), std::ios_base::trunc);
            o << "{{}";
            o.close();

            try {
                ValidatorKeys::make_ValidatorKeys (keyFile);
            } catch (std::runtime_error& e) {
                error = e.what();
            }
            BEAST_EXPECT(error == expectedError);

            Json::Value jv;
            jv["dummy"] = "field";
            expectedError = "Key file '" + keyFile.string() +
                " is missing \"key_type\" field";
            testBadKeyFile (keyFile, jv, expectedError);

            jv["key_type"] = "dummy keytype";
            expectedError = "Key file '" + keyFile.string() +
                " is missing \"master_secret\" field";
            testBadKeyFile (keyFile, jv, expectedError);

            jv["master_secret"] = "dummy secret";
            expectedError = "Key file '" + keyFile.string() +
                " is missing \"sequence\" field";
            testBadKeyFile (keyFile, jv, expectedError);

            jv["sequence"] = "dummy sequence";
            expectedError = "Key file '" + keyFile.string() +
                " contains invalid key type: " +
                jv["key_type"].toStyledString();
            testBadKeyFile (keyFile, jv, expectedError);

            auto const keyType = KeyType::ed25519;
            jv["key_type"] = to_string(keyType);
            expectedError = "Key file '" + keyFile.string() +
                " contains invalid master secret: " +
                jv["master_secret"].toStyledString();
            testBadKeyFile (keyFile, jv, expectedError);

            ValidatorKeys const keys (keyType);
            jv["master_secret"] = 
                toBase58(TOKEN_NODE_PRIVATE, keys.masterSecret);
            expectedError = "Key file '" + keyFile.string() +
                " contains invalid sequence: " +
                jv["sequence"].toStyledString();
            testBadKeyFile (keyFile, jv, expectedError);

            jv["sequence"] = Json::UInt(std::numeric_limits<std::uint32_t>::max ());
            expectedError = "";
            testBadKeyFile (keyFile, jv, expectedError);
        }
    }

    void
    testCreateEphemeralKeys ()
    {
        testcase ("Create Ephemeral Keys");

        for (auto const keyType : keyTypes)
        {
            ValidatorKeys const keys (keyType);

            for (auto const ephKeyType : keyTypes)
            {
                auto const ephKeys = keys.createEphemeralKeys (ephKeyType);

                auto const ssk = generateSecretKey (ephKeyType, ephKeys.seed);
                auto const spk = derivePublicKey(ephKeyType, ssk);

                BEAST_EXPECT (spk == ephKeys.validationPublicKey);

                STObject st (sfGeneric);
                auto const manifest = beast::detail::base64_decode(ephKeys.manifest);
                SerialIter sit (manifest.data (), manifest.size ());
                st.set (sit);

                BEAST_EXPECT (verify (st, HashPrefix::manifest, spk));

                BEAST_EXPECT (verify (
                    st, HashPrefix::manifest, keys.validationPublicKey,
                    sfMasterSignature));
            }
        }
    }

    void
    testWriteToFile ()
    {
        testcase ("Write to File");

        using namespace boost::filesystem;

        auto const keyType = KeyType::ed25519;
        ValidatorKeys keys (keyType);

        {
            std::string const subdir = "test_key_file";
            path const keyFile = subdir / "validator_keys.json";
            detail::KeyFileGuard g (*this, subdir);

            keys.writeToFile (keyFile);
            BEAST_EXPECT(exists (keyFile));

            auto fileKeys = ValidatorKeys::make_ValidatorKeys (keyFile);
            BEAST_EXPECT (keys == fileKeys);

            // Overwrite file with new sequence
            ++keys.sequence;
            keys.writeToFile (keyFile);

            fileKeys = ValidatorKeys::make_ValidatorKeys (keyFile);
            BEAST_EXPECT (keys == fileKeys);
        }
        {
            // Write to key file in current relative directory
            path const keyFile = "test_validator_keys.json";
            if (!exists (keyFile))
            {
                keys.writeToFile (keyFile);
                remove (keyFile.string());
            }
            else
            {
                // Cannot run the test. Someone created a file
                // where we want to put our key file
                Throw<std::runtime_error> (
                    "Cannot create key file: " + keyFile.string ());
            }
        }
        {
            // Create key file directory
            std::string const subdir = "test_key_file";
            path const keyFile =
                subdir / "directories/to/create/validator_keys.json";
            detail::KeyFileGuard g (*this, subdir);

            keys.writeToFile (keyFile);
            BEAST_EXPECT(exists (keyFile));

            auto const fileKeys = ValidatorKeys::make_ValidatorKeys (keyFile);
            BEAST_EXPECT (keys == fileKeys);
        }
        {
            // Fail if file cannot be opened for write
            std::string const subdir = "test_key_file";
            detail::KeyFileGuard g (*this, subdir);

            path const badKeyFile = subdir / ".";
            auto expectedError = "Cannot open key file: " + badKeyFile.string();
            std::string error;
            try {
                keys.writeToFile (badKeyFile);
            } catch (std::runtime_error& e) {
                error = e.what();
            }
            BEAST_EXPECT(error == expectedError);

            // Fail if parent directory is existing file
            path const keyFile = subdir / "validator_keys.json";
            keys.writeToFile (keyFile);
            path const conflictingPath =
                keyFile / "validators_keys.json";
            expectedError = "Cannot create directory: " +
                conflictingPath.parent_path().string();
            try {
                keys.writeToFile (conflictingPath);
            } catch (std::runtime_error& e) {
                error = e.what();
            }
            BEAST_EXPECT(error == expectedError);
        }
    }

public:
    void
    run() override
    {
        testMakeValidatorKeys ();
        testCreateEphemeralKeys ();
        testWriteToFile ();
    }
};

BEAST_DEFINE_TESTSUITE(ValidatorKeys, keys, ripple);

} // tests
} // ripple
