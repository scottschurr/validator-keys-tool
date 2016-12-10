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

#include <beast/unit_test/dstream.hpp>
#include <boost/format.hpp>
#include <boost/program_options.hpp>
#include <ripple/beast/unit_test.h>
#include <ValidatorKeys.h>

namespace po = boost::program_options;

void printHelp (const po::options_description& desc)
{

    static std::string const name = "ripple_validator_keys";

    std::cerr
        << name << " [options] <command> <params>\n"
        << desc << std::endl
        << "Commands: \n"
           "     create_master_keys\n"
           "     create_signing_keys\n"
           "     revoke_master_keys\n";
}

static int runUnitTests ()
{
    using namespace beast::unit_test;
    beast::unit_test::dstream dout{std::cout};
    reporter r{dout};
    bool const anyFailed = r.run_each(global_suites());
    if(anyFailed)
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}

void createKeyFile (const boost::filesystem::path& keyFile)
{
    using namespace boost::filesystem;
    using namespace ripple;

    if (exists (keyFile))
    {
        throw std::runtime_error (
            "Refusing to overwrite existing key file: " +
                keyFile.string ());
    }

    ValidatorKeys keys (KeyType::ed25519);
    keys.writeToFile (keyFile);

    std::cout << "Master validator keys stored in " <<
        keyFile.string() << std::endl;
}

void signManifest (const boost::filesystem::path& keyFile,
    boost::optional<std::uint32_t> sequence)
{
    using namespace ripple;

    auto keys = ValidatorKeys::make_ValidatorKeys (keyFile);

    if (sequence)
    {
        if (*sequence <= keys.sequence)
            throw std::runtime_error (boost::str (boost::format (
                "Sequence should exceed current sequence (%u).") %
                keys.sequence));

        keys.sequence = *sequence;
    }
    else
    {
        if (keys.sequence == std::numeric_limits<std::uint32_t>::max ())
            throw std::runtime_error (
                "Sequence is already at maximum value. Master keys have been revoked.");
        ++keys.sequence;
    }

    if (keys.sequence == std::numeric_limits<std::uint32_t>::max ())
        std::cout << "WARNING: This will revoke your master keys!\n\n";

    auto const ephemeralKeys = keys.createEphemeralKeys (KeyType::secp256k1);

    std::cout << "Update rippled.cfg file with these values:\n\n";
    std::cout << "[validation_seed]\n" << toBase58 (ephemeralKeys.seed) << "\n";
    std::cout << "# validation_public_key: " <<
        toBase58 (TOKEN_NODE_PUBLIC, ephemeralKeys.validationPublicKey) << "\n";
    std::cout << "# sequence number: " << keys.sequence << "\n\n";
    std::cout << "[validation_manifest]\n";

    auto const len = 72;
    for (auto i = 0; i < ephemeralKeys.manifest.size(); i += len)
        std::cout << ephemeralKeys.manifest.substr(i, len) << std::endl;

    std::cout << std::endl;

    // Overwrite key file with updated sequence
    keys.writeToFile (keyFile);
}

int runCommand (const std::vector<std::string>& args,
    const boost::filesystem::path& keyFile)
{
    if (args.empty())
        throw std::runtime_error ("no command specified");

    using namespace ripple;

    if (args.size() != 1)
        throw std::runtime_error (
            "Syntax effor: Wrong number of parameters");
    
    if (args[0] == "create_master_keys")
        createKeyFile (keyFile);
    else if (args[0] == "create_signing_keys")
        signManifest (keyFile, boost::none /* sequence */);
    else if (args[0] == "revoke_master_keys")
        signManifest (keyFile, std::numeric_limits<std::uint32_t>::max ());
    else
        throw std::runtime_error ("Unknown command");

    return 0;
}

static
std::string
getEnvVar (char const* name)
{
    std::string value;

    auto const v = getenv (name);

    if (v != nullptr)
        value = v;

    return value;
}

int main (int argc, char** argv)
{
#if defined(__GNUC__) && !defined(__clang__)
    auto constexpr gccver = (__GNUC__ * 100 * 100) +
                            (__GNUC_MINOR__ * 100) +
                            __GNUC_PATCHLEVEL__;

    static_assert (gccver >= 50100,
        "GCC version 5.1.0 or later is required to compile rippled.");
#endif

    static_assert (BOOST_VERSION >= 105700,
        "Boost version 1.57 or later is required to compile rippled");

    po::variables_map vm;

    // Set up option parsing.
    //
    po::options_description desc ("General Options");
    desc.add_options ()
    ("help,h", "Display this message.")
    ("keyfile", po::value<std::string> (), "Specify the master key file.")
    ("unittest,u", po::value <std::string> ()->implicit_value (""),
        "Perform unit tests.")
    ("parameters", po::value< std::vector<std::string> > (),
        "Specify comma separated parameters.")
    ;

    // Interpret positional arguments as --parameters.
    po::positional_options_description p;
    p.add ("parameters", -1);

    // Parse options, if no error.
    try
    {
        po::store (po::command_line_parser (argc, argv)
            .options (desc)               // Parse options.
            .positional (p)               // Remainder as --parameters.
            .run (),
            vm);
        po::notify (vm);                  // Invoke option notify functions.
    }
    catch (std::exception const&)
    {
        std::cerr << "manifest_tool: Incorrect command line syntax." << std::endl;
        std::cerr << "Use '--help' for a list of options." << std::endl;
        return 1;
    }

    // Run the unit tests if requested.
    // The unit tests will exit the application with an appropriate return code.
    if (vm.count ("unittest"))
        return runUnitTests();

    if (vm.count ("help") || ! vm.count ("parameters"))
    {
        printHelp (desc);
        return 0;
    }

    const std::string DEFAULT_KEY_FILE =
        getEnvVar ("HOME") + "/.ripple/validator-keys.json";

    try
    {
        using namespace boost::filesystem;
        path keyFile = vm.count ("keyfile") ?
            vm["keyfile"].as<std::string> () :
            DEFAULT_KEY_FILE;

        return runCommand (
            vm["parameters"].as<std::vector<std::string>>(),
            keyFile);
    }
    catch(std::exception const& e)
    {
        std::cerr << e.what() << "\n";
    }
}
