# Manifest Tool Guide

This guide explains how to setup a validator so the key pairs used to sign and
verify validations may safely change. This procedure does not require manual
reconfiguration of servers that trust this validator.

Validators use two types of key pairs: *master keys* and *ephemeral
keys*. Ephemeral keys are used to sign and verify validations. Master keys are
used to sign and verify manifests that change ephemeral keys. The master secret
key should be tightly controlled. The ephemeral secret key needs to be present
in the config file.

## Validator Keys

When first setting up a validator, use the `validator-keys` tool to generate a
master key pair:

```
  $ validator-keys create_master_keys
```

Sample output:
```
  Master validator keys stored in /home/ubuntu/.ripple/validator-keys.json
```

Sample key file:
```
  {
     "key_type" : "ed25519",
     "master_secret" : "paUvjG1z51cpSxL3Wc9DaGTEogYk4AEesLJJaawBcVQjejxGFcb",
     "sequence" : 4294967295,
     "validation_public_key" : "nHUtNnLVx7odrz5dnfb2xp1gbEeJPbzJWfdicSkGyVw1eE5GpjQr"
  }
```

The `validation_public_key` is the master public key. Any other rippled trusting
the validator needs to add the master public key to its config. Only add keys
received from trusted sources.

The `master_secret` is the corresponding master secret key. **DO NOT SHARE THIS
KEY**. The master secret key will be used to sign manifests that change
ephemeral validation keys. Put the master secret key in a secure but recoverable
location.

## Validation Keys

When first setting up a validator, or when changing the ephemeral keys, use the
`validator-keys` tool to create a new ephemeral key pair:

```
  $ validator-keys create_signing_keys
```

Sample output:

```
  Update rippled.cfg file with these values:

  [validation_seed]
  shDaxeLXa4EKNt65ZxXUZBRaF2aE2
  # validation_public_key: n9LSS563nUSjgKo49CmMfnHM6tBerU1MLvL7o1GMwvTwXi5UmpWT
  # sequence number: 1

  [validation_manifest]
  JAAAAAFxIe3Jmw2YP06xDcJ/9k7gBjByXwoduRwMZcXH578DGNk1m3MhAvmlIKVGDqdyCU/6
  HIubKFtFhVQefrRr7SLhN48BP5nMdkcwRQIhAI4fn64/8XgJeuVR1Eu6lu50XBC2CcPPAUSf
  Ta7KizeYAiAwpjaahPWW9muj2FA/mAB/zJbrMKL3c462r97JTvi1FHASQDNj/jMpCrZl77r4
  zmeE8pY9cZC5aS+3Jk6y2wvaSG7Szq7Mfc8Hcpm7gBmSVbbQ+rl+DGBgaVnkkDscXvdOpQ4=

```

Add the `[validation_seed]` and `[validation_manifest]` values to this
validator's config.

The manifest is a signed message used to inform other servers of this
validator's ephemeral public key. A manifest contains a sequence number, the
master public key, and the new ephemeral public key, and it is signed with both
the ephemeral and master secret keys.
The sequence number should be higher than the previous sequence number (if it
is not, the manifest will be ignored). The `validator-keys` tool will
automatically increment the sequence number.

## Revoking a key

If a master key is compromised, the key may be revoked permanently. To revoke
the master key, use the `validator-keys` tool to sign a manifest with the
highest possible sequence number (4294967295):

```
  $ validator-keys revoke_master_keys
```
