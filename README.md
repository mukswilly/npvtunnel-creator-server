# NpvTunnel creator server — retired

This repository is archived and is no longer maintained. The addition of
**Share with everyone** files in NpvTunnel removes the need for a separate
creator server to distribute protected configurations to an audience.

## Share configurations directly

1. Prepare a configuration or subscription in NpvTunnel and choose Export.
2. Keep it locked and select **Anyone with the app** to share with everyone.
3. Export the `.npvs` file and distribute it through Telegram, another messaging
   app, or ordinary file hosting.
4. Recipients open the file with a compatible version of NpvTunnel.

For narrower distribution, export for specific recipient public keys or use a
passphrase. Sealing and signing happen in the app; a distribution host only
needs to deliver the exported file unchanged.

An everyone file can be opened by any compatible NpvTunnel installation and
can be forwarded by its recipients. File protection does not prevent extraction
from a compromised running device. Deleting a hosted file does not revoke
copies already downloaded or credentials at the VPN endpoint.

## Existing installations

New NpvTunnel versions retire creator-server registration, share-link redemption
and connection-time issuance. Existing server links and issuer-pointer files
must be replaced with configuration or subscription files exported from the app.
They cannot be converted by renaming the file or changing its download URL.

Before retiring an existing deployment, keep a protected backup of its state,
distribute replacement exports and stop the creator-server service when its
recipients have moved. Archiving this repository does not stop running servers.
Do not create new deployments: this project will receive no further maintenance
or security updates.

The source and previous releases remain available as historical reference.

## License

[Apache-2.0](LICENSE) — see also [NOTICE](NOTICE).
