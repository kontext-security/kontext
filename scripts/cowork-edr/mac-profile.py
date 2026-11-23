#!/usr/bin/env python3
"""Create the system configuration profile for the internal Mac Cowork test."""
import argparse
from pathlib import Path
import plistlib
import uuid

PACKAGE = '/Library/Application Support/KontextCoworkEDR/kontext-cowork-internal.tar.gz'
VENDOR = '06a9bcc2a0ed47cb8029fe34a059a5e8'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    profile = dict(PayloadType='Configuration', PayloadVersion=1,
                   PayloadIdentifier='security.kontext.cowork-edr.internal',
                   PayloadUUID=str(uuid.uuid4()).upper(), PayloadScope='System',
                   PayloadDisplayName='Kontext Cowork EDR — internal test',
                   PayloadDescription='Installs the signed internal observe-only sensor in local Cowork VMs. Remove this profile to disable future installation; remove the sensor separately inside the VM.',
                   PayloadOrganization='Kontext', PayloadRemovalDisallowed=False,
                   PayloadContent=[dict(PayloadType='com.apple.ManagedClient.preferences', PayloadVersion=1,
                                        PayloadIdentifier='security.kontext.cowork-edr.internal.preferences',
                                        PayloadUUID=str(uuid.uuid4()).upper(),
                                        PayloadContent={'com.anthropic.claudefordesktop': {'Forced': [{'mcx_preference_settings': {
                                            'coworkEDRIntegration': PACKAGE,
                                            'coworkEDRIntegrationVendor': VENDOR,
                                        }}]}})])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(plistlib.dumps(profile))
    print(args.output.resolve())

if __name__ == '__main__':
    main()
