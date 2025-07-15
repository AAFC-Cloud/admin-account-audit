<div align="center">
    <h1>🛡️Admin Account Audit🛡️</h1>
    <img src="logo.png" width="230">
    <br/>

[Voir la version française](./README.fr_ca.md)
</div>

## Description

**Admin Account Audit** is a Rust CLI tool to audit Azure role assignments and group ownerships, focusing on identifying non-admin users who have been granted elevated permissions or own security groups. The tool fetches all role assignments, users, and groups, and outputs a JSON report listing non-admin users with direct or group-based role assignments, as well as non-admin group owners.

- Designed for Azure environments
- Outputs results as a JSON file
- Helps organizations identify potential privilege escalations

## Usage

```sh
admin_account_audit <output_path> [--overwrite-existing]
```

- `<output_path>`: Path to write the JSON results.
- `--overwrite-existing`: Overwrite the output file if it already exists.

## Example

```sh
admin_account_audit output.json --overwrite-existing
```

## Copyright

Copyright belongs to © His Majesty the King in Right of Canada, as represented by the Minister of Agriculture and Agri-Food, 2024.
