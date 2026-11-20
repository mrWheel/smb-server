<!--
 fileVersion: [1] 19-11-2026 - 13:25

 PUBLISHING.md - how to publish a component to the ESP Component Registry.
 Copyright (C) 2026 Willem Aandewiel (mrWheel)
 SPDX-License-Identifier: GPL-3.0-or-later
-->

# Publish smb_server to the ESP Component Registry

The repository and local ESP-IDF app are named `smb_server`. The registry
component is named `smb_server`. The component directory holds its
manifest, CMake registration, public headers, C sources and registry README.
The root app is for local development in VS Code.

## Prepare the first release

- Complete the implementation and run the tests in the project prompt.
- Choose a license you can grant for the source, put its text in
  `components/smb_server/LICENSE` and set the matching SPDX identifier in
  `idf_component.yml`. Use `GPL-3.0-or-later`.
- Set the first release version in the manifest, update the README with actual
  usage and tested support, and add the repository URL when it exists.
- Use the namespace assigned to your publishing account. The examples below
  use `your_namespace` as a placeholder.
- To ship a standalone example through the Registry, add it under
  `components/smb_server/examples/` with its own project CMake file and
  a main-component manifest referencing the actual published component.
  Keep the root example for local development.

## Package locally

Open an ESP-IDF terminal in the repository root, then run:

```sh
cd components/smb_server
compote component pack --name smb_server
```

Inspect the generated archive in `dist/` and build a separate ESP-IDF app
to verify the public dependency and include files before releasing.

## Upload and install

After signing in to the Registry and configuring a publishing profile,
run this from the same component directory:

```sh
compote component upload --name smb_server --namespace mrWheel
```

To install the released component from another ESP-IDF project, run:

```sh
idf.py add-dependency "mrWheel/smb_server^0.3.0"
```

Use the actual namespace and release version. Keep Registry credentials
outside the project and its archives.

[Espressif publishing documentation](https://docs.espressif.com/projects/idf-component-manager/en/latest/publish/how_to_upload_component.html)