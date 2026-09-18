# How to build Hubble
After checking out the source code, use your favorite IDE to import the
Hubble project (located in AndroidStudioProject).

Then proceed to build project via the way that your IDE allows you to.

Below are instructions that are specific to (and have been tested on) Android
Studio (version 3.5).

1. Launch Android Studio.

2. Import the Hubble project by navigating to `File`->`Open`, and then browsing
to the location you have downloaded this repository to, and choose `Hubble` in
`AndroidStudioProject`.

3. Sync all the settings or project configurations by `File`->`Sync Project with
Gradle Files`.

4. Build the project by `Build`->`Build Bundle(s) / APK(s)`->`Build APK(s)`.

5. An `Event Log` layout should appear. In the logs, it should tell you where
the build result is located. You can also do so by clicking on the `locate` link
within the `Event Log` window layout.

## Building from Command Line
You can also build Hubble directly from the terminal using the Gradle wrapper:

```bash
cd AndroidStudioProject/Hubble
./gradlew assembleDebug
```

The resulting debug APK will be located at:
`AndroidStudioProject/Hubble/app/build/outputs/apk/debug/app-debug.apk`

Alternatively, running `python3 automate_observation.py` automatically rebuilds
Hubble using Gradle if the `--hubble` flag is omitted.

## Upgrading Gradle Wrapper & Distribution Verification

To protect against supply chain tampering and corrupted downloads,
`gradle/wrapper/gradle-wrapper.properties` configures `distributionSha256Sum` to
cryptographically verify the downloaded Gradle distribution archive before
execution.

Once `distributionSha256Sum` is pinned, the Gradle wrapper task strictly requires
the expected checksum when changing versions. Running `./gradlew wrapper --gradle-version <NEW_VERSION>`
without passing the checksum will fail, as Gradle does not auto-fetch release hashes.

### How to Upgrade
From `AndroidStudioProject/Hubble`:

1. **Look up the official SHA-256 checksum:**
   Cross-reference the release checksum published on the official
   [Gradle Release Checksums page](https://gradle.org/release-checksums/)
   (or retrieve `https://services.gradle.org/distributions/gradle-<NEW_VERSION>-bin.zip.sha256`).

2. **Execute the wrapper upgrade task with the checksum:**
   ```bash
   ./gradlew wrapper --gradle-version <NEW_VERSION> --distribution-type bin \
       --gradle-distribution-sha256-sum "<SHA256_HASH>"
   ```

   Alternatively, for quick local upgrades:
   ```bash
   ./gradlew wrapper --gradle-version <NEW_VERSION> --distribution-type bin \
       --gradle-distribution-sha256-sum "$(curl -sSL https://services.gradle.org/distributions/gradle-<NEW_VERSION>-bin.zip.sha256)"
   ```

   > [!NOTE]
   > Piping `curl` directly into `--gradle-distribution-sha256-sum` is a
   > Trust-On-First-Use (TOFU) pattern. In the context of a binary transparency
   > project, manually cross-checking the hash against
   > [https://gradle.org/release-checksums/](https://gradle.org/release-checksums/)
   > is strongly recommended before committing changes.

> [!WARNING]
> If `distributionSha256Sum` is omitted or does not match the downloaded archive,
> the Gradle wrapper will fail to download or execute.
