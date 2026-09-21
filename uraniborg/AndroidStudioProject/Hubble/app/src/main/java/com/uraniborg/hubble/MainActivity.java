//Copyright 2019 Uraniborg authors.
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.

package com.uraniborg.hubble;

import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

import android.annotation.SuppressLint;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Base64;
import android.util.Log;

import java.util.TreeMap;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;

public class MainActivity extends AppCompatActivity {
  final String TAG = "HUBBLE";

  // semantically tie the notion of app version to versionName, which we will update for every
  // major and minor release. Unfortunately, for now, we have to independently and separately
  // update these values everytime we do any revisions because BuildConfig is phased out.
  private final String VERSION = "2.2.0";

  // We're changing to TreeMap so that package names are sorted. This would ease output comparison.
  private TreeMap<String, PackageMetadata> mAllPackages;
  private TreeMap<String, PackageMetadata> mPreinstalledPackages;
  private HashMap<String, byte[]> mAllCertificates;
  private HashMap<String, BinaryInfo> mAllBinaries;
  private HashMap<String, LibraryInfo> mAllLibraries;
  private HardwareInfo mHardwareInfo;
  private BuildInfo mBuildInfo;
  private PackageManager mPackageManager;
  private DevicePropertiesInfo mDeviceProps;
  private Executor mExecutor;

  private static String HEADER_FMT = "{ \"version\": \"%s\", \"%s\": %d,\n\"%s\": [\n";
  private static String FOOTER_STR = "\n]\n}";


  private boolean initialize() {
    final String tag = TAG + "-INIT";
    mAllPackages = new TreeMap<>();
    mPreinstalledPackages = new TreeMap<>();
    mAllCertificates = new HashMap<>();
    mAllBinaries = new HashMap<>();
    mAllLibraries = new HashMap<>();
    mHardwareInfo = new HardwareInfo();
    mBuildInfo = new BuildInfo();
    mDeviceProps = new DevicePropertiesInfo();
    mExecutor = Executors.newSingleThreadExecutor();

    mPackageManager = getPackageManager();
    if (mPackageManager == null) {
      Log.e(tag, "Failed to obtain package manager");
      return false;
    }
    return true;
  }

  /*
   * other constants not available/visible from SDK
   */
  // this allows us to see installed packages in the 'disabled' or 'hidden' state.
  final int MATCH_HIDDEN_UNTIL_INSTALLED_COMPONENTS = 0x20000000;
  // this allows us to get APEX packages when calling getInstalledPackages
  final int MATCH_APEX = 0x40000000;

  @SuppressWarnings("deprecation")
  private void getInstalledPackagesInformation() {
    String tag = TAG + "-PKGS";

    int flags = PackageManager.GET_ACTIVITIES |
                PackageManager.GET_GIDS |
                PackageManager.GET_INTENT_FILTERS |
                PackageManager.GET_META_DATA |
                PackageManager.GET_PERMISSIONS |
                PackageManager.GET_PROVIDERS |
                PackageManager.GET_RECEIVERS |
                PackageManager.GET_SERVICES |
                PackageManager.GET_SHARED_LIBRARY_FILES |
                MATCH_APEX;

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      flags |= PackageManager.GET_SIGNING_CERTIFICATES | MATCH_HIDDEN_UNTIL_INSTALLED_COMPONENTS;
    } else {
      flags |= PackageManager.GET_SIGNATURES;
    }

    @SuppressLint("WrongConstant") List<PackageInfo> installedPackagesAndApexes = mPackageManager.
        getInstalledPackages(flags);
    for (PackageInfo pkg : installedPackagesAndApexes) {
      PackageMetadata pkgMetadata = PackageMetadata.parse(this, pkg, mPackageManager);
      mAllPackages.put(pkg.packageName, pkgMetadata);
      if (pkgMetadata.isPreinstalled) {
        mPreinstalledPackages.put(pkg.packageName, pkgMetadata);
      }
    }
    Log.d(tag, String.format("There are %d packages (including APEX)", mAllPackages.size()));
  }

  // The Android framework ("platform") package. Its signing identity is what defines a
  // "platform-signed" package and gates access to the system shared UIDs.
  static final String PLATFORM_PACKAGE_NAME = "android";

  /**
   * Returns {@link PackageManager#checkSignatures(String, String)}'s verdict comparing
   * {@code pkgName} against the platform ({@code android}) package.
   *
   * <p>Recorded verbatim as an observation. Per AOSP
   * {@code ComputerEngine#checkSignaturesInternal} and
   * {@code PackageManagerServiceUtils#compareSignatures}, the algorithm is:
   *
   * <ol>
   *   <li>Compare the two packages' <em>current</em> signer sets for exact set equality.</li>
   *   <li>If that fails and either side has a signing lineage, retry using only the
   *       <em>oldest</em> ancestor of each ({@code getPastSigningCertificates()[0]}) - an
   *       explicit backwards-compatibility path for callers predating key rotation.</li>
   * </ol>
   *
   * <p>IMPORTANT: this is <em>not</em> a capability-aware trust decision, and it is not a
   * sound oracle for "is this platform-signed?". It never consults the per-ancestor
   * {@code SigningDetails.CertCapabilities} flags ({@code PERMISSION},
   * {@code SHARED_USER_ID}); those are evaluated elsewhere in the framework (shared-UID join
   * logic and the permission subsystem) and are not reachable from any public API. Two known
   * divergences follow directly from the algorithm above:
   *
   * <ul>
   *   <li>A package that has rotated <em>away</em> from the platform key still reports
   *       {@code MATCH}, because the oldest-ancestor retry compares the retired platform
   *       certificate.</li>
   *   <li>A package co-signed by the platform key <em>plus</em> another key reports
   *       {@code NO_MATCH}, because step 1 requires exact set equality.</li>
   * </ul>
   *
   * <p>Consumers should therefore treat this as descriptive metadata (what
   * {@code PackageManager} itself would report to an app), not as the basis for platform
   * trust. See {@code HubbleParser.is_platform_signed()}.
   *
   * @param pkgName the package to compare against the platform package.
   * @return one of {@code MATCH}, {@code NO_MATCH}, {@code NEITHER_SIGNED},
   *     {@code FIRST_NOT_SIGNED}, {@code SECOND_NOT_SIGNED}, {@code UNKNOWN_PACKAGE}, or
   *     {@code UNKNOWN} if the query itself failed.
   */
  @NotNull
  private String getPlatformSignatureMatch(@NotNull String pkgName) {
    final String tag = TAG + "-CERT";
    try {
      int result = mPackageManager.checkSignatures(pkgName, PLATFORM_PACKAGE_NAME);
      switch (result) {
        case PackageManager.SIGNATURE_MATCH:
          return "MATCH";
        case PackageManager.SIGNATURE_NO_MATCH:
          return "NO_MATCH";
        case PackageManager.SIGNATURE_NEITHER_SIGNED:
          return "NEITHER_SIGNED";
        case PackageManager.SIGNATURE_FIRST_NOT_SIGNED:
          return "FIRST_NOT_SIGNED";
        case PackageManager.SIGNATURE_SECOND_NOT_SIGNED:
          return "SECOND_NOT_SIGNED";
        case PackageManager.SIGNATURE_UNKNOWN_PACKAGE:
          // Expected for entries (e.g. some APEXes) that PackageManager does not track as a
          // signature-comparable package. Consumers should fall back to digest comparison.
          return "UNKNOWN_PACKAGE";
        default:
          Log.e(tag, String.format("Unexpected checkSignatures result %d for package: %s", result,
              pkgName));
          return "UNKNOWN";
      }
    } catch (RuntimeException e) {
      Log.e(tag, String.format("Failed to checkSignatures against platform for package %s: %s",
          pkgName, e.getMessage()));
      return "UNKNOWN";
    }
  }

  @NotNull
  private JSONArray extractAndRegisterCertificates(@NotNull String pkgName,
                                                   @Nullable Signature[] signatures) {
    final String tag = TAG + "-CERT";
    JSONArray digests = new JSONArray();
    if (signatures == null) {
      return digests;
    }
    for (Signature signature : signatures) {
      if (signature == null) {
        continue;
      }
      String encodedSignatureDigest = Utilities.computeSHA256DigestOfCertificate(signature);
      if (encodedSignatureDigest == null) {
        Log.e(tag, String.format("Failed to compute hash for cert of package: %s", pkgName));
        continue;
      }
      if (!mAllCertificates.containsKey(encodedSignatureDigest)) {
        mAllCertificates.put(encodedSignatureDigest, signature.toByteArray());
      }
      digests.put(encodedSignatureDigest);
    }
    return digests;
  }

  @SuppressWarnings("deprecation")
  private void getAllCertificates() {
    final String tag = TAG + "-CERT";
    for (String pkgName : mAllPackages.keySet()) {
      PackageMetadata pkgMetadata = mAllPackages.get(pkgName);
      if (pkgMetadata == null) {
        Log.e(tag, String.format("Unexpected error getting pkg metadata for %s", pkgName));
        continue;
      }
      PackageInfo pkgInfo = pkgMetadata.ref;
      JSONObject signingInfoJson = new JSONObject();
      // Recorded verbatim as an observation; see getPlatformSignatureMatch().
      String platformSignatureMatch = getPlatformSignatureMatch(pkgName);

      if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
        Signature[] signatures = pkgInfo.signatures;
        if (signatures == null) {
          Log.e(tag, String.format("Failed to grab signature for package: %s", pkgName));
          continue;
        }
        // Count the declared signers BEFORE computing digests: a single
        // computeSHA256DigestOfCertificate() failure drops an entry, and must not silently
        // demote a co-signed APK to a single-signer one.
        int declaredSignerCount = 0;
        for (Signature signature : signatures) {
          if (signature != null) {
            declaredSignerCount++;
          }
        }
        JSONArray activeSigners = extractAndRegisterCertificates(pkgName, signatures);
        pkgMetadata.certIds = activeSigners;
        try {
          signingInfoJson.put("hasMultipleSigners", declaredSignerCount > 1);
          // NOTE: pre-P PackageManager exposes no v3 lineage API at all, so rotation is
          // UNOBSERVABLE here rather than known to be absent. Emit null (not false) and no
          // lineage, so consumers classify these as UNKNOWN instead of asserting "never
          // rotated". See docs/hubble_results.md.
          signingInfoJson.put("hasPastSigningCertificates", JSONObject.NULL);
          signingInfoJson.put("apkContentsSigners", activeSigners);
          signingInfoJson.put("signingCertificateLineage", new JSONArray());
          signingInfoJson.put("platformSignatureMatch", platformSignatureMatch);
          pkgMetadata.signingInfo = signingInfoJson;
        } catch (JSONException e) {
          Log.e(tag, String.format("Failed to build signingInfo JSON for package %s: %s",
              pkgName, e.getMessage()));
        }
      } else {
        SigningInfo signingInfo = pkgInfo.signingInfo;
        if (signingInfo == null) {
          Log.e(tag, String.format("Failed to grab signingInfo for package: %s", pkgName));
          continue;
        }
        boolean hasMultipleSigners = signingInfo.hasMultipleSigners();
        boolean hasPastSigningCertificates = signingInfo.hasPastSigningCertificates();
        Signature[] activeSignatures = signingInfo.getApkContentsSigners();
        Signature[] lineageSignatures =
            hasMultipleSigners ? null : signingInfo.getSigningCertificateHistory();

        if (activeSignatures == null && lineageSignatures == null) {
          Log.e(tag, String.format("Failed to grab signature for package: %s", pkgName));
          continue;
        }

        JSONArray apkContentsSigners = extractAndRegisterCertificates(pkgName, activeSignatures);
        JSONArray signingCertificateLineage =
            extractAndRegisterCertificates(pkgName, lineageSignatures);

        if (hasMultipleSigners) {
          pkgMetadata.certIds = apkContentsSigners;
        } else {
          pkgMetadata.certIds = (signingCertificateLineage.length() > 0)
              ? signingCertificateLineage : apkContentsSigners;
        }

        try {
          signingInfoJson.put("hasMultipleSigners", hasMultipleSigners);
          signingInfoJson.put("hasPastSigningCertificates", hasPastSigningCertificates);
          signingInfoJson.put("apkContentsSigners", apkContentsSigners);
          signingInfoJson.put("signingCertificateLineage", signingCertificateLineage);
          signingInfoJson.put("platformSignatureMatch", platformSignatureMatch);
          pkgMetadata.signingInfo = signingInfoJson;
        } catch (JSONException e) {
          Log.e(tag, String.format("Failed to build signingInfo JSON for package %s: %s",
              pkgName, e.getMessage()));
        }
      }
    }
  }

  private void getAllBinaries() {
    final String tag = TAG + "-BININFO";

    // first get the system path
    String binPaths = System.getenv("PATH");
    if (binPaths == null) {
      Log.e(tag, "Error getting system PATH environment value.");
      return;
    }
    Log.d(tag, String.format("binPaths: %s", binPaths));

    String[] paths = binPaths.split(":");
    List<File> accessibleBins = new ArrayList<>();
    for (String path : paths) {
      accessibleBins.addAll(Utilities.getAllFilesInDirectory(path, false));
    }

    for (File binFile : accessibleBins) {
      BinaryInfo binaryInfo = new BinaryInfo();
      binaryInfo.name = binFile.getName();
      binaryInfo.installPath = binFile.getParent();
      binaryInfo.hash = Utilities.computeSHA256DigestOfFile(this, binFile.getAbsolutePath());
      binaryInfo.fileSizeInBytes = binFile.length();

      if (binaryInfo.hash != null ) {
        mAllBinaries.put(binaryInfo.hash, binaryInfo);
      }
    }
    Log.d(tag, String.format("There are %d accessible binaries.", mAllBinaries.size()));
  }

  private void getAllLibraries() {
    final String tag = TAG + "-LIBINFO";

    for (String libDir : LibraryInfo.LIB_PATHS) {
      for (File libFile : Utilities.getAllFilesInDirectory(libDir, false)) {
        LibraryInfo libraryInfo = new LibraryInfo();
        libraryInfo.name = libFile.getName();
        libraryInfo.installPath = libFile.getParent();

        if (libraryInfo.installPath.contains("64")) {
          libraryInfo.bits = 64;
        } else {
          libraryInfo.bits = 32;
        }

        libraryInfo.hash = Utilities.computeSHA256DigestOfFile(this, libFile.getAbsolutePath());

        if (libraryInfo.hash != null) {
          mAllLibraries.put(libraryInfo.hash, libraryInfo);
        }

        libraryInfo.fileSizeInBytes = libFile.length();
      }
    }

    Log.d(tag, String.format("There are %d libraries found.", mAllLibraries.size()));

  }

  private void getHardwareInformation() {
    final String tag = TAG + "-HWINFO";
    mHardwareInfo.brand = Build.BRAND;
    mHardwareInfo.boardName = Build.BOARD;
    mHardwareInfo.deviceName = Build.DEVICE;
    mHardwareInfo.oem = Build.MANUFACTURER;
    mHardwareInfo.modelName = Build.MODEL;
    mHardwareInfo.productName = Build.PRODUCT;
    mHardwareInfo.hardwareName = Build.HARDWARE;
    mHardwareInfo.hash = mHardwareInfo.computeHash();

    //getSystemService(Context.PERSISTENT_DATA_BLOCK_SERVICE);
  }

  @Nullable
  private String getKernelVersion() {
    // there are many ways to get the kernel version, but not all can succeed on every build
    String cmd = "uname -a";
    ExecutionResult result = Utilities.executeInShell(cmd);
    if (!result.exceptionTriggered && result.exitCode == 0 && !result.stdOutStr.trim().isEmpty()) {
      return result.stdOutStr.trim();
    }

    // if we reach here, means the first method didn't give us satisfactory answers.
    cmd = "cat /proc/version";
    result = Utilities.executeInShell(cmd);
    if (!result.exceptionTriggered && result.exitCode == 0 && !result.stdOutStr.trim().isEmpty()) {
      return result.stdOutStr.trim();
    }

    // if we reach here, we're out of ideas!! :(
    return null;
  }

  private void getBuildInformation() {
    final String tag = TAG + "-BUILDINFO";
    mBuildInfo.apiLevel = Build.VERSION.SDK_INT;
    mBuildInfo.fingerprint = Build.FINGERPRINT;
    mBuildInfo.securityPatchLevel = Build.VERSION.SECURITY_PATCH;
    mBuildInfo.bootloaderVersion = Build.BOOTLOADER;
    mBuildInfo.radioVersion = Build.getRadioVersion();
    mBuildInfo.locale = Locale.getDefault().getDisplayName();

    mBuildInfo.kernelVersion = getKernelVersion();
    if (mBuildInfo.kernelVersion == null || mBuildInfo.kernelVersion.isEmpty()) {
      mBuildInfo.kernelVersion = Build.UNKNOWN;
    }
  }

  private void getDeviceProperties() {
    final String tag = TAG + "-GETPROP";
    String cmd = "getprop";
    ExecutionResult result = Utilities.executeInShell(cmd);
    if (!result.exceptionTriggered && result.exitCode != null && result.exitCode.intValue() == 0 &&
        result.stdOutStr != null) {
      mDeviceProps.encodedDevProps = Base64.encodeToString(result.stdOutStr.getBytes(),
          Base64.NO_WRAP);
    }
  }


  private void writePackagesToFile() {
    final String tag = TAG + "-W_PKG";
    final String PKG_FILENAME = "packages.txt";
    final String PREINSTALL_FILENAME = "preinstalled_packages.txt";

    String header = String.format(HEADER_FMT, VERSION, "totalPackages", mAllPackages.size(),
        "packages");
    Utilities.writeToFile(this, PKG_FILENAME, header, false);
    int i = 0;
    String[] skip = new String[] {"ref"};
    for (PackageMetadata pkgMetadata : mAllPackages.values()) {
      Utilities.writeToFile(this, PKG_FILENAME, pkgMetadata.getJSONString(skip), true);
      if (i == mAllPackages.size() - 1) {
        continue;
      }
      Utilities.writeToFile(this, PKG_FILENAME, ",\n", true);
      i++;
    }
    Utilities.writeToFile(this, PKG_FILENAME, FOOTER_STR, true);

    // write preload info to preload file.
    header = String.format(HEADER_FMT, VERSION, "totalPreinstalledPackages",
            mPreinstalledPackages.size(), "preinstalledPackages");
    Utilities.writeToFile(this, PREINSTALL_FILENAME, header, false);
    int j = 0;
    for (PackageMetadata preinstalledMetadata : mPreinstalledPackages.values()) {
      Utilities.writeToFile(this, PREINSTALL_FILENAME,
              preinstalledMetadata.getJSONString(skip), true);
      if (j == mPreinstalledPackages.size() - 1) {
        continue;
      }
      Utilities.writeToFile(this, PREINSTALL_FILENAME, ",\n", true);
      j++;
    }
    Utilities.writeToFile(this, PREINSTALL_FILENAME, FOOTER_STR, true);
  }

  private void writeCertsToFile() {
    final String tag = TAG + "-W_CRT";
    final String CERT_FILENAME = "certificates.txt";

    String header = String.format(HEADER_FMT, VERSION, "totalCerts", mAllCertificates.size(),
        "certs");
    Utilities.writeToFile(this, CERT_FILENAME, header, false);
    int i = 0;
    for (String certHash : mAllCertificates.keySet()) {
      JSONObject cert = new JSONObject();
      try {
        cert.put("hash", certHash);
        cert.put("encodedCert", Base64.encodeToString(mAllCertificates.get(certHash),
            Base64.NO_WRAP));
        Utilities.writeToFile(this, CERT_FILENAME, cert.toString(2), true);
      } catch (JSONException e) {
        Log.e(tag, String.format("Facing errors dealing with JSON: %s", e.getMessage()));
      }
      if (i == mAllCertificates.size() - 1) {
        continue;
      }
      Utilities.writeToFile(this, CERT_FILENAME, ",\n", true);
      i++;

    }
    Utilities.writeToFile(this, CERT_FILENAME, FOOTER_STR, true);
  }

  private void writeBinsToFile() {
    final String tag = TAG + "-W_BIN";
    final String BIN_FILENAME = "binaries.txt";

    String header = String.format(HEADER_FMT, this.VERSION, "totalBins", mAllBinaries.size(),
        "bins");
    Utilities.writeToFile(this, BIN_FILENAME, header, false);
    int i = 0;
    for (String binHash : mAllBinaries.keySet()) {
      BinaryInfo binInfo = mAllBinaries.get(binHash);
      Utilities.writeToFile(this, BIN_FILENAME, binInfo.getJSONString(null), true);

      if (i == mAllBinaries.size() - 1) {
        continue;
      }
      Utilities.writeToFile(this, BIN_FILENAME, ",\n", true);
      i++;
    }
    Utilities.writeToFile(this, BIN_FILENAME, FOOTER_STR, true);
  }

  private void writeLibsToFile() {
    final String tag = TAG + "-W_LIB";
    final String LIB_FILENAME = "libraries.txt";

    String header = String.format(HEADER_FMT, VERSION, "totalLibs", mAllLibraries.size(), "libs");
    Utilities.writeToFile(this, LIB_FILENAME, header, false);
    int i = 0;
    for (String libHash : mAllLibraries.keySet()) {
      LibraryInfo libInfo = mAllLibraries.get(libHash);
      Utilities.writeToFile(this, LIB_FILENAME, libInfo.getJSONString(null), true);

      if (i == mAllLibraries.size() - 1) {
        continue;
      }
      Utilities.writeToFile(this, LIB_FILENAME, ",\n", true);
      i++;
    }
    Utilities.writeToFile(this, LIB_FILENAME, FOOTER_STR, true);
  }

  private void writeHardwareToFile() {
    final String tag = TAG + "-W_HW";
    final String HW_FILENAME = "hardware.txt";

    writeSingleInfoToFile(HW_FILENAME, "totalHardware", "hwInfo",
        mHardwareInfo, null);
  }

  private void writeBuildToFile() {
    final String tag = TAG + "-W_BI";
    final String BUILD_FILENAME = "build.txt";

    writeSingleInfoToFile(BUILD_FILENAME, "totalBuild", "buildInfo",
        mBuildInfo, null);
  }

  private void writeDevicePropsToFile() {
    final String tag = TAG + "-W-DP";
    final String DP_FILENAME = "device_properties.txt";

    writeSingleInfoToFile(DP_FILENAME, "totalDeviceProps", "b64EncodedDeviceProps",
        mDeviceProps, null);
  }

  private void writeSingleInfoToFile(@NotNull String filename, @NotNull String countName,
                                     @NotNull String fieldName, @NotNull BaseInfo info,
                                     @Nullable String[] skip) {
    StringBuilder sbToWrite = new StringBuilder(String.format(HEADER_FMT, VERSION, countName, 1,
        fieldName));
    sbToWrite.append(info.getJSONString(skip));
    sbToWrite.append(FOOTER_STR);
    Utilities.writeToFile(this, filename, sbToWrite.toString(), false);
  }

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);

    final TextView textView = findViewById(R.id.textView);
    textView.setText(R.string.scan_start);

    initialize();

    mExecutor.execute(() -> {
      final long start = SystemClock.elapsedRealtime();

      getInstalledPackagesInformation();
      getAllCertificates();
      getAllBinaries();
      getAllLibraries();
      getHardwareInformation();
      getBuildInformation();
      getDeviceProperties();

      final long duration = SystemClock.elapsedRealtime() - start;

      writePackagesToFile();
      writeCertsToFile();
      writeBinsToFile();
      writeLibsToFile();
      writeHardwareToFile();
      writeBuildToFile();
      writeDevicePropsToFile();

      Log.d(TAG, String.format("Execution took %d ms.", duration));
      Log.w(TAG, String.format("Build version: %d", Build.VERSION.SDK_INT));
      Log.w(TAG,
              String.format("Results are available at: %s", Utilities.getResultStorageDirectory(this)));
      runOnUiThread(() -> textView.setText(getResources().getString(R.string.scan_end)));
    });
  }
}
