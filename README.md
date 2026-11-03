# Java-

/*
 * SecurityHelper.java
 *
 * Optional companion to security.lua. Anything compared purely in Lua is
 * visible to anyone who pulls apart the AndLua assets and reads the
 * bytecode/source. Moving the comparison constants and logic here instead
 * means an attacker has to reverse a compiled .class/.dex instead of a
 * text-editable script, which is a meaningfully higher bar for the
 * load-bearing checks (expected hashes, cert fingerprint, license key
 * material).
 *
 * Call these methods from Lua via AndLua's luajava bridge, e.g.:
 *
 *   local Helper = luajava.bindClass("com.yourstudio.yourgame.SecurityHelper")
 *   local ok = Helper.verifyAll(context)
 *
 * Package/class name below is a placeholder — rename to match your project.
 */

package com.yourstudio.yourgame;

import android.app.ActivityManager;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.SigningInfo;
import android.os.Debug;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public final class SecurityHelper {

    // TODO: replace with your real values, ideally loaded from the
    // encrypted config (see security.lua decryptConfig) rather than left
    // as plain string constants in the class file.
    private static final String EXPECTED_PACKAGE_NAME = "com.yourstudio.yourgame";
    private static final String EXPECTED_CERT_SHA256   = "PUT_YOUR_CERT_SHA256_HERE";
    private static final String EXPECTED_DEX_SHA256    = "PUT_YOUR_DEX_SHA256_HERE";

    private SecurityHelper() {}

    // -------------------------------------------------------------
    // Debugger / tracer detection
    // -------------------------------------------------------------

    public static boolean isDebuggerAttached() {
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            return true;
        }
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/status"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    String value = line.substring("TracerPid:".length()).trim();
                    return Integer.parseInt(value) != 0;
                }
            }
        } catch (Exception e) {
            // If we can't read it, don't fail closed on a parsing error alone.
        }
        return false;
    }

    // -------------------------------------------------------------
    // DEX integrity
    // -------------------------------------------------------------

    public static boolean verifyDexIntegrity(Context context) {
        try {
            String apkPath = context.getPackageCodePath();
            try (ZipFile zip = new ZipFile(apkPath)) {
                ZipEntry entry = zip.getEntry("classes.dex");
                if (entry == null) return false;

                MessageDigest md = MessageDigest.getInstance("SHA-256");
                try (InputStream is = zip.getInputStream(entry)) {
                    byte[] buf = new byte[8192];
                    int n;
                    while ((n = is.read(buf)) != -1) {
                        md.update(buf, 0, n);
                    }
                }
                String actual = bytesToHex(md.digest());
                return actual.equalsIgnoreCase(EXPECTED_DEX_SHA256);
            }
        } catch (Exception e) {
            return false;
        }
    }

    // -------------------------------------------------------------
    // Signing cert + package identity (anti-repackaging)
    // -------------------------------------------------------------

    public static boolean verifyAppIdentity(Context context) {
        try {
            String packageName = context.getPackageName();
            if (!EXPECTED_PACKAGE_NAME.equals(packageName)) {
                return false;
            }

            PackageManager pm = context.getPackageManager();
            PackageInfo info = pm.getPackageInfo(
                    packageName, PackageManager.GET_SIGNING_CERTIFICATES);
            SigningInfo signingInfo = info.signingInfo;
            if (signingInfo == null) return false;

            android.content.pm.Signature[] sigs = signingInfo.getApkContentsSigners();
            if (sigs == null || sigs.length == 0) return false;

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(sigs[0].toByteArray());
            String actual = bytesToHex(md.digest());

            return actual.equalsIgnoreCase(EXPECTED_CERT_SHA256.replace(":", ""));
        } catch (Exception e) {
            return false;
        }
    }

    // -------------------------------------------------------------
    // GameGuardian / known cheat-tool process scan
    // -------------------------------------------------------------

    private static final String[] GG_SIGNATURES = {
            "org.gg.app", "catch_.me.if.you.can", "GameGuardian", "gg_mem"
    };

    public static boolean scanRunningProcesses(Context context) {
        try {
            ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
            List<ActivityManager.RunningAppProcessInfo> procs = am.getRunningAppProcesses();
            if (procs == null) return false;
            for (ActivityManager.RunningAppProcessInfo p : procs) {
                for (String sig : GG_SIGNATURES) {
                    if (p.processName != null && p.processName.contains(sig)) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        }
        return false;
    }

    // -------------------------------------------------------------
    // License signature verification (RSA)
    // -------------------------------------------------------------

    public static boolean verifySignature(byte[] data, byte[] signatureBytes, java.security.PublicKey publicKey) {
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(publicKey);
            sig.update(data);
            return sig.verify(signatureBytes);
        } catch (Exception e) {
            return false;
        }
    }

    // -------------------------------------------------------------
    // Convenience: run everything, return false on first failure
    // -------------------------------------------------------------

    public static boolean verifyAll(Context context) {
        if (isDebuggerAttached()) return false;
        if (scanRunningProcesses(context)) return false;
        if (!verifyDexIntegrity(context)) return false;
        if (!verifyAppIdentity(context)) return false;
        return true;
    }

    // -------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
