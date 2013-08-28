/*
 * Copyright 2012 Giesecke & Devrient GmbH.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package org.simalliance.openmobileapi.service.security;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.pm.Signature;
import android.os.Build;
import android.os.SystemProperties;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.PrintWriter;
import java.security.AccessControlException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.MissingResourceException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.simalliance.openmobileapi.service.CardException;
import org.simalliance.openmobileapi.service.IChannel;
import org.simalliance.openmobileapi.service.ISmartcardServiceCallback;
import org.simalliance.openmobileapi.service.ITerminal;
import org.simalliance.openmobileapi.service.SmartcardService;
import org.simalliance.openmobileapi.service.Util;
import org.simalliance.openmobileapi.service.security.ChannelAccess.ACCESS;
import org.simalliance.openmobileapi.service.security.ara.AraController;

import org.simalliance.openmobileapi.service.security.arf.ArfController;


public class AccessControlEnforcer {

    private PackageManager mPackageManager = null;

    private AraController mAraController = null;
    private boolean mUseAra = true;

    private ArfController mArfController = null;
    private boolean mUseArf = false;

    private AccessRuleCache mAccessRuleCache = null;

    private ITerminal mTerminal = null;

    private ChannelAccess mInitialChannelAccess = new ChannelAccess();
    private boolean mFullAccess = false;

    private final String _TAG = "SmartcardService ACE";

    private final String ACCESS_CONTROL_ENFORCER = "Access Control Enforcer: ";

    public AccessControlEnforcer( ITerminal terminal ) {
        mTerminal = terminal;
        mAccessRuleCache = new AccessRuleCache();
        // by default Access Rule Applet is preferred.
        mAraController = new AraController( this );

    }

    public PackageManager getPackageManager() {
        return mPackageManager;
    }

    public void setPackageManager(PackageManager packageManager) {
        this.mPackageManager = packageManager;
    }

    public ITerminal getTerminal(){
        return mTerminal;
    }

    public AccessRuleCache getAccessRuleCache(){
        return mAccessRuleCache;
    }

    public static byte[] getDefaultAccessControlAid(){
        return AraController.getAraMAid();
    }

    public synchronized boolean initialize( boolean loadAtStartup, ISmartcardServiceCallback callback ) {
        boolean status = true;
        String denyMsg = "";
        readSecurityProfile();

        if(!mTerminal.getName().startsWith(SmartcardService._UICC_TERMINAL)) {
            // When SE is not the UICC then it's allowed to grant full access if no
            // rules can be retreived.
            mFullAccess = true;
        }

        /* 1 - Let's try to use ARA */
        if( mUseAra && mAraController != null ){
            try {
                // initialize returns true if access rules has been changed otherwise
                // there are no changes -> no update of intialchannelaccess necessary.
                if(mAraController.initialize(loadAtStartup, callback)) {
                    // allow access to set up access control for a channel
                    mInitialChannelAccess.setApduAccess(ChannelAccess.ACCESS.ALLOWED);
                    mInitialChannelAccess.setNFCEventAccess(ChannelAccess.ACCESS.ALLOWED);
                    mInitialChannelAccess.setAccess(ChannelAccess.ACCESS.ALLOWED, "");
                }

                // disable other access methods
                Log.i(_TAG, "ARA applet is used for:" + mTerminal.getName());
                mUseArf = false;
                mFullAccess = false;

            } catch( Exception e ) {
                // ARA cannot be used since we got an exception during initialization
                mUseAra = false;
                denyMsg = e.getLocalizedMessage();

                if( e instanceof MissingResourceException ) {
                    throw new MissingResourceException( e.getMessage(), "", "");
                }
                else if( mAraController.isNoSuchElement() ) {
                    Log.i(_TAG, "No ARA applet found in: " + mTerminal.getName());
                }
                else {
                    // ARA is available but doesn't work properly.
                    // We are going to disable everything per security req.
                    Log.i(_TAG, e.getLocalizedMessage() );
                    mUseArf = false;
                    mFullAccess = false;
                    status = false;
                }
            }
        }

        /* 2 - Let's try to use ARF since ARA cannot be used */
        if(mUseArf && !mTerminal.getName().startsWith(SmartcardService._UICC_TERMINAL)) {
            Log.i(_TAG, "Disable ARF for terminal: " + mTerminal.getName() + " (ARF is only available for UICC)");
            mUseArf = false; // Arf is only supproted on UICC
        }

        if( mUseArf && mArfController == null)
            mArfController = new ArfController(this);

        if( mUseArf && mArfController != null){
            try {
                // initialize returns true if access rules has been changed otherwise
                // there are no changes -> no update of intialchannelaccess necessary.
                if( mArfController.initialize(callback) == true ) {
                    // allow access to set up access control for a channel
                    mInitialChannelAccess.setApduAccess(ChannelAccess.ACCESS.ALLOWED);
                    mInitialChannelAccess.setNFCEventAccess(ChannelAccess.ACCESS.ALLOWED);
                    mInitialChannelAccess.setAccess(ChannelAccess.ACCESS.ALLOWED, "");
                }

                // disable other access methods
                Log.i(_TAG, "ARF rules are used for:" + mTerminal.getName());
                mFullAccess = false;

            } catch( Exception e ) {
                // ARF cannot be used since we got an exception
                mUseArf = false;
                status = false;
                denyMsg = e.getLocalizedMessage();
                Log.i(_TAG, e.getLocalizedMessage() );
            }
        }

        /* 3 - Let's grant full access since neither ARA nor ARF can be used */
        if(mFullAccess) {
            mInitialChannelAccess.setApduAccess(ChannelAccess.ACCESS.ALLOWED);
            mInitialChannelAccess.setNFCEventAccess(ChannelAccess.ACCESS.ALLOWED);
            mInitialChannelAccess.setAccess(ChannelAccess.ACCESS.ALLOWED, "");

            Log.i(_TAG, "Full access granted for:" + mTerminal.getName());
        }

        /* 4 - Let's block everything since neither ARA, ARF or fullaccess can be used */
        if(!mUseArf && !mUseAra && !mFullAccess) {
            mInitialChannelAccess.setApduAccess(ChannelAccess.ACCESS.DENIED);
            mInitialChannelAccess.setNFCEventAccess(ChannelAccess.ACCESS.DENIED);
            mInitialChannelAccess.setAccess(ChannelAccess.ACCESS.DENIED, denyMsg);

            Log.i(_TAG, "Deny any access to:" + mTerminal.getName());
        }

        return status;
    }

    public static Certificate decodeCertificate(byte[] certData) throws CertificateException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory
                .generateCertificate(new ByteArrayInputStream(certData));

        return cert;
    }

    public synchronized void checkCommand(IChannel channel, byte[] command) {

        ChannelAccess ca = channel.getChannelAccess();
        if (ca == null) {

            throw new AccessControlException(ACCESS_CONTROL_ENFORCER + "Channel access not set");
        }

        String reason = ca.getReason();
        if (reason.length() == 0) {
            reason = "Command not allowed!";
        }

        if (ca.getAccess() != ACCESS.ALLOWED ) {

            throw new AccessControlException(ACCESS_CONTROL_ENFORCER + reason);
        }
        if (ca.isUseApduFilter()) {
            ApduFilter[] accessConditions = ca.getApduFilter();
            if (accessConditions == null || accessConditions.length == 0) {

                throw new AccessControlException(ACCESS_CONTROL_ENFORCER + "Access Rule not available: " + reason);
            }
            for (ApduFilter ac : accessConditions) {
                if (CommandApdu.compareHeaders(command, ac.getMask(), ac.getApdu())) {

                    return;
                }
            }

            throw new AccessControlException(ACCESS_CONTROL_ENFORCER + "Access Rule does not match: " + reason);
        }
        if (ca.getApduAccess() == ChannelAccess.ACCESS.ALLOWED) {

            return;
        } else {

            throw new AccessControlException(ACCESS_CONTROL_ENFORCER + "APDU access NOT allowed" );
        }
    }


    public synchronized boolean[] isNFCEventAllowed(
            byte[] aid,
            String[] packageNames,
            ISmartcardServiceCallback callback)
                    throws CardException
    {
        if( mUseAra && mAraController != null ){
            return mAraController.isNFCEventAllowed(aid, packageNames, callback);
        }

        else if( mUseArf && mArfController != null ) {
            return mArfController.isNFCEventAllowed(aid, packageNames, callback);
        }

        else {
            // 2012-09-27
            // if ARA is not available and terminal DOES NOT belong to a UICC -> mFullAccess is true;
            // if ARA is not available and terminal belongs to a UICC -> mFullAccess is false (if ARF is not available);
            boolean[] ret = new boolean[packageNames.length];
            for( int i = 0; i < ret.length; i++ ){
                ret[i] = this.mFullAccess;
            }
            return ret;
        }
    }

    public ChannelAccess setUpChannelAccess(
            byte[] aid,
            String packageName,
            ISmartcardServiceCallback callback) {
        ChannelAccess channelAccess = null;



        // check result of channel access during initialization procedure
        if( mInitialChannelAccess.getAccess() == ChannelAccess.ACCESS.DENIED ){
            throw new AccessControlException( ACCESS_CONTROL_ENFORCER + "access denied: " + mInitialChannelAccess.getReason() );
        }
        // this is the new GP Access Control Enforcer implementation
        if( mUseAra && mAraController != null ){
            try {
                channelAccess = mAraController.setUpChannelAccess(aid, packageName, callback);
            } catch( Exception e ) {
                if( e instanceof MissingResourceException ) {
                    throw new MissingResourceException( ACCESS_CONTROL_ENFORCER + e.getMessage(), "", "");
                } else {
                    // access is denied for any terminal if exception during accessing ARA has any other reason.
                    throw new AccessControlException( ACCESS_CONTROL_ENFORCER + "access denied: " + e.getMessage() );
                }
            }
        }

        else if( mUseArf && mArfController != null){
            try {
                channelAccess = mArfController.setUpChannelAccess(aid, packageName, callback);
            } catch( Exception e ) {
                if( e instanceof MissingResourceException ) {
                    throw new MissingResourceException( ACCESS_CONTROL_ENFORCER + e.getMessage(), "", "");
                }
                throw new AccessControlException( ACCESS_CONTROL_ENFORCER + "access denied: " + e.getMessage() );
            }
        }

        if( channelAccess == null || // precautionary check
            (channelAccess.getApduAccess() != ChannelAccess.ACCESS.ALLOWED &&
             channelAccess.isUseApduFilter() == false)) {
            if( this.mFullAccess == true ){ // mFullAccess is set if SE has no ARA and is not a UICC.
                // if full access is set then we reuse the initial channel access,
                // since we got so far it allows everything with a descriptive reason.
                channelAccess = mInitialChannelAccess;
            } else {
                throw new AccessControlException( ACCESS_CONTROL_ENFORCER + "no APDU access allowed!" );
            }
        }

        channelAccess.setPackageName(packageName);

        return channelAccess.clone();
    }

    /**
     * Returns Certificate chain for one package.
     *
     * @param packageName
     * @return
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws AccessControlException
     * @throws CardException
     */
    public Certificate[] getAPPCerts(String packageName)
             throws CertificateException, NoSuchAlgorithmException, AccessControlException {

        if(packageName == null || packageName.length() == 0)
             throw new AccessControlException("Package Name not defined");

        PackageInfo foundPkgInfo;

        try {
            foundPkgInfo = mPackageManager.getPackageInfo(packageName,
                                                    PackageManager.GET_SIGNATURES);
        } catch (NameNotFoundException ne) {
            throw new AccessControlException("Package does not exist");
        }

         if (foundPkgInfo == null) {
                 throw new AccessControlException("Package does not exist");
             }

         ArrayList<Certificate> appCerts = new ArrayList<Certificate>();

         for (Signature signature : foundPkgInfo.signatures) {
            appCerts.add(decodeCertificate(signature.toByteArray()));
         }
         return appCerts.toArray(new Certificate[appCerts.size()]);
    }

    public static byte[] getAppCertHash(Certificate appCert) throws CertificateEncodingException
    {
        /**
         * Note: This loop is needed as workaround for a bug in Android 2.3.
         * After a failed certificate verification in a previous step the
         * MessageDigest.getInstance("SHA") call will fail with the
         * AlgorithmNotSupported exception. But a second try will normally
         * succeed.
         */
        MessageDigest md = null;
        for (int i = 0; i < 10; i++) {
            try {
                md = MessageDigest.getInstance("SHA");
                break;
            } catch (Exception e) {
            }
        }
        if (md == null) {
            throw new AccessControlException("Hash can not be computed");
        }
        return md.digest(appCert.getEncoded());
    }

    public void dump(PrintWriter writer, String prefix) {
       writer.println(prefix + _TAG + ":");
       prefix += "  ";

       writer.println(prefix + "mUseArf: " + mUseArf);
       writer.println(prefix + "mUseAra: " + mUseAra);
       writer.println(prefix + "mInitialChannelAccess:");
       writer.println(prefix + "  " + mInitialChannelAccess.toString());
       writer.println();

       /* Dump the access rule cache */
       if(mAccessRuleCache != null) mAccessRuleCache.dump(writer, prefix);
    }

    private void readSecurityProfile() {
        if(!Build.IS_DEBUGGABLE) {
            mUseArf = true;
            mUseAra = true;
            mFullAccess = false; // Per default we don't grant full access.
        } else {
            String level = SystemProperties.get("service.seek", "useara usearf");
            level = SystemProperties.get("persist.service.seek", level);

            if(level.contains("usearf")) mUseArf = true; else mUseArf = false;
            if(level.contains("useara")) mUseAra = true; else mUseAra = false;
            if(level.contains("fullaccess")) mFullAccess = true; else mFullAccess = false;
        }
        Log.i(_TAG, "Allowed ACE mode: ara=" + mUseAra + " arf=" + mUseArf + " fullaccess=" + mFullAccess );
    }
}
