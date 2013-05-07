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

package org.simalliance.openmobileapi.service.security.ara;

import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.security.AccessControlException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.MissingResourceException;

import org.simalliance.openmobileapi.service.CardException;
import org.simalliance.openmobileapi.service.IChannel;
import org.simalliance.openmobileapi.service.ISmartcardServiceCallback;
import org.simalliance.openmobileapi.service.ITerminal;
import org.simalliance.openmobileapi.service.SmartcardService;
import org.simalliance.openmobileapi.service.security.AccessControlEnforcer;
import org.simalliance.openmobileapi.service.security.AccessRuleCache;
import org.simalliance.openmobileapi.service.security.ChannelAccess;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.AID_REF_DO;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.AR_DO;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.BerTlv;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.DO_Exception;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.Hash_REF_DO;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.ParserException;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.REF_AR_DO;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.REF_DO;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.Response_ALL_AR_DO;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.Response_AR_DO;
import org.simalliance.openmobileapi.service.security.gpac.dataobjects.Response_DO_Factory;

public class AraController {

    private AccessControlEnforcer mMaster = null;
    private AccessRuleCache mAccessRuleCache = null;

    private ITerminal mTerminal = null;
    private AccessRuleApplet mApplet = null;

    private boolean[] mNfcEventFlags = null;

    private boolean mNoSuchElement = false;
    private boolean mAllRulesRead = false;

    private String ACCESS_CONTROL_ENFORCER_TAG = "ACE ARA";

    public static final byte[] ARA_M_AID = new byte[] {
            (byte)0xA0, (byte)0x00, (byte)0x00, (byte)0x01, (byte)0x51, (byte)0x41, (byte)0x43, (byte)0x4C,
            (byte)0x00
    };

    public AraController(AccessControlEnforcer master ) {
        mMaster = master;
        mAccessRuleCache = mMaster.getAccessRuleCache();
        mTerminal = mMaster.getTerminal();

    }

    public boolean isNoSuchElement(){
        return mNoSuchElement;
    }

    public static byte[] getAraMAid() {
        return ARA_M_AID;
    }

    public synchronized boolean[] isNFCEventAllowed(
            byte[] aid,
            String[] packageNames,
            ISmartcardServiceCallback callback) throws CardException
    {
        ChannelAccess channelAccess = null;
        // the NFC Event Flags boolean array is created and filled in internal_enableAccessConditions.
        mNfcEventFlags = new boolean[packageNames.length];
        int i=0;
        for( String packageName : packageNames ) {
            // estimate the device application's certificates.
            Certificate[] appCerts;
            try {
                appCerts = mMaster.getAPPCerts(packageName);
                // APP certificates must be available => otherwise Exception
                if (appCerts == null || appCerts.length == 0) {
                    throw new AccessControlException("Application Certificates are invalid or do not exist.");
                }


                 channelAccess = getAccessRule(aid, appCerts, callback);
                 mNfcEventFlags[i] = (channelAccess.getNFCEventAccess() == ChannelAccess.ACCESS.ALLOWED);

            } catch (Exception e) {
                Log.w(ACCESS_CONTROL_ENFORCER_TAG, " Access Rules for NFC: " + e.getLocalizedMessage());
                mNfcEventFlags[i] = false;
            }
            i++;
        }
        return mNfcEventFlags;
    }

    public synchronized boolean initialize(
            boolean loadAtStartup,
            ISmartcardServiceCallback callback)
    {
        IChannel channel = this.handleOpenChannel(callback);

        if( channel == null ){
            throw new AccessControlException("could not open channel");
        }

        try {
            // set new applet handler since a new channel is used.
            mApplet = new AccessRuleApplet(channel);
            byte[] tag = mApplet.readRefreshTag();
            // if refresh tag is equal to the previous one it is not
            // neccessary to read all rules again.
            if( mAccessRuleCache.isRefreshTagEqual(tag)) {
                Log.d(ACCESS_CONTROL_ENFORCER_TAG, "Refresh tag has not changed. Using access rules from cache.");
                return false;
            }
            Log.d(ACCESS_CONTROL_ENFORCER_TAG, "Refresh tag has changed.");
            // set new refresh tag and empty cache.
            mAccessRuleCache.setRefreshTag(tag);
            mAccessRuleCache.clearCache();

            if( loadAtStartup ) {
                // Read content from ARA
                Log.d(ACCESS_CONTROL_ENFORCER_TAG, "Read ARs from ARA");
                this.readAllAccessRules();
            }
        } catch (Exception e) {
            Log.d(ACCESS_CONTROL_ENFORCER_TAG, "ARA error: " + e.getLocalizedMessage());
            throw new AccessControlException(e.getLocalizedMessage()); // Throw Exception
        } finally {
            if( channel != null )
                closeChannel(channel);
        }
        return true;
    }

    private IChannel handleOpenChannel( ISmartcardServiceCallback callback ){
        IChannel channel = null;
        String reason = "";

        try {
            channel = openChannel(mTerminal, getAraMAid(), callback);
        } catch (Exception e) {
            String msg = e.toString();
            msg = " ARA-M couldn't be selected: " + msg;
            Log.d(ACCESS_CONTROL_ENFORCER_TAG, msg);
            if (e instanceof NoSuchElementException) {
                mNoSuchElement = true;
                // SELECT failed
                // Access Rule Applet is not available => deny any access
                reason = " No Access because ARA-M is not available";
                Log.d(ACCESS_CONTROL_ENFORCER_TAG, msg );
                throw new AccessControlException(reason);
            } else if( e instanceof MissingResourceException ){
                // re-throw exception
                // fixes issue 23
                // this indicates that no channel is left for accessing the SE element
                Log.d(ACCESS_CONTROL_ENFORCER_TAG, "no channels left to access ARA-M: " + e.getMessage() );
                throw (MissingResourceException)e;
            }else {
                // MANAGE CHANNEL failed or general error

                reason = msg;
                Log.d(ACCESS_CONTROL_ENFORCER_TAG," ARA-M can not be accessed: " + msg);
                throw new AccessControlException(reason);
            }
        }   // End of Exception handling
        return channel;
    }

    public synchronized ChannelAccess setUpChannelAccess(
            byte[] aid,
            String packageName,
            ISmartcardServiceCallback callback) {

        ChannelAccess channelAccess = new ChannelAccess();
        if (packageName == null || packageName.isEmpty() ) {
            throw new AccessControlException("package name must be specified");
        }
        if (aid == null || aid.length == 0) {
            throw new AccessControlException("AID must be specified");
        }
        if (aid.length < 5 || aid.length > 16) {
            throw new AccessControlException("AID has an invalid length");
        }

        try {
            // estimate device application's certificates.
            Certificate[] appCerts = mMaster.getAPPCerts(packageName);

            // APP certificates must be available => otherwise Exception
            if (appCerts == null || appCerts.length == 0) {
                throw new AccessControlException("Application certificates are invalid or do not exist.");
            }


            channelAccess = getAccessRule(aid, appCerts, callback );

        } catch (Throwable exp) {
            throw new AccessControlException(exp.getMessage());
        }
        return channelAccess;
    }

    private ChannelAccess getAccessRule( byte[] aid, Certificate[] appCerts, ISmartcardServiceCallback callback  ) throws AccessControlException, CardException, CertificateEncodingException {

        ChannelAccess channelAccess = null;

        // if read all is false then get access rules on demand.
        if( this.mAllRulesRead == false ){
            IChannel channel = this.handleOpenChannel(callback);
            if (channel == null) {
                throw new AccessControlException("could not open channel");
            }
            // set new applet handler since a new channel is used.
            mApplet = new AccessRuleApplet(channel);
            try {
                byte[] tag = mApplet.readRefreshTag();
                // generate hash value of end entity certificate...
                //byte[] appCertHash = AccessController.getAppCertHash(appCerts[0]);

                // check if ARA data has been changed
                // if yes then reload the channel access rule from ARA.
                // otherwise it is save to use the cached rule.
                if( mAccessRuleCache.isRefreshTagEqual(tag) ) {
                    channelAccess = mAccessRuleCache.findAccessRule( aid, appCerts );
                    if( channelAccess != null ){
                        return channelAccess;
                    }
                } else {
                    // if refresh tag differs -> invalidate the whole cache.
                    mAccessRuleCache.clearCache();
                    mAccessRuleCache.setRefreshTag( tag );
                }

                channelAccess = readAccessRule( aid, appCerts );
            } finally {
                if( channel != null ){
                    closeChannel(channel);
                }
            }
        } else {
            // get rules from internal storage
            channelAccess = mAccessRuleCache.findAccessRule( aid, appCerts );
        }

        // if no rule was found return an empty access rule
        // with all access denied.
        if( channelAccess == null ){
            channelAccess = new ChannelAccess();
            channelAccess.setAccess(ChannelAccess.ACCESS.DENIED, "no access rule found!" );
            channelAccess.setApduAccess(ChannelAccess.ACCESS.DENIED);
            channelAccess.setNFCEventAccess(ChannelAccess.ACCESS.DENIED);
        }
        return channelAccess;
    }

    private ChannelAccess readAccessRule( byte[] aid, Certificate[] appCerts) throws AccessControlException, CardException {

        // TODO: check difference between DeviceCertHash and Certificate Chain (EndEntityCertHash, IntermediateCertHash (1..n), RootCertHash)
        // The DeviceCertificate is equal to the EndEntityCertificate.
        // The android systems seems always to deliver only the EndEntityCertificate, but this seems not to be sure.
        // thats why we implement the whole chain.

        AID_REF_DO aid_ref_do = null;
        Hash_REF_DO hash_ref_do = null;
        AR_DO ar_do = null;
        REF_DO ref_do = null;

        // build-up hash map key as specific as possible.
        REF_DO ref_do_key;
        try {
            ref_do_key = AccessRuleCache.buildHashMapKey(aid, AccessControlEnforcer.getAppCertHash(appCerts[0]));
        } catch (CertificateEncodingException e1) {
            throw new AccessControlException("Problem with App Certificate.");
        }

        // Search Rule A ( Certificate(s); AID )
        // walk through certificate chain.
        for( Certificate appCert : appCerts ){

            aid_ref_do = AccessRuleCache.getAidRefDo(aid);
            try {
                hash_ref_do = new Hash_REF_DO(AccessControlEnforcer.getAppCertHash(appCert));
                ref_do = new REF_DO(aid_ref_do, hash_ref_do);
                ar_do = readSpecificAccessRule( ref_do );

                if( ar_do != null ){
                    mAccessRuleCache.put( ref_do, ar_do );
                    return mAccessRuleCache.put( ref_do_key, ar_do );
                }
            } catch (CertificateEncodingException e) {
                throw new AccessControlException("Problem with App Certificate.");
            }
        }

        // SearchRule B ( <AllDeviceApplications>; AID)
        aid_ref_do =  AccessRuleCache.getAidRefDo(aid);
        hash_ref_do = new Hash_REF_DO(); // empty hash ref
        ref_do = new REF_DO(aid_ref_do, hash_ref_do);
        ar_do = readSpecificAccessRule( ref_do );

        if( ar_do != null ){
            mAccessRuleCache.put( ref_do, ar_do );
            return mAccessRuleCache.put( ref_do_key, ar_do );
        }


        // Search Rule C ( Certificate(s); <AllSEApplications> )
        for( Certificate appCert : appCerts ){
            aid_ref_do = new AID_REF_DO(AID_REF_DO._TAG);
            try {
                hash_ref_do = new Hash_REF_DO(AccessControlEnforcer.getAppCertHash(appCert));
                ref_do = new REF_DO(aid_ref_do, hash_ref_do);
                ar_do = readSpecificAccessRule( ref_do );

                if( ar_do != null ){
                    mAccessRuleCache.put( ref_do, ar_do );
                    return mAccessRuleCache.put( ref_do_key, ar_do );
                }
            } catch (CertificateEncodingException e) {
                throw new AccessControlException("Problem with App Certificate.");
            }
        }

        // SearchRule D ( <AllDeviceApplications>; <AllSEApplications>)
        aid_ref_do =  new AID_REF_DO(AID_REF_DO._TAG);
        hash_ref_do = new Hash_REF_DO();
        ref_do = new REF_DO(aid_ref_do, hash_ref_do);
        ar_do = readSpecificAccessRule( ref_do );

        if( ar_do != null ){
            mAccessRuleCache.put( ref_do, ar_do );
            return mAccessRuleCache.put( ref_do_key, ar_do );
        }

        return null;
    }

    private AR_DO readSpecificAccessRule( REF_DO ref_do  ) throws AccessControlException, CardException {

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            ref_do.build(out);

            byte[] data = mApplet.readSpecificAccessRule(out.toByteArray());
            // no data returned, but no exception
            // -> no rule.
            if( data == null ) {
                return null;
            }

            BerTlv tlv = Response_DO_Factory.createDO( data );
            if( tlv == null ) {
                return null; // no rule
            } if( tlv instanceof Response_AR_DO ){
                return ((Response_AR_DO)tlv).getArDo();
            } else {
                throw new AccessControlException( "Applet returned invalid or wrong data object!");
            }

        } catch (DO_Exception e) {
            throw new AccessControlException("Data Object Exception: " + e.getMessage());
        } catch (ParserException e) {
            throw new AccessControlException("Parsing Data Object Exception: " + e.getMessage());
        }
    }

    /**
     *
     * @return true if rules are read, false if not necessary or not available, but no error
     * @throws AccessControlException
     * @throws CardException
     */
    private boolean readAllAccessRules() throws AccessControlException, CardException {

        try {
            mAllRulesRead = false;

            byte[] data = mApplet.readAllAccessRules();
            // no data returned, but no exception
            // -> no rule.
            if( data == null ) {
                return false;
            }

            BerTlv tlv = Response_DO_Factory.createDO( data );
            if( tlv == null ) {
                throw new AccessControlException("No valid data object found" );
            } if( tlv instanceof Response_ALL_AR_DO ){

                ArrayList<REF_AR_DO> array = ((Response_ALL_AR_DO)tlv).getRefArDos();
                if( array == null || array.size() == 0 ){
                    return false; // no rules
                } else {
                    Iterator<REF_AR_DO> iter = array.iterator();
                    while( iter.hasNext() ){
                        REF_AR_DO ref_ar_do = iter.next();
                        this.mAccessRuleCache.putWithMerge(ref_ar_do.getRefDo(), ref_ar_do.getArDo());
                    }
                }
            } else {
                throw new AccessControlException( "Applet returned invalid or wrong data object!");
            }
        } catch (ParserException e) {
            throw new AccessControlException("Parsing Data Object Exception: " + e.getMessage());
        }
        mAllRulesRead = true;
        return true;
    }

    private IChannel openChannel(ITerminal terminal, byte[] aid, ISmartcardServiceCallback callback) throws Exception
    {


        IChannel channel = terminal.openLogicalChannel(null, aid, callback);

        // set access conditions to access ARA-M.
        ChannelAccess araChannelAccess = new ChannelAccess();
        araChannelAccess.setAccess(ChannelAccess.ACCESS.ALLOWED, ACCESS_CONTROL_ENFORCER_TAG);
        araChannelAccess.setApduAccess(ChannelAccess.ACCESS.ALLOWED);
        channel.setChannelAccess(araChannelAccess);

        return channel;
}

    private void closeChannel(IChannel channel) {
        try {
            if (channel != null && channel.getChannelNumber() != 0) {

                channel.close();

            }
        } catch (org.simalliance.openmobileapi.service.CardException e) {
        }
    }
}
