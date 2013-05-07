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
package org.simalliance.openmobileapi.service.security.arf;

import android.util.Log;

import java.security.AccessControlException;
import java.security.cert.Certificate;
import org.simalliance.openmobileapi.service.CardException;
import org.simalliance.openmobileapi.service.ISmartcardServiceCallback;
import org.simalliance.openmobileapi.service.ITerminal;
import org.simalliance.openmobileapi.service.security.AccessControlEnforcer;
import org.simalliance.openmobileapi.service.security.AccessRuleCache;
import org.simalliance.openmobileapi.service.security.ChannelAccess;
import org.simalliance.openmobileapi.service.security.arf.SecureElement;
import org.simalliance.openmobileapi.service.security.arf.PKCS15.PKCS15Handler;

public class ArfController {

    private PKCS15Handler mPkcs15Handler = null;
    private SecureElement mSecureElement = null;

    private AccessControlEnforcer mMaster = null;
    private AccessRuleCache mAccessRuleCache = null;
    private ITerminal mTerminal = null;

    protected boolean[] mNfcEventFlags = null;

    protected String _TAG = "SmartcardService ACE ARF";

    public ArfController(AccessControlEnforcer master) {
        mMaster = master;
        mAccessRuleCache = mMaster.getAccessRuleCache();
        mTerminal = mMaster.getTerminal();

    }

    public synchronized boolean initialize(ISmartcardServiceCallback callback) {

        if( mSecureElement == null ){
            mSecureElement = new SecureElement(this, mTerminal);
        }
        if( mPkcs15Handler == null ) {
            mPkcs15Handler = new PKCS15Handler(mSecureElement);
        }
        return mPkcs15Handler.loadAccessControlRules(mTerminal.getName());

    }

    public synchronized ChannelAccess setUpChannelAccess(byte[] aid, String packageName,
            ISmartcardServiceCallback callback) {
        ChannelAccess channelAccess = new ChannelAccess();

        if (packageName == null || packageName.isEmpty()) {
            throw new AccessControlException("package names must be specified");
        }
        if (aid == null || aid.length == 0) {
            throw new AccessControlException("AID must be specified");
        }
        if (aid.length < 5 || aid.length > 16) {
            throw new AccessControlException("AID has an invalid length");
        }

        try {
            // estimate SHA-1 hash value of the device application's certificate.
            Certificate[] appCerts = mMaster.getAPPCerts(packageName);

            // APP certificates must be available => otherwise Exception
            if (appCerts == null || appCerts.length == 0) {
                throw new AccessControlException("Application certificates are invalid or do not exist.");
            }

            channelAccess = getAccessRule(aid, appCerts);

        } catch (Throwable exp) {


            throw new AccessControlException(exp.getMessage());
        }
        return channelAccess;
    }


    public synchronized boolean[] isNFCEventAllowed(byte[] aid,
                                       String[] packageNames,
                                       ISmartcardServiceCallback callback)
        throws CardException
    {
        // the NFC Event Flags boolean array is created and filled in internal_enableAccessConditions.
        mNfcEventFlags = new boolean[packageNames.length];
        int i=0;
        ChannelAccess channelAccess = null;
        for( String packageName : packageNames ) {
            // estimate SHA-1 hash value of the device application's certificate.
            Certificate[] appCerts;
            try {
                appCerts = mMaster.getAPPCerts(packageName);

                // APP certificates must be available => otherwise Exception
                if (appCerts == null || appCerts.length == 0) {
                    throw new AccessControlException("Application certificates are invalid or do not exist.");
                }

                 channelAccess = getAccessRule(aid, appCerts);
                 mNfcEventFlags[i] = (channelAccess.getNFCEventAccess() == ChannelAccess.ACCESS.ALLOWED);

            } catch (Exception e) {
                Log.w(_TAG, " Access Rules for NFC: " + e.getLocalizedMessage());
                mNfcEventFlags[i] = false;
            }
            i++;
        }
        return mNfcEventFlags;
    }

    private ChannelAccess getAccessRule( byte[] aid, Certificate[] appCerts ) throws AccessControlException, CardException {
        ChannelAccess channelAccess = this.mAccessRuleCache.findAccessRule( aid, appCerts );
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

    public AccessRuleCache getAccessRuleCache(){
        return mAccessRuleCache;
    }
}
