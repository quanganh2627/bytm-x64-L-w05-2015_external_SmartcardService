/*
 * Copyright (C) 2011, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Contributed by: Giesecke & Devrient GmbH.
 */

package org.simalliance.openmobileapi.service;

import dalvik.system.DexClassLoader;
import dalvik.system.DexFile;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.os.AsyncTask;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.os.RemoteException;

import org.simalliance.openmobileapi.service.Channel;
import org.simalliance.openmobileapi.service.Channel.SmartcardServiceChannel;
import org.simalliance.openmobileapi.service.ISmartcardService;
import org.simalliance.openmobileapi.service.ISmartcardServiceCallback;
import org.simalliance.openmobileapi.service.Terminal.SmartcardServiceReader;

import android.util.Log;

import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.lang.reflect.Constructor;
import java.security.AccessControlException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;



import org.simalliance.openmobileapi.service.security.AccessControlEnforcer;
import org.simalliance.openmobileapi.service.security.ChannelAccess;


/**
 * The smartcard service is setup with privileges to access smart card hardware.
 * The service enforces the permission
 * 'org.simalliance.openmobileapi.service.permission.BIND'.
 */
public final class SmartcardService extends Service {

    public static final String _TAG = "SmartcardService";
    public static final String _UICC_TERMINAL = "SIM";
    public static final String _eSE_TERMINAL = "eSE";
    public static final String _SD_TERMINAL = "SD";

    static void clearError(SmartcardError error) {
        if (error != null) {
            error.clear();
        }
    }

    @SuppressWarnings({ "rawtypes" })
    static void setError(SmartcardError error, Class clazz, String message) {
        if (error != null) {
            error.setError(clazz, message);
        }
    }

    static void setError(SmartcardError error, Exception e) {
        if (error != null) {
            error.setError(e.getClass(), e.getMessage());
        }
    }

    /**
     * For now this list is setup in onCreate(), not changed later and therefore
     * not synchronized.
     */
    private Map<String, ITerminal> mTerminals = new TreeMap<String, ITerminal>();

    /**
     * For now this list is setup in onCreate(), not changed later and therefore
     * not synchronized.
     */
    private Map<String, ITerminal> mAddOnTerminals = new TreeMap<String, ITerminal>();



    public SmartcardService() {
        super();
    }

    @Override
    public IBinder onBind(Intent intent) {
        Log.v(_TAG, Thread.currentThread().getName()
                        + " smartcard service onBind");
        if (ISmartcardService.class.getName().equals(intent.getAction())) {
            return mSmartcardBinder;
        }
        return null;
    }

    @Override
    public void onCreate() {
        Log.v(_TAG, Thread.currentThread().getName()
                + " smartcard service onCreate");
        createTerminals();
        new InitialiseTask().execute();
    }

    @Override
    public void dump(FileDescriptor fd, PrintWriter writer, String[] args) {
        writer.println("SMARTCARD SERVICE (dumpsys activity service org.simalliance.openmobileapi)");
        writer.println();

        String prefix = "  ";

        if(!Build.IS_DEBUGGABLE) {
            writer.println(prefix + "Your build is not debuggable!");
            writer.println(prefix + "Smarcard service dump is only available for userdebug and eng build");
        } else {
            writer.println(prefix + "List of terminals:");
            for (ITerminal terminal : mTerminals.values()) {
               writer.println(prefix + "  " + terminal.getName());
            }
            writer.println();

            writer.println(prefix + "List of add-on terminals:");
            for (ITerminal terminal : mAddOnTerminals.values()) {
               writer.println(prefix + "  " + terminal.getName());
            }
            writer.println();

            for (ITerminal terminal : mTerminals.values()) {
               terminal.dump(writer, prefix);
            }
            for (ITerminal terminal : mAddOnTerminals.values()) {
               terminal.dump(writer, prefix);
            }
        }
    }

    private class InitialiseTask extends AsyncTask<Void, Void, Void> {

        @Override
        protected void onPreExecute() {
            super.onPreExecute();

        }

        @Override
        protected Void doInBackground(Void... arg0) {

            initializeAccessControl(null, null);
            return null;
        }

        @Override
        protected void onPostExecute(Void result) {
            super.onPostExecute(result);
            Log.i(_TAG, "OnPostExecute()");
            registerSimStateChangedEvent(getApplicationContext()) ;
            registerAdapterStateChangedEvent(getApplicationContext());
            registerMediaMountedEvent(getApplicationContext());
        }
    }

    private void registerSimStateChangedEvent(Context context) {
        Log.v(_TAG, "register SIM_STATE_CHANGED event");

        IntentFilter intentFilter = new IntentFilter("android.intent.action.SIM_STATE_CHANGED");
        BroadcastReceiver mReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                final boolean simAction = intent.getAction().equals("android.intent.action.SIM_STATE_CHANGED");
                final boolean simReady = simAction && intent.getExtras().getString("ss").equals("READY");
                final boolean simLoaded = simAction && intent.getExtras().getString("ss").equals("LOADED");
                if( simReady ){
                    Log.i(_TAG, "SIM is ready. Checking access rules for updates.");
                    try {
                        initializeAccessControl( _UICC_TERMINAL, null );
                    } catch (Exception e) {

                    }
                }
                 else if( simLoaded){
                    Log.i(_TAG, "SIM is loaded. Checking access rules for updates.");
                    try {
                        initializeAccessControl( _UICC_TERMINAL, null );
                    } catch (Exception e) {

                    }
                }
            }
        };

        context.registerReceiver(mReceiver, intentFilter);
    }

    private void registerAdapterStateChangedEvent(Context context) {
        Log.v(_TAG, "register ADAPTER_STATE_CHANGED event");

        IntentFilter intentFilter = new IntentFilter("android.nfc.action.ADAPTER_STATE_CHANGED");
        BroadcastReceiver mReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                final boolean nfcAdapterAction = intent.getAction().equals("android.nfc.action.ADAPTER_STATE_CHANGED");
                final boolean nfcAdapterOn = nfcAdapterAction && intent.getIntExtra("android.nfc.extra.ADAPTER_STATE", 1) == 3; // is NFC Adapter turned on ?
                if( nfcAdapterOn){
                    Log.i(_TAG, "NFC Adapter is ON. Checking access rules for updates.");
                    try {
                        initializeAccessControl( SmartcardService._eSE_TERMINAL, null );
                    } catch (Exception e) {

                    }
                }
            }
        };
        context.registerReceiver(mReceiver, intentFilter);
    }

    private void registerMediaMountedEvent(Context context) {
        Log.v(_TAG, "register MEDIA_MOUNTED event");

        IntentFilter intentFilter = new IntentFilter("android.intent.action.MEDIA_MOUNTED");
        BroadcastReceiver mReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                final boolean mediaMounted = intent.getAction().equals("android.intent.action.MEDIA_MOUNTED");
                if( mediaMounted){
                    Log.i(_TAG, "New Media is mounted. Checking access rules for updates.");
                    try {
                        initializeAccessControl( SmartcardService._SD_TERMINAL, null );
                    } catch (Exception e) {

                    }
                }
            }
        };
        context.registerReceiver(mReceiver, intentFilter);
    }

    /**
     * Initalizes Access Control.
     * At least the refresh tag is read and if it differs to the previous one (e.g. is null) the all
     * access rules are read.
     *
     * @param se
     */
    public synchronized void initializeAccessControl( String se, ISmartcardServiceCallback callback ) {
        Log.i(_TAG, "Initializing Access Control");

        if( callback == null ) {
            callback = new ISmartcardServiceCallback.Stub(){};
        }

        Collection<ITerminal>col = mTerminals.values();
        Iterator<ITerminal> iter = col.iterator();
        while(iter.hasNext()){
            ITerminal terminal = iter.next();
            if( terminal == null ){

                continue;
            }

            try {
                if( se == null || terminal.getName().startsWith(se)) {
                    if( terminal.isCardPresent() ) {
                        Log.i(_TAG, "Initializing Access Control for " + terminal.getName());
                        terminal.initializeAccessControl(true, callback);
                    }
                }
            } catch (CardException e) {

            }
        }
        col = this.mAddOnTerminals.values();
        iter = col.iterator();
        while(iter.hasNext()){
            ITerminal terminal = iter.next();
            if( terminal == null ){

                continue;
            }

            try {
                if( se == null || terminal.getName().startsWith(se)) {
                    if(terminal.isCardPresent() ) {
                        Log.i(_TAG, "Initializing Access Control for " + terminal.getName());
                        terminal.initializeAccessControl(true, callback);
                    } else {
                        Log.i(_TAG, "NOT initializing Access Control for " + terminal.getName() + " SE not present.");
                    }
                }
            } catch (CardException e) {

            }
        }
    }

    public void onDestroy() {
        Log.v(_TAG, " smartcard service onDestroy ...");
        for (ITerminal terminal : mTerminals.values())
            terminal.closeChannels();
        for (ITerminal terminal : mAddOnTerminals.values())
            terminal.closeChannels();

        Log.v(_TAG, Thread.currentThread().getName()
                + " ... smartcard service onDestroy");
    }

    private ITerminal getTerminal(String reader, SmartcardError error) {
        if (reader == null) {
            setError(error, NullPointerException.class, "reader must not be null");
            return null;
        }
        ITerminal terminal = mTerminals.get(reader);
        if (terminal == null) {
            terminal = mAddOnTerminals.get(reader);
            if (terminal == null) {
                setError(error, IllegalArgumentException.class, "unknown reader");
            }
        }
        return terminal;
    }

    private String[] createTerminals() {
        createBuildinTerminals();

        Set<String> names = mTerminals.keySet();
        ArrayList<String> list = new ArrayList<String>(names);
        Collections.sort(list);

        // set UICC on the top
        if(list.remove(_UICC_TERMINAL + " - UICC"))
            list.add(0, _UICC_TERMINAL + " - UICC");

        createAddonTerminals();
        names = mAddOnTerminals.keySet();
        for (String name : names) {
            if (!list.contains(name)) {
                list.add(name);
            }
        }

        return list.toArray(new String[list.size()]);
    }

    private String[] updateTerminals() {
        Set<String> names = mTerminals.keySet();
        ArrayList<String> list = new ArrayList<String>(names);
        Collections.sort(list);

        // set UICC on the top
        if(list.remove(_UICC_TERMINAL + " - UICC"))
            list.add(0, _UICC_TERMINAL + " - UICC");

        updateAddonTerminals();
        names = mAddOnTerminals.keySet();
        for (String name : names) {
            if (!list.contains(name)) {
                list.add(name);
            }
        }

        return list.toArray(new String[list.size()]);
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private void createBuildinTerminals() {
        Class[] types = new Class[] {
            Context.class
        };
        Object[] args = new Object[] {
            this
        };
        Object[] classes = getBuildinTerminalClasses();
        for (Object clazzO : classes) {
            try {
                Class clazz = (Class) clazzO;
                Constructor constr = clazz.getDeclaredConstructor(types);
                ITerminal terminal = (ITerminal) constr.newInstance(args);
                mTerminals.put(terminal.getName(), terminal);
                Log.v(_TAG, Thread.currentThread().getName() + " adding "
                        + terminal.getName());
            } catch (Throwable t) {
                Log.e(_TAG, Thread.currentThread().getName()
                        + " CreateReaders Error: "
                        + ((t.getMessage() != null) ? t.getMessage() : "unknown"));
            }
        }
    }

    private void createAddonTerminals() {
        String[] packageNames = AddonTerminal.getPackageNames(this);
        for (String packageName : packageNames) {
            try {
                String apkName = getPackageManager().getApplicationInfo(packageName, 0).sourceDir;
                DexFile dexFile = new DexFile(apkName);
                Enumeration<String> classFileNames = dexFile.entries();
                while (classFileNames.hasMoreElements()) {
                    String className = classFileNames.nextElement();
                    if (className.endsWith("Terminal")) {
                        ITerminal terminal = new AddonTerminal(this, packageName, className);
                        mAddOnTerminals.put(terminal.getName(), terminal);
                        Log.v(_TAG, Thread.currentThread().getName() + " adding "
                                + terminal.getName());
                    }
                }
            } catch (Throwable t) {
                Log.e(_TAG, Thread.currentThread().getName()
                        + " CreateReaders Error: "
                        + ((t.getMessage() != null) ? t.getMessage() : "unknown"));
            }
        }
    }

    private void updateAddonTerminals() {
        Set<String> names = mAddOnTerminals.keySet();
        ArrayList<String> namesToRemove = new ArrayList<String>();
        for (String name : names) {
            ITerminal terminal = mAddOnTerminals.get(name);
            if (!terminal.isConnected()) {
                namesToRemove.add(terminal.getName());
            }
        }
        for (String name : namesToRemove) {
            mAddOnTerminals.remove(name);
        }

        String[] packageNames = AddonTerminal.getPackageNames(this);
        for (String packageName : packageNames) {
            try {
                String apkName = getPackageManager().getApplicationInfo(packageName, 0).sourceDir;
                DexFile dexFile = new DexFile(apkName);
                Enumeration<String> classFileNames = dexFile.entries();
                while (classFileNames.hasMoreElements()) {
                    String className = classFileNames.nextElement();
                    if (className.endsWith("Terminal")) {
                        ITerminal terminal = new AddonTerminal(this, packageName, className);
                        if (!mAddOnTerminals.containsKey(terminal.getName())) {
                            mAddOnTerminals.put(terminal.getName(), terminal);
                            Log.v(_TAG, Thread.currentThread().getName()
                                    + " adding " + terminal.getName());
                        }
                    }
                }

            } catch (Throwable t) {
                Log.e(_TAG, Thread.currentThread().getName()
                        + " CreateReaders Error: "
                        + ((t.getMessage() != null) ? t.getMessage() : "unknown"));
            }
        }
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private Object[] getBuildinTerminalClasses() {
        ArrayList classes = new ArrayList();
        try {
            String packageName = "org.simalliance.openmobileapi.service";
            String apkName = getPackageManager().getApplicationInfo(packageName, 0).sourceDir;
            DexClassLoader dexClassLoader = new DexClassLoader(apkName, getApplicationContext().getFilesDir().getAbsolutePath(), null, getClass()
                    .getClassLoader());

            Class terminalClass = Class.forName("org.simalliance.openmobileapi.service.Terminal", true, dexClassLoader);
            if (terminalClass == null) {
                return classes.toArray();
            }

            DexFile dexFile = new DexFile(apkName);
            Enumeration<String> classFileNames = dexFile.entries();
            while (classFileNames.hasMoreElements()) {
                String className = classFileNames.nextElement();
                Class clazz = Class.forName(className);
                Class superClass = clazz.getSuperclass();
                if (superClass != null && superClass.equals(terminalClass)
                        && !className.equals("org.simalliance.openmobileapi.service.AddonTerminal")) {
                    classes.add(clazz);
                }
            }
        } catch (Throwable exp) {
            // nothing to to
        }
        return classes.toArray();
    }

    public String getProcessNameFromPid(int pid) {
        ActivityManager am = (ActivityManager) getSystemService(Activity.ACTIVITY_SERVICE);
        List<ActivityManager.RunningAppProcessInfo> appInfoList = am.getRunningAppProcesses();
        for (ActivityManager.RunningAppProcessInfo appInfo : appInfoList) {
            if (appInfo.pid == pid) {
                return appInfo.processName;
            }
        }
        throw new AccessControlException("CallerPackageName can not be determined");
    }

    /**
     * The smartcard service interface implementation.
     */
    private final ISmartcardService.Stub mSmartcardBinder = new ISmartcardService.Stub() {

        @Override
        public String[] getReaders(SmartcardError error) throws RemoteException {
            clearError(error);
            Log.v(_TAG, "getReaders()");
            return updateTerminals();
        }

        @Override
        public ISmartcardServiceReader getReader(String reader,
                SmartcardError error) throws RemoteException {
            clearError(error);
            Terminal terminal = (Terminal)getTerminal(reader, error);
            if( terminal != null ){
                return terminal.new SmartcardServiceReader(SmartcardService.this);
            }
            setError(error, IllegalArgumentException.class, "invalid reader name");
            return null;
        }


        @Override
        public synchronized boolean[] isNFCEventAllowed(
                String reader,
                byte[] aid,
                String[] packageNames,
                ISmartcardServiceCallback callback,
                SmartcardError error)
                        throws RemoteException
        {
            clearError(error);
            try
            {
                if (callback == null) {
                    setError(error, NullPointerException.class, "callback must not be null");
                    return null;
                }
                ITerminal terminal = getTerminal(reader, error);
                if (terminal == null) {
                    return null;
                }
                if (aid == null || aid.length == 0) {
                    aid = new byte[] {
                            0x00, 0x00, 0x00, 0x00, 0x00
                    };
                }
                if (aid.length < 5 || aid.length > 16) {
                     setError(error, IllegalArgumentException.class, "AID out of range");
                     return null;
                }
                if (packageNames == null || packageNames.length == 0) {
                     setError(error, IllegalArgumentException.class, "process names not specified");
                     return null;
                }
                AccessControlEnforcer ac = null;
                if( terminal.getAccessControlEnforcer() == null ) {
                    ac = new AccessControlEnforcer( terminal );
                } else {
                    ac = terminal.getAccessControlEnforcer();
                }
                ac.setPackageManager(getPackageManager());
                ac.initialize(true, callback);
                return ac.isNFCEventAllowed(aid, packageNames, callback );
            } catch (Exception e) {
                setError(error, e);
                Log.v(_TAG, "isNFCEventAllowed Exception: " + e.getMessage() );
                return null;
            }
        }
    };

    /**
     * The smartcard service interface implementation.
     */
    final class SmartcardServiceSession extends ISmartcardServiceSession.Stub {

        private final SmartcardServiceReader mReader;
        /** List of open channels in use of by this client. */
        private final Set<Channel> mChannels = new HashSet<Channel>();

        private final Object mLock = new Object();

        private boolean mIsClosed;

        private byte[] mAtr;

        public SmartcardServiceSession(SmartcardServiceReader reader){
            mReader = reader;
            mAtr = mReader.getAtr();
            mIsClosed = false;
        }

        @Override
        public ISmartcardServiceReader getReader() throws RemoteException {
            return mReader;
        }

        @Override
        public byte[] getAtr() throws RemoteException {
            return mAtr;
        }

        @Override
        public void close(SmartcardError error) throws RemoteException {
            clearError(error);
            if (mReader == null) {
                return;
            }
            try {
                mReader.closeSession(this);
            } catch (CardException e) {
                setError(error,e);
            }
        }

        @Override
        public void closeChannels(SmartcardError error) throws RemoteException {
            synchronized (mLock) {

                Iterator<Channel>iter = mChannels.iterator();

                try {
                    while(iter.hasNext()) {

                        Channel channel = iter.next();

                        if (channel != null && !channel.isClosed()) {
                            try {
                                channel.close();
                            } catch (Exception ignore) {
                            }
                            channel.setClosed();
                        }
                    }
                    mChannels.clear();
                } catch( Exception e ) {


                }
            }
        }

        @Override
        public boolean isClosed() throws RemoteException {

            return mIsClosed;
        }

        @Override
        public ISmartcardServiceChannel openBasicChannel(
                ISmartcardServiceCallback callback, SmartcardError error)
                throws RemoteException {
            return openBasicChannelAid( null, callback, error);
        }

        @Override
        public ISmartcardServiceChannel openBasicChannelAid(byte[] aid,
                ISmartcardServiceCallback callback, SmartcardError error)
                throws RemoteException {
            clearError(error);
            if ( isClosed() ) {
                setError( error, IllegalStateException.class, "session is closed");
                return null;
            }
            if (callback == null) {
                setError(error, NullPointerException.class, "callback must not be null");
                return null;
            }
            if (mReader == null) {
                setError(error, NullPointerException.class, "reader must not be null");
                return null;
            }

            try {
                boolean noAid = false;
                if (aid == null || aid.length == 0) {
                    aid = new byte[] {0x00, 0x00, 0x00, 0x00, 0x00 };
                    noAid = true;
                }

                if (aid.length < 5 || aid.length > 16) {
                    setError(error, IllegalArgumentException.class, "AID out of range");
                    return null;
                }


                String processName = getProcessNameFromPid(Binder.getCallingPid());
                Log.v(_TAG, "Enable access control on basic channel.");
                ChannelAccess channelAccess = mReader.getTerminal().setUpChannelAccess(
                        getPackageManager(),
                        aid,
                        processName,
                        callback );
                Log.v(_TAG, "Access control successfully enabled.");

                channelAccess.setCallingPid(Binder.getCallingPid());



                Log.v(_TAG, "OpenBasicChannel(AID)");
                Channel channel = null;
                if (noAid) {
                    channel = mReader.getTerminal().openBasicChannel(this, callback);
                } else {
                    channel = mReader.getTerminal().openBasicChannel(this, aid, callback);
                }

                channel.setChannelAccess(channelAccess);

                Log.v(_TAG, "Open basic channel success. Channel: " + channel.getChannelNumber() );

                SmartcardServiceChannel basicChannel = channel.new SmartcardServiceChannel(this);
                mChannels.add(channel);
                return basicChannel;

            } catch (Exception e) {
                setError(error, e);
                Log.v(_TAG, "OpenBasicChannel Exception: " + e.getMessage());
                return null;
            }
        }

        @Override
        public ISmartcardServiceChannel openLogicalChannel(byte[] aid,
                ISmartcardServiceCallback callback, SmartcardError error)
                throws RemoteException {
            clearError(error);

            if ( isClosed() ) {
                setError( error, IllegalStateException.class, "session is closed");
                return null;
            }

            if (callback == null) {
                setError(error, NullPointerException.class, "callback must not be null");
                return null;
            }
            if (mReader == null) {
                setError(error, NullPointerException.class, "reader must not be null");
                return null;
            }

            try {
                boolean noAid = false;
                if (aid == null || aid.length == 0) {
                    aid = new byte[] {
                            0x00, 0x00, 0x00, 0x00, 0x00
                    };
                    noAid = true;
                }

                if (aid.length < 5 || aid.length > 16) {
                    setError(error, IllegalArgumentException.class, "AID out of range");
                    return null;
                }


                String processName = getProcessNameFromPid(Binder.getCallingPid());
                Log.v(_TAG, "Enable access control on logical channel.");
                ChannelAccess channelAccess = mReader.getTerminal().setUpChannelAccess(
                        getPackageManager(),
                        aid,
                        processName,
                        callback );
                Log.v(_TAG, "Access control successfully enabled.");
               channelAccess.setCallingPid(Binder.getCallingPid());


                Log.v(_TAG, "OpenLogicalChannel");
                Channel channel = null;
                if (noAid) {
                    channel = mReader.getTerminal().openLogicalChannel(this, callback);
                } else {
                    channel = mReader.getTerminal().openLogicalChannel(this, aid, callback);
                }

                channel.setChannelAccess(channelAccess);

                Log.v(_TAG, "Open logical channel successfull. Channel: " + channel.getChannelNumber());
                SmartcardServiceChannel logicalChannel = channel.new SmartcardServiceChannel(this);
                mChannels.add(channel);
                return logicalChannel;
            } catch (Exception e) {
                setError(error, e);
                Log.v(_TAG, "OpenLogicalChannel Exception: " + e.getMessage());
                return null;
            }
        }

        void setClosed(){
            mIsClosed = true;

        }

        /**
         * Closes the specified channel. <br>
         * After calling this method the session can not be used for the
         * communication with the secure element any more.
         *
         * @param hChannel the channel handle obtained by an open channel command.
         */
        void removeChannel(Channel channel) {
            if (channel == null) {
                return;
            }
            mChannels.remove(channel);
        }
    }

}
