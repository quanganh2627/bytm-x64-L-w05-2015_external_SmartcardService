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

package org.simalliance.openmobileapi.service.terminals;

import android.content.Context;
import org.simalliance.openmobileapi.service.CardException;
import org.simalliance.openmobileapi.service.Terminal;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.SystemProperties;

import com.android.internal.telephony.IOEMHook;
import com.android.internal.telephony.ITelephony;
import com.android.internal.telephony.TelephonyProperties;

import java.util.MissingResourceException;
import java.util.NoSuchElementException;

public class UiccTerminal extends Terminal {

    private ITelephony manager = null;
    private IOEMHook oemManager = null;

    private int[] channelId = new int[4];

    public UiccTerminal(Context context) {
        super("SIM: UICC", context);

        try {
            manager = ITelephony.Stub.asInterface(ServiceManager
                            .getService(Context.TELEPHONY_SERVICE));
            oemManager = IOEMHook.Stub.asInterface(ServiceManager
                            .getService("oemhook"));
        } catch (Exception ex) {
        }

        for (int i = 0; i < channelId.length; i++)
            channelId[i] = 0;
    }

    public boolean isCardPresent() throws CardException {
        String prop = SystemProperties.get(TelephonyProperties.PROPERTY_SIM_STATE);
        if ("READY".equals(prop)) {
            return true;
        }
        return false;
    }

    @Override
    public byte[] getAtr() {
        try {
            String response = oemManager.getATR();

            return StringToByteArray(response);
        } catch (RemoteException ex) {
            return null;
        }
    }

    @Override
    protected void internalConnect() throws CardException {
        if (manager == null || oemManager == null) {
            throw new CardException("Cannot connect to Telephony Service or OEMHook Service");
        }
        mIsConnected = true;
    }

    @Override
    protected void internalDisconnect() throws CardException {
    }

    private byte[] StringToByteArray(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return b;
    }

    private String ByteArrayToString(byte[] b, int start) {
        StringBuffer s = new StringBuffer();
        for (int i = start; i < b.length; i++) {
            s.append(Integer.toHexString(0x100 + (b[i] & 0xff)).substring(1));
        }
        return s.toString();
    }

    @Override
    protected byte[] internalTransmit(byte[] command) throws CardException {
        int cla = command[0] & 0xff;
        int ins = command[1] & 0xff;
        int p1 = command[2] & 0xff;
        int p2 = command[3] & 0xff;
        int p3 = -1;
        if (command.length > 4) {
            p3 = command[4] & 0xff;
        }
        String data = null;
        if (command.length > 5) {
            data = ByteArrayToString(command, 5);
        }

// FIXME:(SNI) Use Basic Channel only
//        int channelNumber = cla & 0xf;
//
//        if (channelNumber == 0) {
            try {
                String response = manager.transmitIccBasicChannel(cla, ins, p1, p2, p3, data);
                return StringToByteArray(response);
            } catch (Exception ex) {
                throw new CardException("transmit command failed");
            }
//        } else {
//            if ((channelNumber > 0) && (channelId[channelNumber] == 0)) {
//                throw new CardException("channel not open");
//            }
//
//            try {
//                String response = manager.transmitIccLogicalChannel(cla & 0xf0, ins,
//                        channelId[channelNumber], p1, p2, p3, data);
//                return StringToByteArray(response);
//            } catch (Exception ex) {
//                throw new CardException("transmit command failed");
//            }
//        }
    }

    @Override
    protected int internalOpenLogicalChannel() throws Exception {

		byte[] manageChannelCommand = new byte[] { 0x00, 0x70, 0x00, 0x00, 0x01 };
		byte[] rsp = transmit(manageChannelCommand, 2, 0x9000, 0, "MANAGE CHANNEL");
		if (rsp.length == 2 && ((rsp[0] == (byte)0x6D || rsp[0] == (byte)0x6E) && rsp[1] == (byte)0x00))
			throw new NoSuchElementException("logical channels not supported");
		if ((rsp.length == 2) && ((rsp[0] == (byte)0x68) && (rsp[1] == (byte)0x81)))
			throw new NoSuchElementException("logical channels not supported");
		if (rsp.length == 2 && (rsp[0] == (byte)0x6A && rsp[1] == (byte)0x81))
			throw new MissingResourceException("no free channel available", "", "");
		if (rsp.length != 3)
			throw new MissingResourceException("unsupported MANAGE CHANNEL response data", "", "");
		int channelNumber = rsp[0] & 0xFF;
		if (channelNumber == 0 || channelNumber > 19)
			throw new MissingResourceException("invalid logical channel number returned", "", "");

		return channelNumber;
    }

    @Override
    protected int internalOpenLogicalChannel(byte[] aid) throws Exception {
		if(aid == null)
			throw new NullPointerException("aid must not be null");

		byte[] manageChannelCommand = new byte[] { 0x00, 0x70, 0x00, 0x00, 0x01 };
		byte[] rsp = transmit(manageChannelCommand, 2, 0x9000, 0, "MANAGE CHANNEL");

		if (rsp.length == 2 && ((rsp[0] == (byte)0x6D || rsp[0] == (byte)0x6E) && rsp[1] == (byte)0x00))
			throw new NoSuchElementException("logical channels not supported");

		if ((rsp.length == 2) && ((rsp[0] == (byte)0x68) && (rsp[1] == (byte)0x81)))
			throw new NoSuchElementException("logical channels not supported");

		if (rsp.length == 2 && (rsp[0] == (byte)0x6A && rsp[1] == (byte)0x81))
			throw new MissingResourceException("no free channel available", "", "");

		if (rsp.length != 3)
			throw new MissingResourceException("unsupported MANAGE CHANNEL response data", "", "");

		int channelNumber = rsp[0] & 0xFF;
		if (channelNumber == 0 || channelNumber > 19)
			throw new MissingResourceException("invalid logical channel number returned", "", "");

		byte[] selectCommand = new byte[aid.length + 6];
		selectCommand[0] = (byte) channelNumber;
		if (channelNumber > 3)
			selectCommand[0] |= 0x40;
		selectCommand[1] = (byte) 0xA4;
		selectCommand[2] = 0x04;
		selectCommand[4] = (byte) aid.length;
		System.arraycopy(aid, 0, selectCommand, 5, aid.length);
		try
		{
			transmit(selectCommand, 2, 0x9000, 0xFFFF, "SELECT");
		}
		catch(CardException exp)
		{
			internalCloseLogicalChannel(channelNumber);
			throw new NoSuchElementException(exp.getMessage());
		}

		return channelNumber;
    }

    @Override
    protected void internalCloseLogicalChannel(int channelNumber) throws CardException {
		if (channelNumber > 0) {
			byte cla = (byte) channelNumber;
			if (channelNumber > 3) {
				cla |= 0x40;
			}
			byte[] manageChannelClose = new byte[] { cla, 0x70, (byte) 0x80, (byte) channelNumber };
			transmit(manageChannelClose, 2, 0x9000, 0xFFFF, "MANAGE CHANNEL");
		}
    }
}
