/*
 * Copyright (c) 2016 Rodrigo Lourenço, Miguel Costa, Paulo Ferreira, João Barreto @  INESC-ID.
 *
 * This file is part of TRACE.
 *
 * TRACE is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * TRACE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with TRACE.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.trace.storeclient.auth;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;

import org.trace.storeclient.StoreClientConstants;


public class LoginBroadcastListener extends BroadcastReceiver {

    Class onSuccess, onFail;

    public LoginBroadcastListener(Class OnSuccessActivity, Class OnFailActivity){
        onSuccess = OnSuccessActivity;
        onFail = OnFailActivity;
    }

    public static IntentFilter getLoginIntentFilter(){
        IntentFilter filter = new IntentFilter();
        filter.addAction(StoreClientConstants.LOGIN_ACTION);
        return filter;
    }



    @Override
    public void onReceive(Context context, Intent intent) {

        if(intent.hasExtra(StoreClientConstants.SUCCESS_LOGIN_EXTRA)
                && intent.getBooleanExtra(StoreClientConstants.SUCCESS_LOGIN_EXTRA, false)) {

            Intent mainActivity = new Intent(context, onSuccess);
            context.startActivity(mainActivity);
        }else{
            Intent failedLogin = new Intent(context, onFail);
            failedLogin.putExtra(StoreClientConstants.LOGIN_ERROR_MSG_EXTRA, intent.getStringExtra(StoreClientConstants.LOGIN_ERROR_MSG_EXTRA));
            context.startActivity(failedLogin);
        }
    }
}
