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
import android.widget.Toast;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.trace.storeclient.R;
import org.trace.storeclient.StoreClientConstants;
import org.trace.storeclient.TraceAuthenticationManager;

public class AuthenticationRenewalListener extends BroadcastReceiver {

    private Context mContext;
    private TraceAuthenticationManager mAuthManager;

    public AuthenticationRenewalListener(Context context, TraceAuthenticationManager manager){
        mContext = context;
        mAuthManager = manager;
    }

    public static IntentFilter getAuthenticationRenewalFilter(){
        IntentFilter filter = new IntentFilter();
        filter.addAction(StoreClientConstants.TOKEN_EXPIRED_ACTION);
        return filter;
    }


    public static Intent getFailedRemoteOperationIntent(JsonObject operation){
        return new Intent(StoreClientConstants.TOKEN_EXPIRED_ACTION)
                .putExtra(StoreClientConstants.FAILED_OPERATION_KEY, operation.toString());
    }

    @Override
    public void onReceive(Context context, Intent intent) {

        mAuthManager.login();
        JsonParser parser = new JsonParser();

        if(intent.hasExtra(StoreClientConstants.FAILED_OPERATION_KEY)){
            JsonObject failedOperation = (JsonObject)parser.parse(intent.getStringExtra(StoreClientConstants.FAILED_OPERATION_KEY));

            if(!avoidOperation(failedOperation.get("endpoint").getAsString())){
                Toast.makeText(mContext, mContext.getString(R.string.failed_remote_operation), Toast.LENGTH_LONG).show();
            }
        }
    }

    private boolean avoidOperation(String urlEndpoint){

        return  urlEndpoint.equals("/auth/session/open");
    }
    private void parseOperation(String urlEndpoint){
        switch (urlEndpoint){
            case "/auth/session/open":
                break;
            default:
                return;
        }
    }
}
