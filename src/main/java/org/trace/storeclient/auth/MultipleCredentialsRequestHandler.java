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

import android.content.Intent;
import android.support.annotation.NonNull;
import android.util.Log;

import com.google.android.gms.auth.api.Auth;
import com.google.android.gms.auth.api.credentials.Credential;
import com.google.android.gms.auth.api.credentials.IdentityProviders;
import com.google.android.gms.auth.api.signin.GoogleSignInAccount;
import com.google.android.gms.auth.api.signin.GoogleSignInResult;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.OptionalPendingResult;
import com.google.android.gms.common.api.ResultCallback;

import org.trace.storeclient.TraceAuthenticationManager;


/**
 * The MultipleCredentialsRequestHandler was designed to ease the handling of different operations,
 * when multiple credentials are currently being stored by the device's smart lock. Namely, the following
 * operations are supported:
 * <br>
 *     <ul>
 *         <li>Sign-in</li>
 *         <li>Credential Removal</li>
 *         <li>Credential Loading</li>
 *         <li>Credential Storing</li>
 *     </ul>
 */
public class MultipleCredentialsRequestHandler {

    private static final String TAG = "Auth";

    private GoogleApiClient mGoogleApiClient;
    private TraceAuthenticationManager mAuthManager;

    public MultipleCredentialsRequestHandler(GoogleApiClient googleApiClient, TraceAuthenticationManager manager){
        mAuthManager = manager;
        mGoogleApiClient = googleApiClient;
    }

    public int onRequestResult(int requestCode, int resultCode, Intent data){
        if(resultCode != -1) {
            Log.e(TAG, "Failed at code " + requestCode + " with result code "+resultCode);
            return -1;
        }

        switch (requestCode){
            case TraceAuthenticationManager.RC_SIGN_IN:
                googleSignIn(data);
                break;
            case TraceAuthenticationManager.RC_LOAD:
                loginFromStoredCredentials(data);
                break;
            case TraceAuthenticationManager.RC_SAVE:
                Log.d(TAG, "TODO: Save - dont know what to do");
                break;
            case TraceAuthenticationManager.RC_DELETE:
                removeCredential(data);
                break;
            default:
                Log.e(TAG, "Unknown request code "+requestCode);
        }

        return requestCode;
    }

    private void googleSignIn(Intent data){
        GoogleSignInResult result = Auth.GoogleSignInApi.getSignInResultFromIntent(data);

        if (result.isSuccess()) {
            GoogleSignInAccount acct = result.getSignInAccount();
            mAuthManager.login(acct);
        }else{
            Log.e(TAG, "Failed to handle sign in request");
        }
    }
    
    private void loginFromStoredCredentials(Intent data){

        Credential credential = data.getParcelableExtra(Credential.EXTRA_KEY);
        String accountType = credential.getAccountType();

        if(accountType == null){ //Login from stored password
            mAuthManager.login(credential.getId(), credential.getPassword());
        }else if(accountType.equals(IdentityProviders.GOOGLE)){

            //Login with google - Silent Login
            OptionalPendingResult<GoogleSignInResult> opr =
                    Auth.GoogleSignInApi.silentSignIn(mGoogleApiClient);

            opr.setResultCallback(new ResultCallback<GoogleSignInResult>() {
                @Override
                public void onResult(@NonNull GoogleSignInResult googleSignInResult) {


                    mAuthManager.login(googleSignInResult.getSignInAccount());
                }
            });
        }else{
            Log.e(TAG, "Unsupported provider '"+accountType+"'");
        }
    }

    private void removeCredential(Intent data){
        Credential credential = data.getParcelableExtra(Credential.EXTRA_KEY);
        mAuthManager.removeCredential(credential);
    }
}
