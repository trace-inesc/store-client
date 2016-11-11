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

package org.trace.storeclient;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.IntentSender;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.support.annotation.NonNull;
import android.util.Log;

import com.google.android.gms.auth.api.Auth;
import com.google.android.gms.auth.api.credentials.Credential;
import com.google.android.gms.auth.api.credentials.CredentialRequest;
import com.google.android.gms.auth.api.credentials.CredentialRequestResult;
import com.google.android.gms.auth.api.credentials.IdentityProviders;
import com.google.android.gms.auth.api.signin.GoogleSignInAccount;
import com.google.android.gms.auth.api.signin.GoogleSignInOptions;
import com.google.android.gms.auth.api.signin.GoogleSignInResult;
import com.google.android.gms.auth.api.signin.GoogleSignInStatusCodes;
import com.google.android.gms.common.api.CommonStatusCodes;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.OptionalPendingResult;
import com.google.android.gms.common.api.ResultCallback;
import com.google.android.gms.common.api.Status;

import org.trace.storeclient.exceptions.AuthTokenIsExpiredException;
import org.trace.storeclient.exceptions.InvalidAuthCredentialsException;
import org.trace.storeclient.exceptions.LoginFailedException;
import org.trace.storeclient.exceptions.NetworkConnectivityRequiredException;
import org.trace.storeclient.exceptions.RemoteTraceException;
import org.trace.storeclient.exceptions.UnableToPerformLogin;
import org.trace.storeclient.exceptions.UnsupportedIdentityProvider;
import org.trace.storeclient.exceptions.UserIsNotLoggedException;
import org.trace.storeclient.remote.HttpClient;

import java.math.BigInteger;
import java.security.SecureRandom;

//TODO: make this a service
public class TraceAuthenticationManager {

    private final String TAG = "Auth";

    private Context mContext;
    private static TraceAuthenticationManager MANAGER = null;
    private HttpClient mHttpClient;
    private GrantType mCurrentGrantType = GrantType.none;
    private String mAuthenticationToken = null;

    private ConnectivityManager mConnectivityManager;

    private TraceAuthenticationManager(Context context, GoogleApiClient credentialsApiClient){
        mContext = context;
        mHttpClient = new HttpClient(context);
        mCredentialsApiClient = credentialsApiClient;
        mConnectivityManager = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
    }

    /**
     * Creates or fetches an instance of the TraceAuthenticationManager with the provided Context
     * and GoogleApiClient.
     *
     * @param context The current activity context.
     * @param credentialsApiClient A valid GoogleApiClient
     *
     * @return Instance of the TraceAuthenticationManager
     */
    public static TraceAuthenticationManager getAuthenticationManager(Context context, GoogleApiClient credentialsApiClient){

        synchronized (TraceAuthenticationManager.class){
            if(MANAGER == null)
                MANAGER = new TraceAuthenticationManager(context, credentialsApiClient);
            else
                MANAGER.updateContext(context, credentialsApiClient);
        }

        return MANAGER;
    }

    private void updateContext(Context context, GoogleApiClient credentialsApiClient){
        this.mContext = context;
        this.mCredentialsApiClient = credentialsApiClient;
        this.mConnectivityManager = (ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
    }

    /**
     * This method attempts to login the user, but only if the the device has a network connection.
     * <br>
     * This operation is performed <b>asynchronously</b>, results are broadcasted and are identifiable
     * by TraceTracking.store.LOGIN_ACTION. The results can therefore be caught by a BroadcastReceiver,
     * however its recommended the use of the LoginBroadcastListener, which was specifically designed
     * for that purpose.
     *
     * @see org.trace.storeclient.auth.LoginBroadcastListener
     */
    public void login() {

        //Only attempt login if the network is connected
        boolean attemptLogin = isNetworkConnected();


        if(mCurrentCredential!=null) //a) Check if there is any active credential and use it to login
            login(mCurrentCredential);
        else //b) Attempt to login from one of the stored credentials
            retrieveCredentials(attemptLogin);
    }

    private void login(Credential credential){
        String accountType = credential.getAccountType();

        if(accountType == null) { //password-based accout, i.e. native trace
            login(credential.getId(), credential.getPassword());
        }else{
            switch (accountType){
                case IdentityProviders.GOOGLE:
                    performSilentGoogleLogin();
                    break;
                default:
                    throw new UnsupportedIdentityProvider(accountType);
            }
        }
    }

    /**
     * Logs the user out. <b>Note: </b>Currently this method does nothing, except clean the
     * authentication token on the application level.
     */
    public void logout(){
        switch (mCurrentGrantType){
            case trace:
                //TODO
            case google:
                //TODO
            case none:
            default:

        }

        clearAuthenticationToken();
    }

    /* Authentication Token Management
    /* Authentication Token Management
    /* Authentication Token Management
     ***********************************************************************************************
     ***********************************************************************************************
     ***********************************************************************************************
     */

    public static final String AUTH_TOKEN = "auth_token";
    private static final String AUTH_SETTINGS_KEY = "auth_settings";

    private void storeAuthenticationToken(String token){
        SharedPreferences.Editor editor =
                mContext.getSharedPreferences(AUTH_SETTINGS_KEY, Context.MODE_PRIVATE).edit();

        editor.putString(AUTH_TOKEN, token);
        editor.commit();
    }

    /**
     * Returns the current authentication token, which is required to perform remote security sensitive
     * operations.
     *
     * @return The authentication token
     * @throws UserIsNotLoggedException if the user is not logged in, i.e. is there is no authentication token.
     */
    public String getAuthenticationToken() throws UserIsNotLoggedException {

        String authToken = mContext.getSharedPreferences(AUTH_SETTINGS_KEY, Context.MODE_PRIVATE)
                .getString(AUTH_TOKEN, "");

        if(authToken.isEmpty())
            throw new UserIsNotLoggedException();
        else
            return authToken;
    }

    /**
     * Clears the current authentication token. It is important to mention that this is only performed
     * on the application side.
     */
    public void clearAuthenticationToken(){
        SharedPreferences.Editor editor =
                mContext.getSharedPreferences(AUTH_SETTINGS_KEY, Context.MODE_PRIVATE).edit();

        editor.remove(AUTH_TOKEN);
        editor.commit();
    }

    /* TRACE Native Login
    /* TRACE Native Login
    /* TRACE Native Login
     ***********************************************************************************************
     ***********************************************************************************************
     ***********************************************************************************************
     */

    /**
     * Logs a user through Trace's native login, i.e. with a previously registered TRACE account. This
     * TRACE account is identifiable by a user identifier and password pair.
     * <br>
     * This operation is performed <b>asynchronously</b>, results are broadcasted and are identifiable
     * by TraceTracking.store.LOGIN_ACTION. The results can therefore be caught by a BroadcastReceiver,
     * however its recommended the use of the LoginBroadcastListener, which was specifically designed
     * for that purpose.
     *
     * @param username The user identifier (either username or email)
     * @param password The user's password.
     * @throws InvalidAuthCredentialsException If the provided credentials are not valid.
     *
     * @see org.trace.storeclient.auth.LoginBroadcastListener
     */
    public void login(final String username, final String password){

        Log.i(TAG, "Native login as "+username);

        if(username == null || username.isEmpty()
                || password == null || password.isEmpty()) {
            Log.i(TAG, "The provided credentials are empty or null.");
            return;
        }

        new Thread(new Runnable() {
            @Override
            public void run() {

                boolean success = false;
                String authToken, error = "";

                try {

                    authToken = mHttpClient.login(username, password);

                    mAuthenticationToken = authToken;
                    storeAuthenticationToken(authToken);

                    Log.d(TAG, "Successfully logged in " + username + ", token is {" + authToken + "}");

                    storeTraceNativeCredentials(username, password);

                    success = true;

                } catch (UnableToPerformLogin | LoginFailedException e) {
                    e.printStackTrace();
                    error = e.getMessage();
                }catch ( InvalidAuthCredentialsException e){
                    removeCredential(mCurrentCredential);
                }

                mCurrentGrantType = GrantType.trace;

                //Broadcast the results of the login operation
                mContext.sendBroadcast(getFailedLoginIntent(success, error));
            }
        }).start();

    }

    /* Google Federated Login
    /* Google Federated Login
    /* Google Federated Login
     ***********************************************************************************************
     ***********************************************************************************************
     ***********************************************************************************************
     */

    /**
     * Logs a user in through a federated login, more specifically, through Google's login API.
     * @param account A GoogleSignInAccount
     */
    public void login(final GoogleSignInAccount account){

        Log.i(TAG, "Google login as "+account.getDisplayName());

        final String idToken = account.getIdToken();

        if(idToken == null || idToken.isEmpty()) {
            Log.i(TAG, "The provided credentials are empty or null.");
            return;
        }

        new Thread(new Runnable() {
            @Override
            public void run() {

                boolean success = false;
                String authToken, error = "";

                try {

                    authToken = mHttpClient.federatedLogin(idToken);

                    mAuthenticationToken = authToken;
                    storeAuthenticationToken(authToken);

                    Log.d(TAG, "Successfully logged with grant google, token is {" + authToken + "}");

                    storeGoogleCredentials(account);

                    mCurrentGrantType = GrantType.google;
                    success = true;

                } catch (UnableToPerformLogin | LoginFailedException | InvalidAuthCredentialsException e) {
                    e.printStackTrace();
                    error = e.getMessage();
                }

                //Broadcast the results of the login operation
                mContext.sendBroadcast(getFailedLoginIntent(success, error));
            }
        }).start();
    }



    /* SmartLock - Credential Storage
    /* SmartLock - Credential Storage
    /* SmartLock - Credential Storage
     ***********************************************************************************************
     ***********************************************************************************************
     ***********************************************************************************************
     */

    private Credential mCurrentCredential;
    private GoogleApiClient mCredentialsApiClient;

    public static final int RC_SAVE     = 0;
    public static final int RC_LOAD     = 1;
    public static final int RC_SIGN_IN  = 2;
    public static final int RC_DELETE   = 3;

    private void storeTraceNativeCredentials(String username, String password){

        Credential credential = new Credential.Builder(username)
                                    .setPassword(password)
                                    .build();

        storeGenericCredential(credential);
    }

    private void storeGoogleCredentials(GoogleSignInAccount account){
        Credential credential = new Credential.Builder(account.getEmail())
                .setAccountType(IdentityProviders.GOOGLE)
                .setName(account.getDisplayName())
                .setProfilePictureUri(account.getPhotoUrl())
                .build();


        storeGenericCredential(credential);
    }

    private void storeGenericCredential(Credential credential){

        if(!mCredentialsApiClient.isConnected()){
            Log.e(TAG, "GoogleApiClient is not yet connected.");
            return;
        }


        //Testing
        mCurrentCredential = credential;

        Auth.CredentialsApi.save(mCredentialsApiClient, credential).setResultCallback(
                new ResultCallback<Status>() {
                    @Override
                    public void onResult(@NonNull Status status) {
                        if (status.isSuccess())
                            Log.d(TAG, "SAVE: OK");
                        else {

                            if (status.hasResolution()) {
                                try {
                                    status.startResolutionForResult((Activity) mContext, RC_SAVE);
                                } catch (IntentSender.SendIntentException e) {
                                    e.printStackTrace();
                                }
                            } else {
                                Log.e(TAG, "Failed to save the credentials");
                            }
                        }
                    }
                }
        );
    }

    /* Login Support
    /* Login Support
    /* Login Support
     ***********************************************************************************************
     ***********************************************************************************************
     ***********************************************************************************************
     */
    private void retrieveCredentials(final boolean attemptLogin){
        final CredentialRequest mCredentialRequest = new CredentialRequest.Builder()
                .setPasswordLoginSupported(true)
                .setAccountTypes(IdentityProviders.GOOGLE)
                .build();

        Auth.CredentialsApi.request(mCredentialsApiClient, mCredentialRequest).setResultCallback(
                new ResultCallback<CredentialRequestResult>() {
                    @Override
                    public void onResult(@NonNull CredentialRequestResult credentialRequestResult) {

                        if (credentialRequestResult.getStatus().isSuccess()) {
                            if (attemptLogin)
                                onCredentialRetrievedLogin(credentialRequestResult.getCredential());
                            else
                                mContext.sendBroadcast(getFailedLoginIntent());
                        } else {

                            Status status = credentialRequestResult.getStatus();

                            if (status.getStatusCode() == CommonStatusCodes.RESOLUTION_REQUIRED) {

                                if (attemptLogin) {
                                    try {
                                        status.startResolutionForResult((Activity) mContext, RC_LOAD);
                                    } catch (IntentSender.SendIntentException e) {
                                        e.printStackTrace();
                                    }
                                } else
                                    mContext.sendBroadcast(getSuccessLoginIntent());

                            } else {
                                mContext.sendBroadcast(getFailedLoginIntent());
                            }


                        }
                    }
                }
        );
    }

    private void performSilentGoogleLogin(){
        OptionalPendingResult<GoogleSignInResult> opr =
                Auth.GoogleSignInApi.silentSignIn(mCredentialsApiClient);

        opr.setResultCallback(new ResultCallback<GoogleSignInResult>() {
            @Override
            public void onResult(@NonNull GoogleSignInResult googleSignInResult) {


                Status status = googleSignInResult.getStatus();

                switch (status.getStatusCode()){
                    case CommonStatusCodes.SUCCESS:
                        login(googleSignInResult.getSignInAccount());
                        break;
                    case GoogleSignInStatusCodes.SIGN_IN_REQUIRED:
                        mContext.sendBroadcast(getFailedLoginIntent());

                }
            }
        });
    }

    private void onCredentialRetrievedLogin(Credential credential){
        mCurrentCredential = credential;
        login(credential);
    }

    /* Credential Removal
    /* Credential Removal
    /* Credential Removal
     ***********************************************************************************************
     ***********************************************************************************************
     ***********************************************************************************************
     */

    /**
     * Removes all stored credentials from the smart lock.
     * @throws NetworkConnectivityRequiredException This operation required connectivity in order to be performed.
     */
    public void removeAllStoredCredentials() throws NetworkConnectivityRequiredException {

        if(!isNetworkConnected())
            throw new NetworkConnectivityRequiredException();

        CredentialRequest mCredentialRequest = new CredentialRequest.Builder()
                .setPasswordLoginSupported(true)
                .setAccountTypes(IdentityProviders.GOOGLE)
                .build();

        Auth.CredentialsApi.request(mCredentialsApiClient, mCredentialRequest).setResultCallback(
                new ResultCallback<CredentialRequestResult>() {
                    @Override
                    public void onResult(@NonNull CredentialRequestResult credentialRequestResult) {

                        if(credentialRequestResult.getStatus().isSuccess()) {
                            Log.i(TAG, "DELETE: found credential to remove.");
                            removeCredential(credentialRequestResult.getCredential());
                        }else {


                            Status status = credentialRequestResult.getStatus();

                            if(status.getStatusCode() == CommonStatusCodes.RESOLUTION_REQUIRED){

                                Log.i(TAG, "DELETE: there are several credentials, choosing one...");

                                try {
                                    status.startResolutionForResult((Activity) mContext, RC_DELETE);
                                } catch (IntentSender.SendIntentException e) {
                                    e.printStackTrace();
                                }

                            }else{
                                Log.e(TAG, "DELETE: found no credentials to remove. {"+status.getStatusCode()+"}");
                            }
                        }
                    }
                }
        );
    }


    /**
     * Removes a specific credential from the smart lock.
     * @param credential The credential to be removed.
     */
    public void removeCredential(final Credential credential){
        Auth.CredentialsApi.delete(mCredentialsApiClient, credential).setResultCallback(
                new ResultCallback<Status>() {
                    @Override
                    public void onResult(@NonNull Status status) {

                        String accountType = credential.getAccountType() == null ? "unknown" : credential.getAccountType();

                        if (status.isSuccess()) {
                            Log.i(TAG, "Removed " + accountType);
                        } else
                            Log.e(TAG, "Did not remove " + accountType);
                    }
                }
        );
    }



    /*
     * When user input is required to select a credential, the getStatusCode() method returns
     * RESOLUTION_REQUIRED. In this case, call the status object's startResolutionForResult() method
     * to prompt the user to choose an account.
     */
    private void resolveCredentialResult(Status status, int code){

        if(status.getStatusCode() == CommonStatusCodes.RESOLUTION_REQUIRED){

            try {
                status.startResolutionForResult((Activity) mContext, code);
            } catch (IntentSender.SendIntentException e) {
                e.printStackTrace();
            }

        }else{
            mContext.sendBroadcast(getFailedLoginIntent());
        }
    }


    /* Session Management
    /* Session Management
    /* Session Management
     ***********************************************************************************************
     ***********************************************************************************************
     ***********************************************************************************************
     */
    private String session;
    private boolean isValid;
    private final Object mSessionLock = new Object();

    /**
     * A tracking session is valid if generated on the TRACE server-side.
     * @return True if valid, false otherwise.
     */
    public boolean isValid() { synchronized (mSessionLock){ return isValid; }}

    /**
     * Fetches the current tracking session.
     * @return The tracking session identifier.
     */
    public String getSession() { synchronized (mSessionLock) { return session; }}


    /**
     * Updates the tracking session identifier by requesting a new one to the TRACE server. However,
     * if there is no network connectivity, a random session is generated locally.
     * <br>
     * This is an asynchronous method, therefore it does not return the acquired session identifier.
     */
    public void fetchNewTrackingSession(){

        if(!isNetworkConnected()){
            TRACEStore.Client.setSessionId(generateFakeSessionId(), false);
        }

        synchronized (mSessionLock){
            isValid = false;
            session = "";
        }

        new Thread(new Runnable() {
                @Override
                public void run() {

                    boolean failed = false;
                    String tmpSession;
                    try {

                        tmpSession = mHttpClient.requestTrackingSession(mAuthenticationToken);

                        synchronized (mSessionLock){
                            session = tmpSession;
                            isValid = true;
                            Log.d("SESSION", session);
                            TRACEStore.Client.setSessionId(session, isValid);
                        }

                    } catch (RemoteTraceException e) {
                        e.printStackTrace();
                    } catch (AuthTokenIsExpiredException e) {
                        failed = true;
                        login();
                    }finally {
                        if(failed)
                            fetchNewTrackingSession();
                    }

                }
            }).start();
    }

    /**
     * Clears the current tracking session.
     */
    public void clearSession(){
        synchronized (mSessionLock){
            session = "";
            isValid = false;
        }
    }


    private String generateFakeSessionId(){
        SecureRandom random = new SecureRandom();
        return "local_"+new BigInteger(130, random).toString(16);
    }

    /* Others
    /* Others
    /* Others
     ***********************************************************************************************
     ***********************************************************************************************
     ***********************************************************************************************
     */

    private boolean isNetworkConnected(){
        return mConnectivityManager.getActiveNetworkInfo() != null;
    }


    /* Helpers
    /* Helpers
    /* Helpers
     ***********************************************************************************************
     ***********************************************************************************************
     ***********************************************************************************************
     */

    /**
     * Returns a GoogleSignInOptions object specifically designed for TRACE authentication.
     * @param traceClientId The application's client identifier
     * @return A custom GoogleSignInOption for TRACE authentication.
     */
    public static GoogleSignInOptions getTraceGoogleSignOption(String traceClientId){
        return new GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
                .requestIdToken(traceClientId)
                .requestEmail()
                .build();
    }


    private Intent getSuccessLoginIntent(){
        return new Intent(StoreClientConstants.LOGIN_ACTION)
                .putExtra(StoreClientConstants.SUCCESS_LOGIN_EXTRA, true)
                .putExtra(StoreClientConstants.LOGIN_ERROR_MSG_EXTRA, "");
    }

    private Intent getFailedLoginIntent(){
        return new Intent(StoreClientConstants.LOGIN_ACTION)
                .putExtra(StoreClientConstants.SUCCESS_LOGIN_EXTRA, false)
                .putExtra(StoreClientConstants.LOGIN_ERROR_MSG_EXTRA, "First time login");
    }

    private Intent getFailedLoginIntent(boolean success, String error){
        return new Intent(StoreClientConstants.LOGIN_ACTION)
                .putExtra(StoreClientConstants.SUCCESS_LOGIN_EXTRA, success)
                .putExtra(StoreClientConstants.LOGIN_ERROR_MSG_EXTRA, error);
    }

    public enum GrantType {
        google,
        trace,
        none
    }
}
