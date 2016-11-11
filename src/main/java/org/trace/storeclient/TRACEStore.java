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


import android.app.IntentService;
import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.util.Log;
import android.widget.Toast;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.trace.storeclient.exceptions.AuthTokenIsExpiredException;
import org.trace.storeclient.exceptions.AuthenticationTokenNotSetException;
import org.trace.storeclient.exceptions.RemoteTraceException;
import org.trace.storeclient.exceptions.UnableToSubmitTrackTokenExpiredException;
import org.trace.storeclient.remote.HttpClient;

import java.math.BigInteger;
import java.security.SecureRandom;

//TODO: Tratamento de AuthTokenExpired
public class TRACEStore extends IntentService{

    private final String LOG_TAG = this.getClass().getSimpleName();

    private final HttpClient mHttpClient;

    public TRACEStore() {
        super("TRACEStore");
        this.mHttpClient = new HttpClient(this);
    }


    @Override
    protected void onHandleIntent(Intent intent) {

        intent.hasExtra(StoreClientConstants.OPERATION_KEY);

        Operations op;
        try {
            op = Operations.valueOf(intent.getStringExtra(StoreClientConstants.OPERATION_KEY));
        }catch (NullPointerException e){
            Log.e(LOG_TAG, "Un-parseable operation");
            return;
        }

        switch (op){
            case submitTrack:
                performSubmitTrack(intent);
                break;
            case initiateSession:

                try {
                    performInitiateSession(intent);
                } catch (RemoteTraceException e) {
                    e.printStackTrace();
                }

                break;

            default:
                Log.e(LOG_TAG, "Unknown operation "+op);
        }
    }

    /* Tracking Session Management
    /* Tracking Session Management
    /* Tracking Session Management
     ***********************************************************************************************
     ***********************************************************************************************
     ***********************************************************************************************
     */

    private String extractAuthenticationToken(Intent data){
        if(!data.hasExtra(StoreClientConstants.AUTH_TOKEN_EXTRA))
            throw new AuthenticationTokenNotSetException();

        return data.getStringExtra(StoreClientConstants.AUTH_TOKEN_EXTRA);
    }

    public void performInitiateSession(Intent intent) throws RemoteTraceException {

        Log.d(LOG_TAG, "Attempting session acquisition...");

        String session = "";
        String authToken = extractAuthenticationToken(intent);
        boolean isValid = false;

        try {

            session = mHttpClient.requestTrackingSession(authToken);
            isValid = true;

        } catch (RemoteTraceException e) {
            Log.e(LOG_TAG, e.getMessage());
        }catch(AuthTokenIsExpiredException e){
            Log.e(LOG_TAG, "Authentication token has expired");
            //TODO: tento renovar logo o token o desisto... e logo tento no upload?
        } finally {

            if(session.isEmpty()){ //Create fake session
                Log.i(LOG_TAG, "Unable to acquire session due to connectivity problems, proceeding with fake one...");
                SecureRandom random = new SecureRandom();
                session = "local_"+new BigInteger(130, random).toString(16);
                isValid = false;
            }

            Client.setSessionId(session, isValid);
        }
    }

    /* Information Uploading
    /* Information Uploading
    /* Information Uploading
     ***********************************************************************************************
     ***********************************************************************************************
     ***********************************************************************************************
     */

    private void performSubmitTrack(Intent intent) {
        JsonObject track;
        JsonParser parser = new JsonParser();
        String authToken = extractAuthenticationToken(intent);
        if(!intent.hasExtra(StoreClientConstants.TRACK_EXTRA)) return;

        track = (JsonObject) parser.parse(intent.getStringExtra(StoreClientConstants.TRACK_EXTRA));

        try {
            if(mHttpClient.submitTrack(authToken, track))
                postUserFeedback("Track successfully posted.");
            else
                postUserFeedback("Track was not successfully posted.");

        } catch (RemoteTraceException e) {
            Log.e(LOG_TAG, e.getMessage());
            postUserFeedback("Track was not posted because " + e.getMessage());

        } catch (UnableToSubmitTrackTokenExpiredException e){
            //TODO: Token expired broadcast that information
            Log.e(LOG_TAG, "Token expired");
            broadcastFailedSubmitOperation(track.toString());
        }
    }



    private void broadcastFailedSubmitOperation(String track) {
        //Intent i = AuthenticationRenewalListener.getFailedToSubmitTrackIntent(track);
        //sendBroadcast(i);
        Log.e(LOG_TAG, "Not doing anything in @broadcastFailedSubmitOperation!");
    }


    /* User Feedback
    /* User Feedback
    /* User Feedback
     ***********************************************************************************************
     ***********************************************************************************************
     ***********************************************************************************************
     */

    private Handler mHandler = new Handler();

    private void postUserFeedback(String feedback){
        mHandler.post(new DisplayToast(this, feedback));
    }

    private class DisplayToast implements Runnable {

        private final Context mContext;
        private String message;

        public DisplayToast(Context context, String message){
            this.mContext = context;
            this.message  = message;
        }

        @Override
        public void run() {
            Toast.makeText(mContext, message, Toast.LENGTH_SHORT).show();
        }
    }

    /* Supported Operations
    /* Supported Operations
    /* Supported Operations
     ***********************************************************************************************
     ***********************************************************************************************
     ***********************************************************************************************
     */
    public enum Operations {
        initiateSession,
        submitTrack,
        unknown
    }

    /**
     * This class operates as an abstraction layer over the communication between the application
     * and corresponding activities and the TRACEStore IntentService. All the methods provided are static.
     * <br>
     * <emph>Note: </emph> The employed design pattern greatly differs with the one employed in the TRACETracker.Client.
     */
    public static class Client {

        private static final String LOG_TAG = "TRACEStore";

        private static String sessionId;
        private static boolean isValid;

        protected static void setSessionId(String session){
            sessionId = session;
            isValid = true;
        }

        protected static void setSessionId(String session, boolean valid){
            sessionId = session;
            isValid = valid;
        }

        /**
         * Checks if the current session identifier is a valid one, i.e. one generated by the  TRACEStore
         * server.
         * @return True if the current session identifier is valid, false otherwise.
         */
        public static  boolean isValidSession(){
            return isValid;
        }

        /**
         * Returns the current session identifier. This session identifier should be used to uniquely
         * identify a traced track.
         * @return The session identifier.
         */

        public static String getSessionId(){
            return sessionId;
        }


        /**
         * Requests for a new tracking session to be initiated if possible.
         * @param context The current context.
         */
        /*
        public static void requestInitiateSession(Context context, String authToken){
            Intent mI = new Intent(context, TRACEStore.class);
            mI.putExtra(StoreClientConstants.store.OPERATION_KEY, Operations.initiateSession.toString());
            mI.putExtra(StoreClientConstants.store.AUTH_TOKEN_EXTRA, authToken);
            //context.startService(mI);
        }
        */

        /**
         * Uploads a complete track. It is important to note that the method was designed to handle
         * the possibility of the track being a local track, i.e. it is not associated with a valid
         * session identifier from the server's standpoint. Therefore, if the session identifier is
         * not a valid one, this method handles the track's session identifier renewal.
         * @param context The current context.
         * @param track The Track to be uploaded.
         */
        public static void uploadTrack(Context context, String authToken, JsonObject track){

            Intent mI = new Intent(context, TRACEStore.class);
            mI.putExtra(StoreClientConstants.OPERATION_KEY, Operations.submitTrack.toString());
            mI.putExtra(StoreClientConstants.TRACK_EXTRA, track.toString());
            mI.putExtra(StoreClientConstants.AUTH_TOKEN_EXTRA, authToken);
            context.startService(mI);
        }


        public static void uploadTrack(Context context, String authToken, String session, String track){
            //track.setSessionId(session);
            Intent mI = new Intent(context, TRACEStore.class);
            mI.putExtra(StoreClientConstants.OPERATION_KEY, Operations.submitTrack.toString());
            mI.putExtra(StoreClientConstants.TRACK_EXTRA, track);
            mI.putExtra(StoreClientConstants.AUTH_TOKEN_EXTRA, authToken);
            context.startService(mI);
        }
    }
}