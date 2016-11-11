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

package org.trace.storeclient.remote;

import android.content.Context;
import android.util.Log;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.trace.storeclient.auth.AuthenticationRenewalListener;
import org.trace.storeclient.exceptions.AuthTokenIsExpiredException;
import org.trace.storeclient.exceptions.InvalidAuthCredentialsException;
import org.trace.storeclient.exceptions.LoginFailedException;
import org.trace.storeclient.exceptions.RemoteTraceException;
import org.trace.storeclient.exceptions.UnableToPerformLogin;
import org.trace.storeclient.exceptions.UnableToRequestPostException;
import org.trace.storeclient.exceptions.UnableToSubmitTrackTokenExpiredException;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;

public class HttpClient {

    private final String LOG_TAG = HttpClient.class.getSimpleName();

    private JsonParser jsonParser;
    private final String BASE_URI = "http://146.193.41.50:8080/trace";

    private Context mContext;

    public HttpClient(Context context){
        this.mContext = context;
        jsonParser = new JsonParser();
    }

    private String extractAuthToken(String response) throws LoginFailedException {
        JsonObject jsonResponse = (JsonObject) jsonParser.parse(response);

        if(jsonResponse.has("success") && jsonResponse.get("success").getAsBoolean())
            return jsonResponse.get("token").getAsString();
        else {

            int errorCode = jsonResponse.get("code").getAsInt();

            if(errorCode == 2)
                throw new InvalidAuthCredentialsException();

            String errorMessage = jsonResponse.get("error").getAsString();
            throw new LoginFailedException(errorMessage);
        }
    }

    private String validateAndExtractSession(String response) throws RemoteTraceException {
        JsonObject jsonResponse = (JsonObject) jsonParser.parse(response);

        if(jsonResponse.get("success").getAsBoolean()){
            return jsonResponse.get("session").getAsString();
        }else{
            throw new RemoteTraceException("GetSession", jsonResponse.get("error").getAsString());
        }
    }



    private JsonObject constructRemoteRequest(String method, String urlEndpoint, JsonObject requestProperties, String data){
        JsonObject operation = new JsonObject();
        operation.addProperty("method", method);
        operation.addProperty("endpoint", urlEndpoint);
        operation.add("properties", requestProperties);
        operation.addProperty("data", data);
        return operation;
    }

    public String performRemoteRequest(JsonObject operation){

        String method       = operation.get("method").getAsString();
        String urlEndpoint  = operation.get("endpoint").getAsString();
        JsonObject props    = operation.getAsJsonObject("properties");
        String data         = operation.get("data").getAsString();

        URL url;
        HttpURLConnection connection = null;
        String dataUrl = BASE_URI+urlEndpoint;

        //TODO: terminar

        return "";
    }

    public String performPostRequest(String urlEndpoint, JsonObject requestProperties, String data) throws UnableToRequestPostException, AuthTokenIsExpiredException {
        URL url;
        HttpURLConnection connection = null;
        String dataUrl = BASE_URI+urlEndpoint;

        try {

            // Create connection
            url = new URL(dataUrl);
            connection = (HttpURLConnection) url.openConnection();

            connection.setRequestMethod("POST");

            if(requestProperties != null)
                for(Map.Entry<String, JsonElement> entry : requestProperties.entrySet())
                    connection.setRequestProperty(entry.getKey(), entry.getValue().getAsString());

            connection.setUseCaches(false);
            connection.setDoInput(true);
            connection.setDoOutput(true);

            // Send request
            DataOutputStream wr = new DataOutputStream(connection.getOutputStream());
            if(data != null && !data.isEmpty()) wr.write(data.getBytes("UTF-8"));
            wr.flush();
            wr.close();

            // Get Response
            int responseCode = connection.getResponseCode();

            switch (responseCode){
                case 200:
                    break;
                case 401:

                    mContext.sendBroadcast(
                            AuthenticationRenewalListener.getFailedRemoteOperationIntent(
                                    constructRemoteRequest(
                                            "POST",
                                            urlEndpoint,
                                            requestProperties,
                                            data)));

                    throw new AuthTokenIsExpiredException();
                default:
                    throw new UnableToRequestPostException(String.valueOf(responseCode));
            }

            InputStream is = connection.getInputStream();
            BufferedReader rd = new BufferedReader(new InputStreamReader(is));
            String line;
            StringBuilder response = new StringBuilder();
            while ((line = rd.readLine()) != null) {
                response.append(line);
                response.append('\r');
            }

            rd.close();


            return response.toString();

        } catch (IOException e) {

            e.printStackTrace();
            throw new UnableToRequestPostException(e.getMessage());

        } finally {

            if (connection != null) {
                connection.disconnect();
            }
        }

    }

    private void validateHttpResponse(String requestType, String response) throws RemoteTraceException {

        JsonObject jsonResponse = (JsonObject) jsonParser.parse(response);

        if(!jsonResponse.get("success").getAsBoolean()){
            throw new RemoteTraceException(requestType, jsonResponse.get("error").getAsString());
        }

    }



    public String login(String username, String password) throws UnableToPerformLogin, LoginFailedException {

        String urlEndpoint ="/auth/login";
        JsonObject requestProperties = new JsonObject();
        String dataUrlParameters = "username="+username+"&password="+password;

        requestProperties.addProperty(http.CONTENT_TYPE, "application/x-www-form-urlencoded");
        requestProperties.addProperty(http.CONTENT_LENGTH, Integer.toString(dataUrlParameters.getBytes().length));
        requestProperties.addProperty(http.CONTENT_LANGUAGE, "en-US,en,pt");

        try {
            String response = performPostRequest(urlEndpoint, requestProperties, dataUrlParameters);
            String authToken= extractAuthToken(response);
            Log.d(LOG_TAG, "Login successful with { authToken: '" + authToken + "'}");
            return authToken;
        } catch (UnableToRequestPostException | AuthTokenIsExpiredException e) {
            e.printStackTrace();
            throw new UnableToPerformLogin(e.getMessage());
        }
    }

    public String federatedLogin(String idToken) throws UnableToPerformLogin, LoginFailedException {
        String urlEndpoint ="/auth/login";
        JsonObject requestProperties = new JsonObject();
        String dataUrlParameters = "token="+idToken;

        requestProperties.addProperty(http.CONTENT_TYPE, "application/x-www-form-urlencoded");
        requestProperties.addProperty(http.CONTENT_LENGTH, Integer.toString(dataUrlParameters.getBytes().length));
        requestProperties.addProperty(http.CONTENT_LANGUAGE, "en-US,en,pt");

        try {
            String response = performPostRequest(urlEndpoint, requestProperties, dataUrlParameters);
            String authToken= extractAuthToken(response);
            Log.d(LOG_TAG, "Login successful with { authToken: '" + authToken + "'}");
            return authToken;
        } catch (UnableToRequestPostException | AuthTokenIsExpiredException e) {
            e.printStackTrace();
            throw new UnableToPerformLogin(e.getMessage());
        }
    }

    public void logout(String authToken) throws RemoteTraceException, AuthTokenIsExpiredException {

        String urlEndpoint = "/auth/logout";
        JsonObject requestProperties = new JsonObject();
        requestProperties.addProperty(http.AUTHORIZATION, "Bearer " + authToken);

        try {

            performPostRequest(urlEndpoint, requestProperties, null);
            Log.d(LOG_TAG, "Logout successful");

        } catch (UnableToRequestPostException |AuthTokenIsExpiredException e) {
            e.printStackTrace();
            throw new RemoteTraceException("Logout", e.getMessage());
        }

    }


    public String requestTrackingSession(String authToken) throws RemoteTraceException, AuthTokenIsExpiredException {

        String urlEndpoint = "/auth/session/open";
        JsonObject requestProperties = new JsonObject();
        requestProperties.addProperty(http.AUTHORIZATION, "Bearer " + authToken);

        try {
            String response = performPostRequest(urlEndpoint, requestProperties, null);
            return validateAndExtractSession(response);
        } catch (UnableToRequestPostException e) {
            e.printStackTrace();
            throw new RemoteTraceException("GetSession", e.getMessage());
        }
    }


    @Deprecated
    public void closeTrackingSession(String authToken, String session) throws RemoteTraceException, AuthTokenIsExpiredException {

        String urlEndpoint = "/auth/close";
        String dataUrlParams = "session="+session;
        JsonObject requestProperties = new JsonObject();
        requestProperties.addProperty(http.AUTHORIZATION, "Bearer "+authToken);

        try {
            String response = performPostRequest(urlEndpoint, requestProperties, dataUrlParams);
            validateHttpResponse("CloseSession", response);
        } catch (UnableToRequestPostException e) {
            e.printStackTrace();
            throw new RemoteTraceException("CloseSession", e.getMessage());
        }
    }

    private void uploadCompleteTrackSequence(String authToken, String session, String jsonTrack) throws RemoteTraceException, AuthTokenIsExpiredException {
        String data = jsonTrack;
        String urlEndpoint = "/tracker/put/track/"+session;

        JsonObject requestProperties = new JsonObject();
        requestProperties.addProperty(http.AUTHORIZATION, "Bearer "+authToken);
        requestProperties.addProperty(http.CONTENT_TYPE, "application/json; charset=UTF-8");

        try {
            String response = performPostRequest(urlEndpoint, requestProperties, data);
            validateHttpResponse("UploadTrack", response);
        } catch (UnableToRequestPostException e) {
            e.printStackTrace();
            throw new RemoteTraceException("UploadTrack", e.getMessage());
        }
    }

    /*
    @Deprecated
    private void uploadCompleteTrackSequence(String authToken, String session, List<TraceLocation> locations)
            throws RemoteTraceException, AuthTokenIsExpiredException {

        String data = constructTraceTrack(locations);
        String urlEndpoint = "/tracker/put/track/"+session;

        JsonObject requestProperties = new JsonObject();
        requestProperties.addProperty(http.AUTHORIZATION, "Bearer "+authToken);
        requestProperties.addProperty(http.CONTENT_TYPE, "application/json; charset=UTF-8");

        try {
            String response = performPostRequest(urlEndpoint, requestProperties, data);
            validateHttpResponse("UploadTrack", response);
        } catch (UnableToRequestPostException e) {
            e.printStackTrace();
            throw new RemoteTraceException("UploadTrack", e.getMessage());
        }
    }
    */

    public boolean submitTrack(String authToken, JsonObject jsonTrack)
            throws RemoteTraceException, UnableToSubmitTrackTokenExpiredException {

        String session, localSession;

        //PersistentTrackStorage storage = new PersistentTrackStorage(mContext);

        localSession = jsonTrack.get("session").getAsString();
        boolean isValid = jsonTrack.get("isValid").getAsBoolean();

        if(!isValid){
            Log.d(LOG_TAG, "Session is local, requesting a valid session before proceeding...");

            try {
                session = requestTrackingSession(authToken);

                //localSession = jsonTrack.getSessionId();

                //if(!storage.updateTrackSession(localSession, session))
                //    return false;


            } catch (AuthTokenIsExpiredException e) {
                throw new UnableToSubmitTrackTokenExpiredException();
            }

        }else{
            session = localSession;
        }

        try {

            //uploadCompleteTrackSequence(authToken, session, track.getTracedTrack());
            try{
                uploadCompleteTrackSequence(authToken, session, jsonTrack.toString());
            }catch (Exception e){ //TODO: remover isto! Apenas para testes
                //uploadCompleteTrackSequence(authToken, session, jsonTrack.getTracedTrack());
                Log.e("UPLOAD", e.getMessage());
            }


        } catch (AuthTokenIsExpiredException e) {
            e.printStackTrace();
            throw new UnableToSubmitTrackTokenExpiredException();
        }

        return true;
    }


    private interface http {
        String CONTENT_TYPE = "Content-Type";
        String CONTENT_LENGTH = "Content-Length";
        String CONTENT_LANGUAGE = "Content-Language";
        String AUTHORIZATION = "Authorization";
    }
}
