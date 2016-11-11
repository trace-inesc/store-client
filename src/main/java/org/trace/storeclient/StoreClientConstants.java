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

public interface StoreClientConstants {

    String FIRST_TIME_BROADCAST = "org.trace.intent.FIRST_TIME";

    //Login
    String LOGIN_ACTION = "org.trace.intent.LOGIN";
    String SUCCESS_LOGIN_EXTRA = "org.trace.intent.SUCCESS_LOGIN";
    String LOGIN_ERROR_MSG_EXTRA = "org.trace.intent.LOGIN_ERROR";

    //AuthTokenExpired
    String TOKEN_EXPIRED_ACTION  = "org.trace.intent.EXPIRED_TOKEN";
    String FAILED_OPERATION_KEY = "org.trace.intent.FAILED_OPERATION";
    String AUTH_TOKEN_EXTRA = "auth_token";
    String TRACK_EXTRA  = "org.trace.store.extras.TRACK";
    String OPERATION_KEY    = "action";
}
